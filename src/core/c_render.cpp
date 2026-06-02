#include "c_render.h"

#include <algorithm>
#include <cctype>
#include <functional>
#include <set>
#include <sstream>
#include <vector>

namespace oxi {
namespace {

std::string sanitize(const std::string& rust_name) {
    std::string out = "OXI_";
    bool prev_us = false;
    for (char c : rust_name) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            out.push_back(c);
            prev_us = false;
        } else if (!prev_us) {
            out.push_back('_');
            prev_us = true;
        }
    }
    if (out.size() > 200) out.resize(200);  // keep identifiers sane
    return out;
}

bool is_aggregate(const RustTypePtr& t) {
    return t && (t->kind == RKind::Struct || t->kind == RKind::Enum);
}

}  // namespace

CRenderer::CRenderer(const TypeDB& db) : db_(db) {}

std::string CRenderer::ensure_name(const std::string& rust_name) {
    auto it = name_map_.find(rust_name);
    if (it != name_map_.end()) return it->second;
    std::string base = sanitize(rust_name);
    std::string cand = base;
    int n = 1;
    while (used_cnames_.count(cand)) {
        cand = base + "_" + std::to_string(n++);
    }
    used_cnames_[cand] = true;
    name_map_[rust_name] = cand;
    return cand;
}

std::string CRenderer::c_name_for(const std::string& rust_name) const {
    auto it = name_map_.find(rust_name);
    return it == name_map_.end() ? std::string() : it->second;
}

std::string CRenderer::int_token(int bits, bool is_signed) const {
    const char* base = nullptr;
    switch (bits) {
        case 8: base = "__int8"; break;
        case 16: base = "__int16"; break;
        case 32: base = "__int32"; break;
        case 64: base = "__int64"; break;
        case 128: base = "__int128"; break;
        default: return "";  // non-standard width: caller falls back to byte array
    }
    return is_signed ? std::string(base) : std::string("unsigned ") + base;
}

std::string CRenderer::size_token(long long bytes) const {
    switch (bytes) {
        case 1: return "unsigned __int8";
        case 2: return "unsigned __int16";
        case 4: return "unsigned __int32";
        case 8: return "unsigned __int64";
        default: return "";
    }
}

std::string CRenderer::type_token(const RustTypePtr& t) {
    if (!t) return "void *";
    switch (t->kind) {
        case RKind::Int: {
            std::string tok = int_token(t->bits, t->is_signed);
            if (!tok.empty()) return tok;
            // Non-standard width: fall back to a same-sized value type, never a
            // pointer (C forbids a bare array type in token position).
            std::string st = size_token(t->size);
            return st.empty() ? "unsigned __int8" : st;
        }
        case RKind::Float:
            return t->bits == 32 ? "float" : "double";
        case RKind::Bool:
            return "bool";
        case RKind::Char:
            return "__int32";  // Rust char (Unicode scalar)
        case RKind::Pointer: {
            std::string pointee = t->pts_to && is_aggregate(t->pts_to) ? ensure_name(t->pts_to->name)
                                  : t->pts_to                          ? type_token(t->pts_to)
                                                                       : std::string("void");
            // collapse pointer-to-pointer/array tokens to void* for simplicity
            if (pointee.find('*') != std::string::npos || pointee.find('[') != std::string::npos) pointee = "void";
            return pointee + " *";
        }
        case RKind::Array:
            return type_token(t->ele) + " *";  // decays to pointer in token position
        case RKind::Slice:
            return "Oxidizer_Slice";
        case RKind::StrRef:
            return "Oxidizer_StrRef";
        case RKind::Struct:
        case RKind::Enum:
            return ensure_name(t->name);
        case RKind::Bottom:
        default:
            return "void *";
    }
}

std::string CRenderer::member_decl(const RustTypePtr& t, const std::string& member) {
    if (!t) return "void *" + member;
    switch (t->kind) {
        case RKind::Int: {
            std::string tok = int_token(t->bits, t->is_signed);
            if (tok.empty()) {
                return "unsigned __int8 " + member + "[" + std::to_string(t->size) + "]";
            }
            return tok + " " + member;
        }
        case RKind::Float:
            return std::string(t->bits == 32 ? "float " : "double ") + member;
        case RKind::Bool:
            return "bool " + member;
        case RKind::Char:
            return "__int32 " + member;
        case RKind::Pointer:
            return type_token(t) + member;  // type_token ends with "* "
        case RKind::Slice:
            return "Oxidizer_Slice " + member;
        case RKind::StrRef:
            return "Oxidizer_StrRef " + member;
        case RKind::Struct:
        case RKind::Enum:
            return ensure_name(t->name) + " " + member;
        case RKind::Array: {
            // Flatten nested arrays into multiple dimensions.
            std::string dims;
            RustTypePtr cur = t;
            while (cur && cur->kind == RKind::Array) {
                dims += "[" + std::to_string(cur->length) + "]";
                cur = cur->ele;
            }
            // base element declared via member_decl on a dummy to reuse type token
            std::string base = member_decl(cur, member + dims);
            return base;
        }
        case RKind::Bottom:
        default:
            return "unsigned __int8 " + member + "[" + std::to_string(std::max<long long>(1, t->size)) + "]";
    }
}

std::string CRenderer::opaque(const std::string& cname, long long size, const std::string& comment) const {
    long long n = std::max<long long>(1, size);
    std::ostringstream os;
    os << "struct " << cname << " { unsigned __int8 raw[" << n << "]; };";
    if (!comment.empty()) os << "  // " << comment;
    os << "\n";
    return os.str();
}

namespace {
// Lays out members at explicit offsets, inserting padding; reports overlap.
struct Layout {
    std::vector<std::string> decls;
    long long cur = 0;
    bool failed = false;

    void add(long long offset, long long size, const std::string& decl) {
        if (offset < cur) { failed = true; return; }
        if (offset > cur) {
            decls.push_back("unsigned __int8 _pad" + std::to_string(decls.size()) + "[" +
                            std::to_string(offset - cur) + "];");
            cur = offset;
        }
        decls.push_back(decl + ";");
        cur = offset + std::max<long long>(0, size);
    }

    void finish(long long total) {
        if (cur > total) { failed = true; return; }
        if (cur < total) {
            decls.push_back("unsigned __int8 _tail[" + std::to_string(total - cur) + "];");
            cur = total;
        }
    }
};
}  // namespace

std::string CRenderer::render_struct(const RustTypePtr& t) {
    std::string cname = ensure_name(t->name);
    Layout layout;
    for (const auto& f : t->fields) {
        // Zero-sized types (e.g. Rust closures / PhantomData) occupy no space.
        // C would size an embedded empty struct as 1 byte, corrupting the
        // layout, so skip them entirely; explicit padding preserves exact size.
        if (f.ty && f.ty->size == 0) continue;
        // field names just need to be a valid C identifier
        std::string fmember;
        for (char c : f.name) {
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')
                fmember.push_back(c);
            else
                fmember.push_back('_');
        }
        if (fmember.empty() || std::isdigit((unsigned char)fmember[0])) fmember = "f_" + fmember;
        layout.add(f.offset, f.ty ? f.ty->size : 0, member_decl(f.ty, fmember));
    }
    layout.finish(t->size);
    if (layout.failed) {
        return opaque(cname, t->size, "Rust " + t->name + " (opaque: irregular layout)");
    }
    std::ostringstream os;
    os << "struct " << cname << " {  // Rust: " << t->name << "\n";
    for (const auto& d : layout.decls) os << "    " << d << "\n";
    os << "};\n";
    return os.str();
}

std::string CRenderer::render_enum(const RustTypePtr& t) {
    std::string cname = ensure_name(t->name);

    // Niche-encoded (no tag): represent as the largest variant's payload.
    if (t->is_niche_encoded()) {
        const RustVariant* big = nullptr;
        long long best = -1;
        for (const auto& v : t->variants) {
            long long s = 0;
            for (const auto& f : v.fields) s += f.ty ? f.ty->size : 0;
            if (s > best) { best = s; big = &v; }
        }
        Layout layout;
        long long off = 0;
        if (big) {
            for (const auto& f : big->fields) {
                if (f.ty && f.ty->size == 0) continue;  // skip zero-sized payload fields
                std::string fmember;
                for (char c : f.name) fmember.push_back(std::isalnum((unsigned char)c) ? c : '_');
                if (fmember.empty() || std::isdigit((unsigned char)fmember[0])) fmember = "v_" + fmember;
                layout.add(off, f.ty ? f.ty->size : 0, member_decl(f.ty, fmember));
                off += f.ty ? f.ty->size : 0;
            }
        }
        layout.finish(t->size);
        if (layout.failed) return opaque(cname, t->size, "Rust enum " + t->name + " (niche, opaque)");
        std::ostringstream os;
        os << "struct " << cname << " {  // Rust enum (niche-encoded): " << t->name << "\n";
        for (const auto& d : layout.decls) os << "    " << d << "\n";
        os << "};\n";
        return os.str();
    }

    // Tagged: discriminant first, then a payload blob sized to fit.  We keep the
    // payload opaque (a byte blob) but list the variants in a comment so the
    // pseudocode reader can see the shape.  Size is always exact.
    Layout layout;
    long long disc = std::max<long long>(0, t->disc_size);
    if (disc > 0) {
        std::string tok = size_token(disc);
        if (!tok.empty()) {
            layout.add(0, disc, tok + " tag");
        } else {
            layout.add(0, disc, "unsigned __int8 tag[" + std::to_string(disc) + "]");
        }
    }
    layout.finish(t->size);
    if (layout.failed) return opaque(cname, t->size, "Rust enum " + t->name + " (opaque)");

    std::ostringstream os;
    os << "struct " << cname << " {  // Rust enum: " << t->name << "\n";
    for (const auto& v : t->variants) {
        os << "    // variant " << v.name;
        if (v.has_disc) os << " = " << v.discriminant;
        if (!v.fields.empty()) {
            os << " (";
            for (size_t i = 0; i < v.fields.size(); ++i) {
                if (i) os << ", ";
                os << (v.fields[i].ty ? v.fields[i].ty->size : 0) << "B";
            }
            os << ")";
        }
        os << "\n";
    }
    for (const auto& d : layout.decls) os << "    " << d << "\n";
    os << "};\n";
    return os.str();
}

std::string CRenderer::render_header() {
    // Assign C names to every type up front (stable, collision-free).
    std::vector<std::string> order_names;
    for (const auto& [rust_name, ty] : db_.types) {
        ensure_name(rust_name);
        order_names.push_back(rust_name);
    }

    // Topologically order by by-value containment (pointers/slices are not deps).
    // A field type contributes a by-value dependency if it is an aggregate, or an
    // (arbitrarily nested) array of an aggregate; pointers/slices/str/primitives
    // never do (a pointer to an incomplete struct is fine).
    std::function<void(const RustTypePtr&, std::set<std::string>&)> add_byval_dep =
        [&](const RustTypePtr& ty, std::set<std::string>& acc) {
            if (!ty) return;
            if (is_aggregate(ty)) {
                acc.insert(ty->name);
            } else if (ty->kind == RKind::Array) {
                add_byval_dep(ty->ele, acc);
            }
        };
    auto deps_of = [&](const RustTypePtr& t, std::set<std::string>& acc) {
        if (!t) return;
        if (t->kind == RKind::Struct) {
            for (const auto& f : t->fields) add_byval_dep(f.ty, acc);
        } else if (t->kind == RKind::Enum && t->is_niche_encoded()) {
            // niche enums render the largest variant's payload by value
            for (const auto& v : t->variants)
                for (const auto& f : v.fields) add_byval_dep(f.ty, acc);
        }
        // tagged (non-niche) enums render an opaque payload blob: no by-value deps
    };

    std::set<std::string> visited;
    std::set<std::string> on_stack;
    std::vector<std::string> ordered;
    std::function<void(const std::string&)> visit = [&](const std::string& name) {
        if (visited.count(name)) return;
        if (on_stack.count(name)) return;  // cycle: break it
        on_stack.insert(name);
        auto it = db_.types.find(name);
        if (it != db_.types.end()) {
            std::set<std::string> deps;
            deps_of(it->second, deps);
            for (const auto& d : deps) {
                if (db_.types.count(d)) visit(d);
            }
        }
        on_stack.erase(name);
        visited.insert(name);
        ordered.push_back(name);
    };
    for (const auto& name : order_names) visit(name);

    std::ostringstream os;
    os << "// Generated by Oxidizer-for-IDA: Rust std type database\n";
    os << "#pragma pack(push, 1)\n\n";
    std::string lentok = size_token(db_.arch_bytes);
    if (lentok.empty()) lentok = "unsigned __int64";
    os << "typedef struct Oxidizer_Slice { void *data_ptr; " << lentok
       << " length; } Oxidizer_Slice;\n";
    os << "typedef struct Oxidizer_StrRef { unsigned __int8 *data_ptr; " << lentok
       << " length; } Oxidizer_StrRef;\n\n";

    // Forward declarations so pointer members resolve regardless of order.
    for (const auto& name : ordered) {
        os << "typedef struct " << name_map_[name] << " " << name_map_[name] << ";\n";
    }
    os << "\n";

    // Definitions.
    for (const auto& name : ordered) {
        const RustTypePtr& t = db_.types.at(name);
        if (t->kind == RKind::Struct) {
            os << render_struct(t) << "\n";
        } else if (t->kind == RKind::Enum) {
            os << render_enum(t) << "\n";
        }
        // Slice/StrRef/primitives are not top-level named declarations.
    }

    os << "#pragma pack(pop)\n";
    return os.str();
}

std::string CRenderer::render_prototype(const RustFnProto& proto, const std::string& fname) {
    std::string ret = proto.is_retbuf ? "void" : (proto.ret ? type_token(proto.ret) : "void");
    std::ostringstream os;
    os << ret << " " << fname << "(";
    if (proto.args.empty()) {
        os << "void";
    } else {
        for (size_t i = 0; i < proto.args.size(); ++i) {
            if (i) os << ", ";
            os << type_token(proto.args[i]) << " a" << i;
        }
    }
    os << ");";
    return os.str();
}

}  // namespace oxi
