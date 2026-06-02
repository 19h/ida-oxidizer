#include "typedb.h"

#include <algorithm>
#include <functional>

namespace oxi {
namespace {

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

RustTypePtr make(RKind kind, long long size = 0) {
    auto t = std::make_shared<RustType>();
    t->kind = kind;
    t->size = size;
    return t;
}

RustTypePtr make_int(long long size, int bits, bool is_signed, const std::string& name) {
    auto t = make(RKind::Int, size);
    t->bits = bits;
    t->is_signed = is_signed;
    t->prim_name = name;
    return t;
}

long long variant_payload_size(const RustVariant& v) {
    long long s = 0;
    for (const auto& f : v.fields) {
        if (f.ty) s += f.ty->size;
    }
    return s;
}

}  // namespace

bool RustType::is_option() const {
    if (kind != RKind::Enum || !starts_with(name, "core::option::Option")) return false;
    std::set<std::string> names;
    for (const auto& v : variants) names.insert(v.name);
    return names == std::set<std::string>{"Some", "None"};
}

bool RustType::is_result() const {
    if (kind != RKind::Enum || !starts_with(name, "core::result::Result")) return false;
    std::set<std::string> names;
    for (const auto& v : variants) names.insert(v.name);
    return names == std::set<std::string>{"Ok", "Err"};
}

bool RustType::is_niche_encoded() const {
    if (kind != RKind::Enum) return false;
    long long payload = 0;
    for (const auto& v : variants) payload = std::max(payload, variant_payload_size(v));
    return payload >= size && size > 0;
}

TypeDB TypeDB::from_file(const std::string& path, int arch_bits) {
    return from_json(json_parse_file(path), arch_bits);
}

TypeDB TypeDB::from_json(const JsonValue& data, int arch_bits) {
    TypeDB db;
    db.arch_bits = arch_bits;
    db.arch_bytes = arch_bits / 8;
    db.load(data);
    return db;
}

void TypeDB::load(const JsonValue& data) {
    const JsonValue& structs = data["structs"];
    for (const auto& s : structs.items()) {
        if (s.is_object() && s.has("name")) {
            struct_db_[s["name"].as_string()] = &s;
        }
    }
    for (const auto& s : structs.items()) {
        parse_type(s);
    }
    const JsonValue& functions = data["functions"];
    for (const auto& f : functions.items()) {
        RustFnProto proto;
        if (parse_prototype(f["prototype"], proto)) {
            prototypes[f["name"].as_string()].push_back(std::move(proto));
        }
    }
}

RustTypePtr TypeDB::parse_type(const JsonValue& data) {
    if (!data.is_object()) return nullptr;
    std::string kind = data["kind"].as_string("");
    if (kind == "Pointer") return parse_pointer(data);
    if (kind == "Primitive") return parse_primitive(data);
    if (kind == "Struct") return parse_struct(data);
    if (kind == "Enumeration") return parse_enum(data);
    if (kind == "Array") return parse_array(data);
    if (kind == "None") return nullptr;
    return nullptr;
}

RustTypePtr TypeDB::parse_pointer(const JsonValue& data) {
    RustTypePtr pts;
    if (data.has("pts_to") && !data["pts_to"].is_null()) {
        pts = parse_type(data["pts_to"]);
    }
    if (!pts) pts = make(RKind::Bottom);
    auto t = make(RKind::Pointer, arch_bytes);
    t->pts_to = pts;
    return t;
}

RustTypePtr TypeDB::parse_primitive(const JsonValue& data) {
    std::string name = data["name"].as_string("");
    if (name == "i8") return make_int(1, 8, true, "i8");
    if (name == "i16") return make_int(2, 16, true, "i16");
    if (name == "i32") return make_int(4, 32, true, "i32");
    if (name == "i64") return make_int(8, 64, true, "i64");
    if (name == "i128") return make_int(16, 128, true, "i128");
    if (name == "u8") return make_int(1, 8, false, "u8");
    if (name == "u16") return make_int(2, 16, false, "u16");
    if (name == "u32") return make_int(4, 32, false, "u32");
    if (name == "u64") return make_int(8, 64, false, "u64");
    if (name == "u128") return make_int(16, 128, false, "u128");
    if (name == "f32") { auto t = make(RKind::Float, 4); t->bits = 32; return t; }
    if (name == "f64") { auto t = make(RKind::Float, 8); t->bits = 64; return t; }
    if (name == "bool") return make(RKind::Bool, 1);
    if (name == "char") return make(RKind::Char, 4);
    long long size = data["size"].as_int(0);
    if (size > 0) return make_int(size, static_cast<int>(size * 8), false, name);
    return nullptr;
}

RustTypePtr TypeDB::parse_array(const JsonValue& data) {
    RustTypePtr ele = parse_type(data["ele_type"]);
    if (!ele) return nullptr;
    long long length = data["length"].as_int(0);
    auto t = make(RKind::Array, ele->size * length);
    t->ele = ele;
    t->length = length;
    return t;
}

RustTypePtr TypeDB::parse_struct(const JsonValue& data) {
    std::string name = data["name"].as_string("");
    auto existing = types.find(name);
    if (existing != types.end()) return existing->second;
    if (pending_.count(name)) return make(RKind::Bottom);

    const JsonValue& fields_data = data["fields"];
    if (fields_data.is_null()) {
        if (resolving_.count(name)) return nullptr;
        auto it = struct_db_.find(name);
        if (it == struct_db_.end() || it->second == &data) return nullptr;
        resolving_.insert(name);
        RustTypePtr r = parse_struct(*it->second);
        resolving_.erase(name);
        return r;
    }

    pending_.insert(name);
    std::vector<RustField> fields;
    bool ok = true;
    for (const auto& member : fields_data.members()) {
        // member.second is [field_name, field_type]
        const JsonValue& pair = member.second;
        if (!pair.is_array() || pair.size() < 2) { ok = false; break; }
        RustTypePtr fty = parse_type(pair.items()[1]);
        if (!fty) { ok = false; break; }
        RustField fld;
        try {
            fld.offset = std::stoll(member.first);
        } catch (...) {
            fld.offset = 0;
        }
        fld.name = pair.items()[0].as_string("");
        fld.ty = fty;
        fields.push_back(std::move(fld));
    }
    pending_.erase(name);
    if (!ok) return nullptr;

    auto result = make(RKind::Struct, data["size"].as_int(0));
    result->name = name;
    result->fields = std::move(fields);
    RustTypePtr patched = apply_patches(result);
    types[name] = patched;
    return patched;
}

RustTypePtr TypeDB::parse_enum(const JsonValue& data) {
    std::string name = data["name"].as_string("");
    auto existing = types.find(name);
    if (existing != types.end()) return existing->second;
    if (pending_.count(name)) return make(RKind::Bottom);

    const JsonValue& variants_data = data["variants"];
    if (variants_data.is_null()) {
        if (resolving_.count(name)) return nullptr;
        auto it = struct_db_.find(name);
        if (it == struct_db_.end() || it->second == &data) return nullptr;
        resolving_.insert(name);
        RustTypePtr r = parse_enum(*it->second);
        resolving_.erase(name);
        return r;
    }

    pending_.insert(name);
    long long disc_size = data["discriminant_size"].as_int(0);
    std::vector<RustVariant> variants;
    bool ok = true;
    for (const auto& member : variants_data.members()) {
        const JsonValue& vd = member.second;  // [discriminant, [[fname, ftype], ...]]
        if (!vd.is_array() || vd.size() < 2) { ok = false; break; }
        const JsonValue& disc = vd.items()[0];
        const JsonValue& vfields = vd.items()[1];
        RustVariant var;
        var.name = member.first;
        var.has_disc = !disc.is_null();
        var.discriminant = disc.as_int(0);
        var.disc_size = var.has_disc ? disc_size : 0;
        for (const auto& fld : vfields.items()) {
            if (!fld.is_array() || fld.size() < 2) { ok = false; break; }
            RustTypePtr fty = parse_type(fld.items()[1]);
            if (!fty) { ok = false; break; }
            RustField f;
            f.offset = 0;  // payload-relative; recomputed on lowering
            f.name = fld.items()[0].as_string("");
            f.ty = fty;
            var.fields.push_back(std::move(f));
        }
        if (!ok) break;
        variants.push_back(std::move(var));
    }
    pending_.erase(name);
    if (!ok) return nullptr;

    auto result = make(RKind::Enum, data["size"].as_int(0));
    result->name = name;
    result->variants = std::move(variants);
    result->disc_size = disc_size;
    types[name] = result;
    return result;
}

RustTypePtr TypeDB::apply_patches(const RustTypePtr& ty) {
    RustTypePtr t = to_slice(ty);
    if (t->kind == RKind::Struct) t = unwrap_argument(t);
    return t;
}

RustTypePtr TypeDB::to_slice(const RustTypePtr& ty) {
    std::set<std::string> names;
    for (const auto& f : ty->fields) names.insert(f.name);
    if (names != std::set<std::string>{"data_ptr", "length"}) return ty;
    RustTypePtr data_ptr, length;
    for (const auto& f : ty->fields) {
        if (f.name == "data_ptr") data_ptr = f.ty;
        if (f.name == "length") length = f.ty;
    }
    if (data_ptr && data_ptr->kind == RKind::Pointer && length && length->kind == RKind::Int &&
        length->size == arch_bytes) {
        if (ty->name == "&str" && data_ptr->pts_to && data_ptr->pts_to->kind == RKind::Int &&
            data_ptr->pts_to->bits == 8) {
            return make(RKind::StrRef, ty->size);
        }
        auto slice = make(RKind::Slice, ty->size);
        slice->ele = data_ptr->pts_to;
        return slice;
    }
    return ty;
}

RustTypePtr TypeDB::unwrap_argument(const RustTypePtr& ty) {
    if (ty->name != "core::fmt::rt::Argument") return ty;
    std::set<std::string> names;
    for (const auto& f : ty->fields) names.insert(f.name);
    if (names != std::set<std::string>{"ty"}) return ty;
    RustTypePtr inner = ty->fields[0].ty;
    if (inner && inner->kind == RKind::Enum) {
        for (const auto& v : inner->variants) {
            if (v.name == "Placeholder") {
                auto s = make(RKind::Struct, ty->size);
                s->name = "core::fmt::rt::Argument";
                s->fields = v.fields;
                return s;
            }
        }
    }
    return ty;
}

bool TypeDB::parse_prototype(const JsonValue& data, RustFnProto& out) {
    if (!data.is_object()) return false;
    std::vector<RustTypePtr> args;
    for (const auto& a : data["args"].items()) {
        RustTypePtr t = parse_type(a);
        if (!t) return false;
        args.push_back(t);
    }
    RustTypePtr ret = parse_type(data["returnty"]);
    out = fit_abi(std::move(args), ret);
    return true;
}

RustFnProto TypeDB::fit_abi(std::vector<RustTypePtr> args, RustTypePtr ret) {
    long long big = static_cast<long long>(arch_bytes) * 2;
    auto is_aggregate = [](const RustTypePtr& t) {
        return t && (t->kind == RKind::Struct || t->kind == RKind::Enum);
    };
    RustFnProto proto;
    for (auto& a : args) {
        if (is_aggregate(a) && a->size > big) {
            auto p = make(RKind::Pointer, arch_bytes);
            p->pts_to = a;
            proto.args.push_back(p);
        } else {
            proto.args.push_back(a);
        }
    }
    if (is_aggregate(ret) && ret->size > big) {
        auto p = make(RKind::Pointer, arch_bytes);
        p->pts_to = ret;
        proto.args.insert(proto.args.begin(), p);
        proto.ret = nullptr;
        proto.is_retbuf = true;
    } else {
        proto.ret = ret;
        proto.is_retbuf = false;
    }
    return proto;
}

}  // namespace oxi
