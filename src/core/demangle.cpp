#include "demangle.h"

#include <algorithm>
#include <cctype>
#include <optional>
#include <regex>
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace oxi {
namespace {

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

bool is_rust_hash(const std::string& s) {
    if (s.size() != 17 || s[0] != 'h') return false;
    for (size_t i = 1; i < s.size(); ++i) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

std::vector<std::string> split_path(const std::string& s) {
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t pos = s.find("::", start);
        if (pos == std::string::npos) {
            parts.push_back(s.substr(start));
            break;
        }
        parts.push_back(s.substr(start, pos - start));
        start = pos + 2;
    }
    return parts;
}

bool is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// ---------------------------------------------------------------------------
// legacy mangling (_ZN <len><ident> ... E)
// ---------------------------------------------------------------------------

const std::unordered_map<std::string, std::string>& legacy_escapes() {
    static const std::unordered_map<std::string, std::string> m = {
        {"SP", "@"}, {"BP", "*"}, {"RF", "&"}, {"LT", "<"}, {"GT", ">"},
        {"LP", "("}, {"RP", ")"}, {"C", ","},  {"u7e", "~"}, {"u20", " "},
        {"u27", "'"}, {"u5b", "["}, {"u5d", "]"}, {"u7b", "{"}, {"u7d", "}"},
        {"u3b", ";"}, {"u2b", "+"}, {"u21", "!"}, {"u22", "\""},
    };
    return m;
}

void append_utf8(std::string& out, unsigned cp) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

std::string decode_legacy_ident(std::string ident) {
    // rustc prepends "_" to an element that would otherwise start with a special
    // character (e.g. "<" encoded as "$LT$").  Drop that escape underscore.
    if (ident.size() >= 2 && ident[0] == '_' && ident[1] == '$') {
        ident = ident.substr(1);
    }
    std::string out;
    size_t i = 0;
    size_t n = ident.size();
    while (i < n) {
        char c = ident[i];
        if (c == '$') {
            size_t end = ident.find('$', i + 1);
            if (end == std::string::npos) {
                out += ident.substr(i);
                break;
            }
            std::string code = ident.substr(i + 1, end - i - 1);
            const auto& esc = legacy_escapes();
            auto it = esc.find(code);
            if (it != esc.end()) {
                out += it->second;
            } else if (code.size() > 1 && code[0] == 'u' &&
                       std::all_of(code.begin() + 1, code.end(), [](char ch) { return is_hex(ch); })) {
                try {
                    append_utf8(out, static_cast<unsigned>(std::stoul(code.substr(1), nullptr, 16)));
                } catch (...) {
                    out += "$" + code + "$";
                }
            } else {
                out += "$" + code + "$";
            }
            i = end + 1;
        } else if (c == '.' && i + 1 < n && ident[i + 1] == '.') {
            out += "::";
            i += 2;
        } else {
            out.push_back(c);
            ++i;
        }
    }
    return out;
}

std::optional<std::string> demangle_legacy(const std::string& s) {
    std::string body;
    if (s.rfind("_ZN", 0) == 0) {
        body = s.substr(3);
    } else {  // "ZN..."
        body = s.substr(2);
    }
    std::vector<std::string> comps;
    size_t i = 0;
    size_t n = body.size();
    while (i < n) {
        if (body[i] == 'E') break;
        size_t j = i;
        while (j < n && std::isdigit(static_cast<unsigned char>(body[j]))) ++j;
        if (j == i) return std::nullopt;
        size_t length = 0;
        try {
            length = static_cast<size_t>(std::stoul(body.substr(i, j - i)));
        } catch (...) {
            return std::nullopt;
        }
        if (j + length > n) return std::nullopt;
        comps.push_back(decode_legacy_ident(body.substr(j, length)));
        i = j + length;
    }
    if (comps.empty()) return std::nullopt;
    std::string out;
    for (size_t k = 0; k < comps.size(); ++k) {
        if (k) out += "::";
        out += comps[k];
    }
    return out;
}

// ---------------------------------------------------------------------------
// v0 mangling (RFC 2603)
// ---------------------------------------------------------------------------

struct V0Error : std::runtime_error {
    explicit V0Error(const char* m) : std::runtime_error(m) {}
};

const std::unordered_map<char, const char*>& basic_types() {
    static const std::unordered_map<char, const char*> m = {
        {'a', "i8"}, {'b', "bool"}, {'c', "char"}, {'d', "f64"}, {'e', "str"},
        {'f', "f32"}, {'h', "u8"}, {'i', "isize"}, {'j', "usize"}, {'l', "i32"},
        {'m', "u32"}, {'n', "i128"}, {'o', "u128"}, {'s', "i16"}, {'t', "u16"},
        {'u', "()"}, {'v', "..."}, {'x', "i64"}, {'y', "u64"}, {'z', "!"}, {'p', "_"},
    };
    return m;
}

class V0Demangler {
public:
    explicit V0Demangler(const std::string& sym) {
        std::string body = sym.substr(2);  // drop "_R"
        if (!body.empty() && std::isdigit(static_cast<unsigned char>(body[0]))) {
            throw V0Error("unsupported v0 encoding version");
        }
        s_ = body;
        pos_ = 0;
        depth_ = 0;
    }

    std::string parse() {
        depth_ = 0;
        return path();
    }

private:
    std::string s_;
    size_t pos_;
    int depth_;

    char peek() {
        if (pos_ >= s_.size()) throw V0Error("eof");
        return s_[pos_];
    }
    char next() {
        char c = peek();
        ++pos_;
        return c;
    }
    bool eat(char c) {
        if (pos_ < s_.size() && s_[pos_] == c) { ++pos_; return true; }
        return false;
    }
    void guard() {
        if (++depth_ > 256) throw V0Error("recursion");
    }
    struct DepthGuard {
        V0Demangler* d;
        explicit DepthGuard(V0Demangler* dm) : d(dm) { d->guard(); }
        ~DepthGuard() { --d->depth_; }
    };

    long long base62() {
        if (eat('_')) return 0;
        long long val = 0;
        while (true) {
            char c = next();
            if (c == '_') return val + 1;
            if (c >= '0' && c <= '9') val = val * 62 + (c - '0');
            else if (c >= 'a' && c <= 'z') val = val * 62 + 10 + (c - 'a');
            else if (c >= 'A' && c <= 'Z') val = val * 62 + 36 + (c - 'A');
            else throw V0Error("bad base62");
        }
    }

    long long decimal() {
        size_t start = pos_;
        while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) ++pos_;
        if (pos_ == start) throw V0Error("expected decimal");
        return std::stoll(s_.substr(start, pos_ - start));
    }

    void disambiguator() {
        if (eat('s')) base62();
    }

    std::string identifier() {
        bool is_punycode = eat('u');
        long long n = decimal();
        eat('_');
        if (pos_ + static_cast<size_t>(n) > s_.size()) throw V0Error("ident underrun");
        std::string raw = s_.substr(pos_, static_cast<size_t>(n));
        pos_ += static_cast<size_t>(n);
        if (is_punycode) return decode_punycode(raw);
        return raw;
    }

    std::string path() {
        DepthGuard g(this);
        char tag = next();
        if (tag == 'C') {
            disambiguator();
            return identifier();
        }
        if (tag == 'N') {
            char ns = next();
            std::string parent = path();
            disambiguator();
            std::string name = identifier();
            if (name.empty()) return parent + "::{" + std::string(1, ns) + "}";
            return parent + "::" + name;
        }
        if (tag == 'M') {
            disambiguator();
            path();  // impl-path
            std::string ty = type();
            return "<" + ty + ">";
        }
        if (tag == 'X') {
            disambiguator();
            path();  // impl-path
            std::string ty = type();
            std::string tr = path();
            return "<" + ty + " as " + tr + ">";
        }
        if (tag == 'Y') {
            std::string ty = type();
            std::string tr = path();
            return "<" + ty + " as " + tr + ">";
        }
        if (tag == 'I') {
            std::string base = path();
            std::vector<std::string> args;
            while (!eat('E')) args.push_back(generic_arg());
            if (args.empty()) return base;
            std::string out = base + "::<";
            for (size_t i = 0; i < args.size(); ++i) {
                if (i) out += ", ";
                out += args[i];
            }
            out += ">";
            return out;
        }
        if (tag == 'B') {
            base62();
            return "_";
        }
        throw V0Error("unknown path tag");
    }

    std::string generic_arg() {
        if (eat('L')) { base62(); return "'_"; }
        if (eat('K')) return constant();
        return type();
    }

    std::string constant() {
        if (eat('B')) { base62(); return "_"; }
        std::string ty = type();
        if (eat('n')) return "-" + std::to_string(hex_const());
        if (eat('p')) return "_";
        long long val = hex_const();
        if (ty == "bool") return val == 1 ? "true" : "false";
        return std::to_string(val);
    }

    long long hex_const() {
        size_t start = pos_;
        while (pos_ < s_.size() && s_[pos_] != '_') ++pos_;
        std::string hexs = s_.substr(start, pos_ - start);
        eat('_');
        if (hexs.empty()) return 0;
        return std::stoll(hexs, nullptr, 16);
    }

    std::string opt_lifetime() {
        if (eat('L')) { base62(); return "'_ "; }
        return "";
    }

    std::string type() {
        DepthGuard g(this);
        char c = peek();
        auto it = basic_types().find(c);
        if (it != basic_types().end()) {
            ++pos_;
            return it->second;
        }
        char tag = next();
        if (tag == 'A') {
            std::string inner = type();
            std::string n = constant();
            return "[" + inner + "; " + n + "]";
        }
        if (tag == 'S') return "[" + type() + "]";
        if (tag == 'T') {
            std::vector<std::string> parts;
            while (!eat('E')) parts.push_back(type());
            if (parts.size() == 1) return "(" + parts[0] + ",)";
            std::string out = "(";
            for (size_t i = 0; i < parts.size(); ++i) {
                if (i) out += ", ";
                out += parts[i];
            }
            out += ")";
            return out;
        }
        if (tag == 'R') { std::string lt = opt_lifetime(); return "&" + lt + type(); }
        if (tag == 'Q') { std::string lt = opt_lifetime(); return "&" + lt + "mut " + type(); }
        if (tag == 'P') return "*const " + type();
        if (tag == 'O') return "*mut " + type();
        if (tag == 'F') return fn_sig();
        if (tag == 'D') {
            std::string bounds = dyn_bounds();
            opt_lifetime();
            return "dyn " + bounds;
        }
        if (tag == 'B') { base62(); return "_"; }
        --pos_;  // rewind: it is a path-type
        return path();
    }

    std::string fn_sig() {
        if (eat('G')) base62();
        eat('U');
        if (eat('K')) {
            if (!eat('C')) identifier();
        }
        std::vector<std::string> args;
        while (!eat('E')) args.push_back(type());
        std::string ret = type();
        std::string out = "fn(";
        for (size_t i = 0; i < args.size(); ++i) {
            if (i) out += ", ";
            out += args[i];
        }
        out += ") -> " + ret;
        return out;
    }

    std::string dyn_bounds() {
        if (eat('G')) base62();
        std::vector<std::string> traits;
        while (!eat('E')) {
            traits.push_back(path());
            while (eat('p')) {
                identifier();
                type();
            }
        }
        if (traits.empty()) return "?";
        std::string out;
        for (size_t i = 0; i < traits.size(); ++i) {
            if (i) out += " + ";
            out += traits[i];
        }
        return out;
    }

    // RFC 3492 punycode, as used by Rust v0 for non-ASCII identifiers.
    static std::string decode_punycode(const std::string& s) {
        const int BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700;
        const int INITIAL_BIAS = 72, INITIAL_N = 128;
        std::string basic, ext;
        size_t up = s.rfind('_');
        if (up != std::string::npos) {
            basic = s.substr(0, up);
            ext = s.substr(up + 1);
        } else {
            ext = s;
        }
        std::vector<unsigned> output(basic.begin(), basic.end());
        unsigned n = INITIAL_N;
        long long i = 0;
        int bias = INITIAL_BIAS;
        size_t idx = 0;
        auto adapt = [&](long long delta, long long numpoints, bool firsttime) -> int {
            delta = firsttime ? delta / DAMP : delta / 2;
            delta += delta / numpoints;
            int k = 0;
            while (delta > ((BASE - TMIN) * TMAX) / 2) {
                delta /= BASE - TMIN;
                k += BASE;
            }
            return k + static_cast<int>((BASE - TMIN + 1) * delta / (delta + SKEW));
        };
        while (idx < ext.size()) {
            long long oldi = i;
            long long w = 1;
            int k = BASE;
            while (true) {
                if (idx >= ext.size()) throw V0Error("bad punycode");
                char c = ext[idx++];
                int digit;
                if (c >= '0' && c <= '9') digit = c - '0' + 26;
                else if (c >= 'a' && c <= 'z') digit = c - 'a';
                else throw V0Error("bad punycode digit");
                i += digit * w;
                int t = k <= bias ? TMIN : (k >= bias + TMAX ? TMAX : k - bias);
                if (digit < t) break;
                w *= BASE - t;
                k += BASE;
            }
            long long out_len = static_cast<long long>(output.size()) + 1;
            bias = adapt(i - oldi, out_len, oldi == 0);
            n += static_cast<unsigned>(i / out_len);
            i %= out_len;
            output.insert(output.begin() + i, n);
            ++i;
        }
        std::string result;
        for (unsigned cp : output) append_utf8(result, cp);
        return result;
    }
};

// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------

std::string strip_symbol_prefix(const std::string& s) {
    if (s.size() >= 2 && s[0] == '_' && s[1] == '_') return s.substr(1);
    return s;
}

std::optional<std::string> demangle_raw(const std::string& in) {
    std::string s = strip_symbol_prefix(in);
    // Strip IDA thunk prefixes ("j_", possibly repeated) so jump-thunks to Rust
    // functions demangle to their target name.
    while (s.rfind("j_", 0) == 0) s = s.substr(2);
    if (s.rfind("_R", 0) == 0) {
        try {
            return V0Demangler(s).parse();
        } catch (...) {
            return std::nullopt;
        }
    }
    if (s.rfind("_ZN", 0) == 0 || s.rfind("ZN", 0) == 0) {
        return demangle_legacy(s);
    }
    return std::nullopt;
}

}  // namespace

std::string demangle(const std::string& sym) {
    std::optional<std::string> raw;
    try {
        raw = demangle_raw(sym);
    } catch (...) {
        return sym;
    }
    if (!raw.has_value()) return sym;
    std::vector<std::string> parts = split_path(*raw);
    if (parts.size() >= 2 && is_rust_hash(parts.back())) {
        std::string out;
        for (size_t k = 0; k + 1 < parts.size(); ++k) {
            if (k) out += "::";
            out += parts[k];
        }
        return out;
    }
    return *raw;
}

std::string normalize(const std::string& name, bool monopolize, bool concise, bool use_trait_name) {
    static const std::regex generic_re(R"((?:::)?<(?:(?!\sas\s)[^<])*?>)");
    static const std::regex xxx_as_re(R"(<(?!impl\s)([^<]+?)\sas\s([^<]+?)>)");
    static const std::regex impl_as_re(R"(<impl\s([^<]+?)\sas\s([^<]+?)>)");

    std::string demangled = demangle(name);
    if (monopolize) {
        size_t old_len = 0;
        while (old_len != demangled.size()) {
            old_len = demangled.size();
            demangled = std::regex_replace(demangled, generic_re, "");
            demangled = std::regex_replace(demangled, xxx_as_re, use_trait_name ? "$2" : "$1");
            demangled = std::regex_replace(demangled, impl_as_re, "$2");
        }
    }
    if (concise) {
        std::vector<std::string> parts = split_path(demangled);
        demangled = parts.empty() ? demangled : parts.back();
    }
    return demangled;
}

}  // namespace oxi
