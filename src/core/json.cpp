#include "json.h"

#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace oxi {

const JsonValue& JsonValue::null_value() {
    static const JsonValue kNull;
    return kNull;
}

namespace {

struct Parser {
    const char* p;
    const char* end;

    explicit Parser(const std::string& s) : p(s.data()), end(s.data() + s.size()) {}

    [[noreturn]] void fail(const std::string& msg) {
        throw JsonParseError("JSON parse error: " + msg);
    }

    void skip_ws() {
        while (p < end) {
            char c = *p;
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                ++p;
            } else {
                break;
            }
        }
    }

    char peek() {
        if (p >= end) fail("unexpected end of input");
        return *p;
    }

    JsonValue parse_value() {
        skip_ws();
        char c = peek();
        switch (c) {
            case '{': return parse_object();
            case '[': return parse_array();
            case '"': return JsonValue::make_string(parse_string());
            case 't':
            case 'f': return parse_bool();
            case 'n': return parse_null();
            default:
                if (c == '-' || (c >= '0' && c <= '9')) return parse_number();
                fail(std::string("unexpected character '") + c + "'");
        }
    }

    JsonValue parse_object() {
        JsonValue obj = JsonValue::make_object();
        ++p;  // consume '{'
        skip_ws();
        if (p < end && *p == '}') { ++p; return obj; }
        while (true) {
            skip_ws();
            if (peek() != '"') fail("expected string key in object");
            std::string key = parse_string();
            skip_ws();
            if (peek() != ':') fail("expected ':' after object key");
            ++p;
            JsonValue val = parse_value();
            obj.set(std::move(key), std::move(val));
            skip_ws();
            char c = peek();
            if (c == ',') { ++p; continue; }
            if (c == '}') { ++p; break; }
            fail("expected ',' or '}' in object");
        }
        return obj;
    }

    JsonValue parse_array() {
        JsonValue arr = JsonValue::make_array();
        ++p;  // consume '['
        skip_ws();
        if (p < end && *p == ']') { ++p; return arr; }
        while (true) {
            JsonValue val = parse_value();
            arr.push_back(std::move(val));
            skip_ws();
            char c = peek();
            if (c == ',') { ++p; continue; }
            if (c == ']') { ++p; break; }
            fail("expected ',' or ']' in array");
        }
        return arr;
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

    unsigned parse_hex4() {
        if (end - p < 4) fail("truncated \\u escape");
        unsigned v = 0;
        for (int i = 0; i < 4; ++i) {
            char c = *p++;
            v <<= 4;
            if (c >= '0' && c <= '9') v |= unsigned(c - '0');
            else if (c >= 'a' && c <= 'f') v |= unsigned(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= unsigned(c - 'A' + 10);
            else fail("invalid hex digit in \\u escape");
        }
        return v;
    }

    std::string parse_string() {
        ++p;  // consume opening quote
        std::string out;
        while (true) {
            if (p >= end) fail("unterminated string");
            char c = *p++;
            if (c == '"') break;
            if (c == '\\') {
                if (p >= end) fail("unterminated escape");
                char e = *p++;
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        unsigned cp = parse_hex4();
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            // high surrogate: must be followed by a low surrogate
                            if (end - p >= 2 && p[0] == '\\' && p[1] == 'u') {
                                p += 2;
                                unsigned lo = parse_hex4();
                                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                } else {
                                    // unpaired high surrogate -> U+FFFD; then the
                                    // second value (itself replaced if a surrogate).
                                    append_utf8(out, 0xFFFD);
                                    cp = (lo >= 0xD800 && lo <= 0xDFFF) ? 0xFFFD : lo;
                                }
                            } else {
                                cp = 0xFFFD;  // lone high surrogate
                            }
                        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                            cp = 0xFFFD;  // lone low surrogate
                        }
                        append_utf8(out, cp);
                        break;
                    }
                    default: fail(std::string("invalid escape '\\") + e + "'");
                }
            } else {
                out.push_back(c);
            }
        }
        return out;
    }

    JsonValue parse_number() {
        const char* start = p;
        bool is_double = false;
        if (p < end && *p == '-') ++p;
        while (p < end && *p >= '0' && *p <= '9') ++p;
        if (p < end && *p == '.') { is_double = true; ++p; while (p < end && *p >= '0' && *p <= '9') ++p; }
        if (p < end && (*p == 'e' || *p == 'E')) {
            is_double = true;
            ++p;
            if (p < end && (*p == '+' || *p == '-')) ++p;
            while (p < end && *p >= '0' && *p <= '9') ++p;
        }
        std::string num(start, p);
        if (is_double) {
            return JsonValue::make_double(std::strtod(num.c_str(), nullptr));
        }
        errno = 0;
        long long v = std::strtoll(num.c_str(), nullptr, 10);
        return JsonValue::make_int(v);
    }

    JsonValue parse_bool() {
        if (end - p >= 4 && std::string(p, p + 4) == "true") { p += 4; return JsonValue::make_bool(true); }
        if (end - p >= 5 && std::string(p, p + 5) == "false") { p += 5; return JsonValue::make_bool(false); }
        fail("invalid literal");
    }

    JsonValue parse_null() {
        if (end - p >= 4 && std::string(p, p + 4) == "null") { p += 4; return JsonValue(); }
        fail("invalid literal");
    }
};

}  // namespace

JsonValue json_parse(const std::string& text) {
    Parser parser(text);
    JsonValue v = parser.parse_value();
    parser.skip_ws();
    if (parser.p != parser.end) {
        throw JsonParseError("JSON parse error: trailing data after document");
    }
    return v;
}

JsonValue json_parse_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot open file: " + path);
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return json_parse(ss.str());
}

}  // namespace oxi
