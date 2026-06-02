// Minimal, dependency-free JSON reader for the Oxidizer-for-IDA core.
//
// The IDA SDK ships no JSON library, and the per-version Rust type database
// (angr/rust/analyses/type_db/<ver>.json) must be parsed at load time.  This is
// a small recursive-descent parser that is deliberately free of any IDA
// dependency so it can be unit-tested with a host compiler.
//
// Object members preserve insertion order (the type DB keys struct fields by a
// decimal byte-offset string; a sorted map would reorder "0","8","16" wrongly,
// and we also want stable iteration generally).
#pragma once

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace oxi {

class JsonValue {
public:
    enum class Type { Null, Bool, Int, Double, String, Array, Object };

    JsonValue() : type_(Type::Null) {}

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_object() const { return type_ == Type::Object; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_string() const { return type_ == Type::String; }
    bool is_number() const { return type_ == Type::Int || type_ == Type::Double; }

    bool as_bool(bool dflt = false) const { return type_ == Type::Bool ? bool_ : dflt; }
    long long as_int(long long dflt = 0) const {
        if (type_ == Type::Int) return int_;
        if (type_ == Type::Double) return static_cast<long long>(dbl_);
        return dflt;
    }
    double as_double(double dflt = 0.0) const {
        if (type_ == Type::Double) return dbl_;
        if (type_ == Type::Int) return static_cast<double>(int_);
        return dflt;
    }
    const std::string& as_string() const { return str_; }
    std::string as_string(const std::string& dflt) const { return type_ == Type::String ? str_ : dflt; }

    const std::vector<JsonValue>& items() const { return arr_; }
    const std::vector<std::pair<std::string, JsonValue>>& members() const { return obj_; }

    // Object lookup; returns the static null value if absent or not an object.
    const JsonValue& operator[](const std::string& key) const {
        if (type_ == Type::Object) {
            for (const auto& kv : obj_) {
                if (kv.first == key) return kv.second;
            }
        }
        return null_value();
    }

    bool has(const std::string& key) const {
        if (type_ != Type::Object) return false;
        for (const auto& kv : obj_) {
            if (kv.first == key) return true;
        }
        return false;
    }

    size_t size() const {
        if (type_ == Type::Array) return arr_.size();
        if (type_ == Type::Object) return obj_.size();
        return 0;
    }

    static const JsonValue& null_value();

    // builders (used by the parser)
    static JsonValue make_bool(bool b) { JsonValue v; v.type_ = Type::Bool; v.bool_ = b; return v; }
    static JsonValue make_int(long long i) { JsonValue v; v.type_ = Type::Int; v.int_ = i; return v; }
    static JsonValue make_double(double d) { JsonValue v; v.type_ = Type::Double; v.dbl_ = d; return v; }
    static JsonValue make_string(std::string s) { JsonValue v; v.type_ = Type::String; v.str_ = std::move(s); return v; }
    static JsonValue make_array() { JsonValue v; v.type_ = Type::Array; return v; }
    static JsonValue make_object() { JsonValue v; v.type_ = Type::Object; return v; }

    void push_back(JsonValue v) { arr_.push_back(std::move(v)); }
    void set(std::string key, JsonValue v) { obj_.emplace_back(std::move(key), std::move(v)); }

private:
    Type type_;
    bool bool_ = false;
    long long int_ = 0;
    double dbl_ = 0.0;
    std::string str_;
    std::vector<JsonValue> arr_;
    std::vector<std::pair<std::string, JsonValue>> obj_;
};

class JsonParseError : public std::runtime_error {
public:
    explicit JsonParseError(const std::string& msg) : std::runtime_error(msg) {}
};

// Parse a JSON document.  Throws JsonParseError on malformed input.
JsonValue json_parse(const std::string& text);

// Convenience: read a whole file and parse it.  Throws std::runtime_error if the
// file cannot be read, JsonParseError if it cannot be parsed.
JsonValue json_parse_file(const std::string& path);

}  // namespace oxi
