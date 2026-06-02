// Parser for Oxidizer's per-version Rust type database
// (angr/rust/analyses/type_db/<ver>.json) into a small typed IR.
//
// IDA-independent reimplementation of the parsing half of
// angr/rust/analyses/type_db_loader.py.  The oxidizer c_render layer lowers this
// IR to a C header that IDA's own parser ingests.
//
// Improvements over the angr version (its renderer could not use these):
//   * f32/f64 map to real floats instead of being dropped.
//   * char maps to a 4-byte value (a Rust Unicode scalar) instead of one byte.
// All sizes are in bytes.
#pragma once

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "json.h"

namespace oxi {

enum class RKind {
    Int,
    Float,
    Bool,
    Char,
    Pointer,
    Array,
    Slice,
    StrRef,
    Struct,
    Enum,
    Bottom,
};

struct RustType;
using RustTypePtr = std::shared_ptr<RustType>;

struct RustField {
    long long offset = 0;
    std::string name;
    RustTypePtr ty;
};

struct RustVariant {
    std::string name;
    bool has_disc = false;
    long long discriminant = 0;
    long long disc_size = 0;
    std::vector<RustField> fields;
};

struct RustType {
    RKind kind = RKind::Bottom;
    long long size = 0;  // bytes

    // Int
    int bits = 0;
    bool is_signed = false;
    std::string prim_name;

    // Pointer (pts_to) / Slice (ele) / Array (ele)
    RustTypePtr pts_to;
    RustTypePtr ele;
    long long length = 0;  // Array

    // Struct / Enum
    std::string name;
    std::vector<RustField> fields;      // Struct
    std::vector<RustVariant> variants;  // Enum
    long long disc_size = 0;            // Enum

    bool is_option() const;
    bool is_result() const;
    bool is_niche_encoded() const;
};

struct RustFnProto {
    std::vector<RustTypePtr> args;
    RustTypePtr ret;  // null when is_retbuf
    bool is_retbuf = false;
};

class TypeDB {
public:
    int arch_bits = 64;
    int arch_bytes = 8;

    std::map<std::string, RustTypePtr> types;             // struct/enum name -> IR
    std::map<std::string, std::vector<RustFnProto>> prototypes;

    static TypeDB from_file(const std::string& path, int arch_bits = 64);
    static TypeDB from_json(const JsonValue& data, int arch_bits = 64);

    // Lightweight: return just the function names in a type-DB JSON file without
    // parsing the (expensive) struct/enum graph.  Used for version pinning.
    static std::vector<std::string> load_function_names(const std::string& path);

private:
    std::map<std::string, const JsonValue*> struct_db_;
    std::set<std::string> pending_;
    std::set<std::string> resolving_;

    void load(const JsonValue& data);

    RustTypePtr parse_type(const JsonValue& data);
    RustTypePtr parse_pointer(const JsonValue& data);
    RustTypePtr parse_primitive(const JsonValue& data);
    RustTypePtr parse_array(const JsonValue& data);
    RustTypePtr parse_struct(const JsonValue& data);
    RustTypePtr parse_enum(const JsonValue& data);

    RustTypePtr apply_patches(const RustTypePtr& ty);
    RustTypePtr to_slice(const RustTypePtr& ty);
    RustTypePtr unwrap_argument(const RustTypePtr& ty);

    bool parse_prototype(const JsonValue& data, RustFnProto& out);
    RustFnProto fit_abi(std::vector<RustTypePtr> args, RustTypePtr ret);
};

}  // namespace oxi
