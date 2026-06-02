// Lower the Rust type IR (TypeDB) to a C header that IDA's own type parser can
// ingest in a single parse_decls() call, plus per-function C prototype strings.
//
// Rendering to C (instead of hand-building tinfo_t) keeps the hard logic a pure,
// host-testable string transform and is far more portable across IDA SDK
// versions.  Exact struct/enum layout is preserved with `#pragma pack(1)` and
// explicit padding fields computed from the IR's byte offsets and sizes.
//
// IDA-independent: testable with a host compiler.
#pragma once

#include <map>
#include <string>

#include "typedb.h"

namespace oxi {

class CRenderer {
public:
    explicit CRenderer(const TypeDB& db);

    // Full C header declaring every struct/enum in the DB (plus the builtin
    // Oxidizer_Slice / Oxidizer_StrRef fat-pointer types).  Safe to feed to
    // ida_typeinf parse_decls().  Always produces valid, correctly-sized types.
    std::string render_header();

    // The sanitized, C-safe identifier chosen for a Rust type name.  Valid after
    // render_header() (or call ensure_name()).  Empty if the type is unknown.
    std::string c_name_for(const std::string& rust_name) const;

    // Render a function prototype as a C declaration: "ret fname(args);".
    std::string render_prototype(const RustFnProto& proto, const std::string& fname);

    const std::map<std::string, std::string>& name_map() const { return name_map_; }

private:
    const TypeDB& db_;
    std::map<std::string, std::string> name_map_;  // rust name -> C identifier
    std::map<std::string, bool> used_cnames_;

    std::string ensure_name(const std::string& rust_name);
    std::string int_token(int bits, bool is_signed) const;
    std::string size_token(long long bytes) const;  // exact-width unsigned int or byte array base

    // A type used as a parameter / return / pointer-target token (no member name).
    std::string type_token(const RustTypePtr& t);
    // A full member declaration "TYPE name" (handles arrays / odd sizes exactly).
    std::string member_decl(const RustTypePtr& t, const std::string& member);

    std::string render_struct(const RustTypePtr& t);
    std::string render_enum(const RustTypePtr& t);
    std::string opaque(const std::string& cname, long long size, const std::string& comment) const;
};

}  // namespace oxi
