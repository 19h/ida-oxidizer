// Host-compiled test harness for the Oxidizer-for-IDA core (no IDA dependency).
// Mirrors the validated Python reference test-suite (reference_py/tests).
//
// Usage:  test_core [REPO_ROOT]   (default REPO_ROOT = /models/dev/oxidizer)
// Real-data tests (type_db / commit_versions / flirt_sigs) auto-skip if the
// asset files are not present.

#include <cstdio>
#include <fstream>
#include <iostream>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <vector>

#include "../src/core/c_render.h"
#include "../src/core/demangle.h"
#include "../src/core/idioms.h"
#include "../src/core/json.h"
#include "../src/core/typedb.h"
#include "../src/core/version_id.h"

using namespace oxi;

static int g_pass = 0, g_fail = 0, g_skip = 0;

#define CHECK(cond)                                                                 \
    do {                                                                            \
        if (cond) {                                                                 \
            ++g_pass;                                                               \
        } else {                                                                    \
            ++g_fail;                                                               \
            std::cerr << "FAIL: " << #cond << "  @ " << __LINE__ << "\n";           \
        }                                                                           \
    } while (0)

#define CHECK_EQ(a, b)                                                              \
    do {                                                                            \
        auto _a = (a);                                                              \
        decltype(_a) _b = (b);                                                      \
        if (_a == _b) {                                                             \
            ++g_pass;                                                               \
        } else {                                                                    \
            ++g_fail;                                                               \
            std::cerr << "FAIL: " << #a << " == " << #b << "  got [" << _a          \
                      << "] vs [" << _b << "]  @ " << __LINE__ << "\n";             \
        }                                                                           \
    } while (0)

static bool file_exists(const std::string& p) {
    std::ifstream f(p);
    return f.good();
}

// ---------------------------------------------------------------------------
// demangle
// ---------------------------------------------------------------------------
static void test_demangle() {
    // legacy
    CHECK_EQ(demangle("_ZN4core3fmt9Formatter3pad17h05af221ea0b56f8aE"), std::string("core::fmt::Formatter::pad"));
    CHECK_EQ(demangle("ZN3std2rt10lang_start17h0123456789abcdefE"), std::string("std::rt::lang_start"));
    CHECK_EQ(demangle("_ZN33_$LT$alloc..vec..Vec$LT$T$GT$$GT$4push17habcdef0123456789E"),
             std::string("<alloc::vec::Vec<T>>::push"));
    CHECK_EQ(demangle("_ZN3foo3barE"), std::string("foo::bar"));
    CHECK_EQ(demangle("_ZN3foo11baz$u20$qux17h05af221ea0b56f8aE"), std::string("foo::baz qux"));

    // v0
    CHECK_EQ(demangle("_RNvNtCs1234_7mycrate3foo3bar"), std::string("mycrate::foo::bar"));
    CHECK_EQ(demangle("_RC7mycrate"), std::string("mycrate"));
    {
        std::string out = demangle("_RINvNtCs1_5alloc3vec3VechE");
        CHECK(out.rfind("alloc::vec::Vec", 0) == 0);
        CHECK(out.find("<u8>") != std::string::npos);
    }
    {
        std::string out = demangle("_RINvNtCs1_4core3mem4swapRlE");
        CHECK(out.find("core::mem::swap") != std::string::npos);
        CHECK(out.find("&i32") != std::string::npos);
    }

    // normalize
    CHECK_EQ(normalize("alloc::vec::Vec<u8>::push"), std::string("alloc::vec::Vec::push"));
    CHECK_EQ(normalize("<alloc::vec::Vec<u8> as core::ops::Drop>::drop"), std::string("alloc::vec::Vec::drop"));
    CHECK_EQ(normalize("<alloc::vec::Vec<u8> as core::ops::Drop>::drop", true, false, true),
             std::string("core::ops::Drop::drop"));
    CHECK_EQ(normalize("<impl Foo as core::fmt::Display>::fmt"), std::string("core::fmt::Display::fmt"));
    CHECK_EQ(normalize("core::fmt::Formatter::pad", true, true), std::string("pad"));
    CHECK_EQ(normalize("core::ptr::drop_in_place"), std::string("core::ptr::drop_in_place"));

    // IDA thunk prefixes ("j_", possibly repeated) are stripped before demangling
    CHECK_EQ(demangle("j__ZN4core3fmt9Formatter3pad17h05af221ea0b56f8aE"),
             std::string("core::fmt::Formatter::pad"));
    CHECK_EQ(demangle("j_j_j__ZN3foo3barE"), std::string("foo::bar"));
    CHECK_EQ(demangle("j_close"), std::string("j_close"));  // non-rust thunk unchanged

    // robustness
    CHECK_EQ(demangle("main"), std::string("main"));
    CHECK_EQ(demangle("_GLOBAL_OFFSET_TABLE_"), std::string("_GLOBAL_OFFSET_TABLE_"));
    CHECK_EQ(demangle("_R!!!broken"), std::string("_R!!!broken"));
}

// ---------------------------------------------------------------------------
// idioms
// ---------------------------------------------------------------------------
static void test_idioms() {
    CHECK(classify("core::panicking::panic_fmt") == Idiom::Panic);
    CHECK(is_noreturn("core::panicking::panic_fmt"));
    CHECK(classify("_ZN4core9panicking9panic_fmt17h05af221ea0b56f8aE") == Idiom::Panic);
    CHECK(is_noreturn("_ZN4core9panicking9panic_fmt17h05af221ea0b56f8aE"));
    CHECK(classify("core::panicking::panic_bounds_check") == Idiom::Bounds);
    CHECK(is_noreturn("core::panicking::panic_bounds_check"));
    CHECK(is_noreturn("core::result::unwrap_failed"));
    CHECK(is_noreturn("core::option::expect_failed"));
    CHECK(classify("core::ptr::drop_in_place<alloc::string::String>") == Idiom::Drop);
    CHECK(!is_noreturn("core::ptr::drop_in_place<alloc::string::String>"));
    CHECK(classify("alloc::alloc::exchange_malloc") == Idiom::Alloc);
    CHECK(classify("alloc::alloc::box_free") == Idiom::Dealloc);
    CHECK(classify("core::fmt::Arguments::new_v1") == Idiom::Format);
    CHECK(classify("core::fmt::Formatter::pad") == Idiom::Format);
    CHECK(classify("main") == Idiom::None);
    CHECK(classify("my_app::do_business_logic") == Idiom::None);
    CHECK(!is_noreturn("main"));
    CHECK(!comment_for("core::panicking::panic_fmt").empty());
    CHECK(comment_for("main").empty());
}

// ---------------------------------------------------------------------------
// version_id
// ---------------------------------------------------------------------------
static void test_version_id(const std::string& repo) {
    CHECK_EQ(*find_version_in_strings({"x", "compiled by rustc 1.72.1 (deadbeef)", "y"}), std::string("1.72.1"));
    CHECK_EQ(*find_version_in_strings({"/home/user/rust-1.65.0/library/std"}), std::string("1.65.0"));
    {
        std::string h(40, 'a');
        auto out = find_version_in_strings({"/rustc/" + h + "/library/core/src/panic.rs"},
                                           [&](const std::string& c) -> std::optional<std::string> {
                                               return c == h ? std::optional<std::string>("1.70.0") : std::nullopt;
                                           });
        CHECK(out.has_value() && *out == "1.70.0");
    }
    {
        // Unresolved commit must NOT short-circuit: fall through to the version
        // string pattern (robustness for nightlies not in the commit table).
        std::string h(40, 'b');
        auto out = find_version_in_strings({"/rustc/" + h + "/x", "rustc 1.50.0"},
                                           [](const std::string&) -> std::optional<std::string> { return std::nullopt; });
        CHECK(out.has_value() && *out == "1.50.0");
    }
    {
        // Unresolved commit and no version string -> nullopt (caller falls back).
        std::string h(40, 'c');
        auto out = find_version_in_strings({"/rustc/" + h + "/x"},
                                           [](const std::string&) -> std::optional<std::string> { return std::nullopt; });
        CHECK(!out.has_value());
    }
    CHECK(!find_version_in_strings({"nothing", "useful"}).has_value());

    CHECK(parse_sig_filename("1.87.0-O3.sig").version == (std::vector<int>{1, 87, 0}));
    CHECK_EQ(parse_sig_filename("1.87.0-O3.sig").opt_level, std::string("3"));
    CHECK(parse_sig_filename("/x/y/1.39.0-O0.sig").version == (std::vector<int>{1, 39, 0}));

    // FLIRT scoring peaks at the target.
    {
        std::vector<std::string> sigs;
        for (int minor = 40; minor <= 90; ++minor) sigs.push_back("1." + std::to_string(minor) + ".0-O3.sig");
        auto [ver, count] = identify_version_by_flirt(sigs, [](const std::string& sig) {
            int minor = parse_sig_filename(sig).version[1];
            int d = minor > 70 ? minor - 70 : 70 - minor;
            int v = 1000 - d * 50;
            return v < 0 ? 0 : v;
        });
        CHECK(ver.has_value() && *ver == "1.70.0");
        CHECK_EQ(count, 1000);
    }
    {
        auto [ver, count] = identify_version_by_flirt({"1.50.0-O3.sig", "1.50.0-O3.sig", "1.60.0-O3.sig"},
                                                      [](const std::string& s) { return s.rfind("1.60", 0) == 0 ? 5 : 1; });
        (void)count;
        CHECK(ver.has_value() && *ver == "1.60.0");
    }
    {
        auto [ver, count] = identify_version_by_flirt({}, [](const std::string&) { return 0; });
        (void)count;
        CHECK(!ver.has_value());
    }

    // version pinning by type-DB function-name overlap (timing-independent)
    {
        std::set<std::string> recovered = {"core::ptr::drop_in_place<A>", "std::io::Read::read",
                                           "alloc::vec::Vec::push"};
        auto names_for = [](const std::string& v) -> std::vector<std::string> {
            if (v == "1.80.0") return {"core::ptr::drop_in_place<A>", "std::io::Read::read", "x::y"};  // 2
            if (v == "1.70.0") return {"alloc::vec::Vec::push", "z::w"};                                // 1
            return {};
        };
        auto [ver, ov] = pick_version_by_overlap(recovered, {"1.70.0", "1.80.0"}, names_for);
        CHECK(ver.has_value() && *ver == "1.80.0");
        CHECK_EQ(ov, 2);
        auto [none, z] = pick_version_by_overlap({}, {"1.80.0"}, names_for);
        (void)z;
        CHECK(!none.has_value());
    }

    // real commit map
    std::string commit = repo + "/angr/rust/definitions/commit_versions.py";
    if (file_exists(commit)) {
        // find a real (hash, ver) pair from the file
        std::ifstream f(commit);
        std::string line, hash, ver;
        std::regex pat(R"(['"]([0-9a-f]{40})['"]\s*:\s*['"]([0-9.]+)['"])");
        while (std::getline(f, line)) {
            std::smatch m;
            if (std::regex_search(line, m, pat)) { hash = m[1]; ver = m[2]; break; }
        }
        if (!hash.empty()) {
            auto got = lookup_commit_version(commit, hash);
            CHECK(got.has_value() && *got == ver);
        } else {
            ++g_skip;
        }
        CHECK(!lookup_commit_version(commit, std::string(40, 'f')).has_value());
    } else {
        g_skip += 2;
        std::cerr << "SKIP: commit_versions.py not found\n";
    }
}

// ---------------------------------------------------------------------------
// typedb + c_render (real data)
// ---------------------------------------------------------------------------
static void test_typedb_and_render(const std::string& repo) {
    std::string db_path = repo + "/angr/rust/analyses/type_db/1.75.0.json";
    if (!file_exists(db_path)) {
        g_skip += 1;
        std::cerr << "SKIP: type_db/1.75.0.json not found\n";
        return;
    }
    TypeDB db = TypeDB::from_file(db_path);
    CHECK(db.types.size() > 2000);
    CHECK(db.prototypes.size() > 2000);

    // lightweight function-name loader (used for version pinning)
    std::vector<std::string> fnames = TypeDB::load_function_names(db_path);
    CHECK(fnames.size() > 2000);

    bool saw_str = false, saw_slice = false, saw_option = false, saw_result = false;
    for (const auto& [name, t] : db.types) {
        (void)name;
        if (t->kind == RKind::StrRef) saw_str = true;
        if (t->kind == RKind::Slice) saw_slice = true;
        if (t->kind == RKind::Enum && t->is_option()) saw_option = true;
        if (t->kind == RKind::Enum && t->is_result()) saw_result = true;
    }
    CHECK(saw_str);
    CHECK(saw_slice);
    CHECK(saw_option);
    CHECK(saw_result);

    bool saw_retbuf = false;
    for (const auto& [name, protos] : db.prototypes) {
        (void)name;
        for (const auto& p : protos) {
            if (p.is_retbuf) {
                saw_retbuf = true;
                CHECK(!p.args.empty() && p.args[0]->kind == RKind::Pointer);
                CHECK(p.ret == nullptr);
            }
        }
    }
    CHECK(saw_retbuf);

    // Render the header and write it to disk for the C-compile verification step.
    CRenderer renderer(db);
    std::string header = renderer.render_header();
    CHECK(header.find("#pragma pack(push, 1)") != std::string::npos);
    CHECK(header.find("Oxidizer_Slice") != std::string::npos);
    CHECK(header.size() > 10000);

    std::ofstream out("/tmp/oxidizer_types.h", std::ios::binary);
    out << header;
    out.close();
    std::cerr << "INFO: wrote generated header (" << header.size() << " bytes) to /tmp/oxidizer_types.h\n";

    // Render a few prototypes and sanity check they look like C decls.
    int rendered = 0;
    for (const auto& [name, protos] : db.prototypes) {
        std::string c = renderer.render_prototype(protos[0], "f");
        CHECK(!c.empty() && c.back() == ';' && c.find("f(") != std::string::npos);
        if (++rendered >= 50) break;
    }
}

// ---------------------------------------------------------------------------
// json unit checks
// ---------------------------------------------------------------------------
static void test_json() {
    JsonValue v = json_parse(R"({"a": 1, "b": [true, null, "x\n"], "c": {"d": 3.5}})");
    CHECK(v.is_object());
    CHECK_EQ(v["a"].as_int(), 1LL);
    CHECK(v["b"].is_array());
    CHECK_EQ(v["b"].size(), (size_t)3);
    CHECK(v["b"].items()[0].as_bool());
    CHECK(v["b"].items()[1].is_null());
    CHECK_EQ(v["b"].items()[2].as_string(), std::string("x\n"));
    CHECK(v["c"]["d"].as_double() == 3.5);
    // insertion order preserved for object members
    CHECK_EQ(v.members()[0].first, std::string("a"));
    // valid surrogate pair -> U+1F600 (F0 9F 98 80)
    CHECK_EQ(json_parse("\"\\uD83D\\uDE00\"").as_string(), std::string("\xF0\x9F\x98\x80"));
    // unpaired high surrogate -> U+FFFD (EF BF BD), not invalid CESU-8
    CHECK_EQ(json_parse("\"\\uD800x\"").as_string(), std::string("\xEF\xBF\xBD") + "x");
    // lone low surrogate -> U+FFFD
    CHECK_EQ(json_parse("\"\\uDC00\"").as_string(), std::string("\xEF\xBF\xBD"));
    // error path
    bool threw = false;
    try {
        json_parse("{bad}");
    } catch (const JsonParseError&) {
        threw = true;
    }
    CHECK(threw);
}

// An odd-width primitive must render as a same-sized VALUE type, never a pointer.
static void test_render_oddwidth() {
    const char* j =
        "{\"structs\":[],\"functions\":[{\"name\":\"f\",\"prototype\":{\"kind\":\"Prototype\","
        "\"args\":[{\"kind\":\"Primitive\",\"name\":\"weird\",\"size\":3}],"
        "\"returnty\":{\"kind\":\"None\"}}}]}";
    TypeDB db = TypeDB::from_json(json_parse(j));
    auto it = db.prototypes.find("f");
    CHECK(it != db.prototypes.end());
    if (it != db.prototypes.end()) {
        CRenderer r(db);
        std::string proto = r.render_prototype(it->second[0], "f");
        CHECK(proto.find('*') == std::string::npos);          // not a pointer
        CHECK(proto.find("unsigned __int8") != std::string::npos);  // value fallback
    }
}

int main(int argc, char** argv) {
    std::string repo = argc > 1 ? argv[1] : std::string("/models/dev/oxidizer");
    std::cerr << "repo root: " << repo << "\n";

    test_json();
    test_render_oddwidth();
    test_demangle();
    test_idioms();
    test_version_id(repo);
    test_typedb_and_render(repo);

    std::cerr << "\n========================================\n";
    std::cerr << "PASS: " << g_pass << "   FAIL: " << g_fail << "   SKIP: " << g_skip << "\n";
    std::cerr << "========================================\n";
    return g_fail == 0 ? 0 : 1;
}
