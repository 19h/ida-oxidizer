// Oxidizer-for-IDA : native IDA SDK plugin.
//
// Brings a useful slice of Oxidizer's Rust-decompilation capabilities to IDA /
// Hex-Rays without depending on angr.  On invocation it:
//   1. detects the rustc version (embedded strings -> commit map),
//   2. (best effort) applies the matching Rust std FLIRT signatures,
//   3. demangles & renames every function (legacy + v0 mangling),
//   4. marks panic/abort helpers no-return (cleans up decompiler output),
//   5. loads the version-specific type DB, materialises the std structs/enums as
//      IDA local types, and applies recovered function prototypes,
//   6. (if built with Hex-Rays) annotates recognised Rust idiom calls.
//
// The heavy lifting (demangling, version-id, type-DB parsing, C rendering) lives
// in the IDA-independent `core/` library, which is unit-tested with a host
// compiler.  This file is the thin glue that talks to the SDK.

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <typeinf.hpp>
#include <auto.hpp>
#include <diskio.hpp>
#include <bytes.hpp>
#include <nalt.hpp>
#include <fpro.h>
#include <strlist.hpp>

#include <cstdio>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "core/c_render.h"
#include "core/demangle.h"
#include "core/idioms.h"
#include "core/typedb.h"
#include "core/version_id.h"

#ifdef OXIDIZER_WITH_HEXRAYS
#include <hexrays.hpp>
#include "ida/idiom_hooks.h"
#endif

#ifndef OXIDIZER_DEFAULT_DATA_DIR
#define OXIDIZER_DEFAULT_DATA_DIR "/models/dev/oxidizer/angr/rust/analyses"
#endif

namespace {

// ---------------------------------------------------------------------------
// path resolution
// ---------------------------------------------------------------------------

std::string data_dir() {
    qstring buf;
    if (qgetenv("OXIDIZER_DATA_DIR", &buf) && !buf.empty()) return std::string(buf.c_str());
    return std::string(OXIDIZER_DEFAULT_DATA_DIR);
}

std::string type_db_path(const std::string& version) {
    return data_dir() + "/type_db/" + version + ".json";
}

std::string commit_versions_path() {
    // <data>/type_db/.. -> <data>; commit map lives at ../definitions/commit_versions.py
    return data_dir() + "/../definitions/commit_versions.py";
}

bool file_readable(const std::string& path) {
    return qfileexist(path.c_str());
}

// ---------------------------------------------------------------------------
// gather binary strings (for version detection)
// ---------------------------------------------------------------------------

std::vector<std::string> collect_strings(size_t max_strings = 200000) {
    std::vector<std::string> out;
    build_strlist();
    size_t qty = get_strlist_qty();
    if (qty > max_strings) qty = max_strings;
    for (size_t i = 0; i < qty; ++i) {
        string_info_t si;
        if (!get_strlist_item(&si, i)) continue;
        qstring buf;
        if (get_strlit_contents(&buf, si.ea, si.length, si.type) > 0) {
            out.emplace_back(buf.c_str());
        }
    }
    return out;
}

std::optional<std::string> detect_version() {
    std::vector<std::string> strings = collect_strings();
    std::string cv = commit_versions_path();
    bool have_cv = file_readable(cv);
    auto commit_lookup = [&](const std::string& hash) -> std::optional<std::string> {
        if (!have_cv) return std::nullopt;
        return oxi::lookup_commit_version(cv, hash);
    };
    return oxi::find_version_in_strings(strings, commit_lookup);
}

// ---------------------------------------------------------------------------
// rename + no-return marking; returns a demangled-name -> addresses map
// ---------------------------------------------------------------------------

struct RenameStats {
    int renamed = 0;
    int noret = 0;
    std::map<std::string, std::vector<ea_t>> by_demangled;
};

RenameStats rename_functions(bool reanalyze) {
    RenameStats stats;
    size_t n = get_func_qty();
    for (size_t i = 0; i < n; ++i) {
        func_t* f = getn_func(i);
        if (f == nullptr) continue;
        ea_t ea = f->start_ea;

        qstring raw;
        // mangled / current name (skip dummy names like sub_XXXX, those won't demangle)
        if (get_func_name(&raw, ea) <= 0) continue;
        std::string original(raw.c_str());

        std::string dem = oxi::demangle(original);
        stats.by_demangled[dem].push_back(ea);

        if (dem != original && !dem.empty()) {
            // SN_NOCHECK lets Rust path characters ('::','<','>') through, like
            // IDA's own demangled names.
            if (set_name(ea, dem.c_str(), SN_NOCHECK | SN_FORCE | SN_NOWARN)) {
                ++stats.renamed;
            }
        }

        if (oxi::is_noreturn(original) || oxi::is_noreturn(dem)) {
            if ((f->flags & FUNC_NORET) == 0) {
                f->flags |= FUNC_NORET;
                update_func(f);
                // The decompiler honours FUNC_NORET at decompile time; only force a
                // re-analysis in interactive mode (avoids re-entrancy when invoked
                // from the auto_empty_finally event during headless analysis).
                if (reanalyze) reanalyze_function(f);
                ++stats.noret;
            }
        }
    }
    return stats;
}

// ---------------------------------------------------------------------------
// type DB application
// ---------------------------------------------------------------------------

struct TypeStats {
    bool loaded = false;
    int parse_errors = 0;
    int prototypes_applied = 0;
    size_t types_declared = 0;
};

// Best-effort argument count for a function: prefer any prototype IDA already
// holds; otherwise (when Hex-Rays is present) fall back to the decompiler's
// inferred prototype.  Returns -1 if unknown.
int inferred_argcount(ea_t ea) {
    tinfo_t cur;
    if (get_tinfo(&cur, ea) && cur.is_func()) {
        int n = cur.get_nargs();
        if (n >= 0) return n;
    }
#ifdef OXIDIZER_WITH_HEXRAYS
    if (init_hexrays_plugin()) {
        func_t* pfn = get_func(ea);
        if (pfn != nullptr) {
            hexrays_failure_t hf;
            cfuncptr_t cf = decompile(pfn, &hf, DECOMP_NO_WAIT);
            if (cf != nullptr) {
                tinfo_t ft;
                if (cf->get_func_type(&ft)) {
                    int n = ft.get_nargs();
                    if (n >= 0) return n;
                }
            }
        }
    }
#endif
    return -1;
}

TypeStats apply_type_db(const std::string& version, const RenameStats& names) {
    TypeStats ts;
    std::string path = type_db_path(version);
    if (!file_readable(path)) {
        msg("[oxidizer] no type DB for version %s (%s)\n", version.c_str(), path.c_str());
        return ts;
    }

    oxi::TypeDB db;
    try {
        db = oxi::TypeDB::from_file(path, inf_is_64bit() ? 64 : 32);
    } catch (const std::exception& e) {
        msg("[oxidizer] failed to parse type DB: %s\n", e.what());
        return ts;
    }
    ts.loaded = true;
    ts.types_declared = db.types.size();

    oxi::CRenderer renderer(db);
    std::string header = renderer.render_header();

    // Materialise the std structs/enums into the local type library.
    til_t* til = get_idati();
    int herr = parse_decls(til, header.c_str(), nullptr, HTI_DCL | HTI_PAKDEF);
    ts.parse_errors = herr;
    if (herr != 0) {
        msg("[oxidizer] parse_decls reported %d issue(s) while loading std types\n", herr);
    }

    // Cache: parse a C prototype string into a tinfo_t once.
    std::map<std::string, tinfo_t> proto_cache;
    auto parse_proto = [&](const std::string& cdecl_str, tinfo_t& out) -> bool {
        auto cit = proto_cache.find(cdecl_str);
        if (cit != proto_cache.end()) {
            out = cit->second;
            return out.is_func();
        }
        tinfo_t tif;
        bool ok = parse_decl(&tif, nullptr, til, cdecl_str.c_str(), PT_SIL) && tif.is_func();
        proto_cache[cdecl_str] = tif;
        out = tif;
        return ok;
    };

    // Apply recovered prototypes to matching functions:
    //  * unambiguous name (single prototype, or several rendering identically)
    //    -> apply to every matching address;
    //  * ambiguous name (genuinely distinct monomorphisation prototypes)
    //    -> negotiate per address: pick the candidate whose argument count
    //       uniquely matches the one IDA/Hex-Rays inferred for that function.
    // Both paths are provably safe: a prototype is only applied when the DB
    // determines a single correct signature for that address.
    for (const auto& kv : db.prototypes) {
        const std::string& fname = kv.first;
        const std::vector<oxi::RustFnProto>& protos = kv.second;
        if (protos.empty()) continue;

        auto it = names.by_demangled.find(fname);
        if (it == names.by_demangled.end()) continue;

        // Distinct rendered prototypes, each remembering its argument count.
        std::vector<std::pair<std::string, int>> distinct;  // (cdecl, argcount)
        for (const auto& p : protos) {
            std::string cd = renderer.render_prototype(p, "f");
            bool seen = false;
            for (const auto& d : distinct) {
                if (d.first == cd) { seen = true; break; }
            }
            if (!seen) distinct.emplace_back(cd, static_cast<int>(p.args.size()));
        }

        if (distinct.size() == 1) {
            tinfo_t tif;
            if (!parse_proto(distinct[0].first, tif)) continue;
            for (ea_t ea : it->second) {
                if (apply_tinfo(ea, tif, TINFO_DEFINITE)) ++ts.prototypes_applied;
            }
        } else {
            // Negotiate per address by the inferred argument count.
            for (ea_t ea : it->second) {
                int nargs = inferred_argcount(ea);
                if (nargs < 0) continue;
                const std::string* chosen = nullptr;
                for (const auto& d : distinct) {
                    if (d.second == nargs) {
                        if (chosen != nullptr && *chosen != d.first) { chosen = nullptr; break; }
                        chosen = &d.first;
                    }
                }
                if (chosen == nullptr) continue;  // no unique candidate
                tinfo_t tif;
                if (!parse_proto(*chosen, tif)) continue;
                if (apply_tinfo(ea, tif, TINFO_DEFINITE)) ++ts.prototypes_applied;
            }
        }
    }
    return ts;
}

// ---------------------------------------------------------------------------
// FLIRT (best effort): copy the matching sig into IDA's sig dir and apply it.
// ---------------------------------------------------------------------------

bool copy_file(const std::string& src, const std::string& dst) {
    // Use IDA's qfile API (the SDK macros out raw libc fopen/fread/...).
    FILE* in = qfopen(src.c_str(), "rb");
    if (in == nullptr) return false;
    FILE* out = qfopen(dst.c_str(), "wb");
    if (out == nullptr) {
        qfclose(in);
        return false;
    }
    char buf[65536];
    ssize_t r;
    bool ok = true;
    while ((r = qfread(in, buf, sizeof(buf))) > 0) {
        if (qfwrite(out, buf, static_cast<size_t>(r)) != r) {
            ok = false;
            break;
        }
    }
    qfclose(in);
    qfclose(out);
    return ok;
}

int apply_flirt(const std::string& version) {
    // Stage Oxidizer's Rust std signatures into IDA's processor sig dir and plan
    // them.  FLIRT matching is byte-precise, so applying every available opt level
    // and both the inlined / no-inline sig sets is safe (non-matching patterns
    // simply don't fire) and maximises std/core/alloc recovery -- this is what
    // makes stripped Rust binaries tractable.
    int planned = 0;
    // metapc (x86/x86-64) uses the "pc" sig subdir; fall back to the processor name.
    qstring proc = inf_get_procname();
    std::string subdir = (proc == "metapc" || proc.empty()) ? "pc" : std::string(proc.c_str());
    std::string sigdir = std::string(idadir(SIG_SUBDIR)) + "/" + subdir;

    const char* sets[] = {"flirt_sigs", "flirt_sigs_no_inline"};
    const char* opts[] = {"3", "2", "1", "0"};
    for (const char* set : sets) {
        for (const char* opt : opts) {
            std::string src = data_dir() + "/" + set + "/" + version + "-O" + opt + ".sig";
            if (!file_readable(src)) continue;
            std::string sig_name = std::string("oxi_") + set + "_" + version + "_O" + opt + ".sig";
            if (!copy_file(src, sigdir + "/" + sig_name)) {
                msg("[oxidizer] could not stage FLIRT sig into %s (permissions?)\n", sigdir.c_str());
                continue;
            }
            // plan_to_apply_idasgn wants the basename only (no directory part).
            if (plan_to_apply_idasgn(sig_name.c_str()) != 0) ++planned;
        }
    }
    return planned;  // application happens during the next analysis pass
}

// ---------------------------------------------------------------------------
// version-robust fallback: when the exact rustc version cannot be read from the
// binary (stripped / unknown nightly commit not in the table), recover anyway by
// applying FLIRT for ALL known versions (byte-precise matching means only the
// binary's actual version fires) and then pinning the version by matching the
// recovered std names against each version's type-DB function-name set.
// ---------------------------------------------------------------------------

// Collects basenames matching a pattern in a directory (drops the extension for
// .json type-DB version files).
struct name_collector_t : public file_enumerator_t {
    std::vector<std::string> names;
    std::string strip_ext;  // if set, remove this suffix
    int visit_file(const char* file) override {
        std::string f(file);
        size_t slash = f.find_last_of("/\\");
        std::string base = slash == std::string::npos ? f : f.substr(slash + 1);
        if (!strip_ext.empty() && base.size() > strip_ext.size() &&
            base.compare(base.size() - strip_ext.size(), strip_ext.size(), strip_ext) == 0) {
            base = base.substr(0, base.size() - strip_ext.size());
        }
        names.push_back(base);
        return 0;
    }
};

std::vector<std::string> list_db_versions() {
    name_collector_t coll;
    coll.strip_ext = ".json";
    char answer[1024];
    std::string dir = data_dir() + "/type_db";
    enumerate_files(answer, sizeof(answer), dir.c_str(), "*.json", coll);
    return coll.names;
}

int apply_all_flirt() {
    int planned = 0;
    qstring proc = inf_get_procname();
    std::string subdir = (proc == "metapc" || proc.empty()) ? "pc" : std::string(proc.c_str());
    std::string sigdir = std::string(idadir(SIG_SUBDIR)) + "/" + subdir;
    const char* sets[] = {"flirt_sigs", "flirt_sigs_no_inline"};
    const char* opts[] = {"3", "2", "1", "0"};
    for (const auto& ver : list_db_versions()) {
        for (const char* set : sets) {
            for (const char* opt : opts) {
                std::string src = data_dir() + "/" + set + "/" + ver + "-O" + opt + ".sig";
                if (!file_readable(src)) continue;
                std::string sig_name = std::string("oxi_") + set + "_" + ver + "_O" + opt + ".sig";
                std::string dst = sigdir + "/" + sig_name;
                if (!file_readable(dst) && !copy_file(src, dst)) continue;  // stage once, then reuse
                if (plan_to_apply_idasgn(sig_name.c_str()) != 0) ++planned;
            }
        }
    }
    return planned;
}

std::set<std::string> collect_recovered_names() {
    std::set<std::string> out;
    size_t n = get_func_qty();
    for (size_t i = 0; i < n; ++i) {
        func_t* f = getn_func(i);
        if (f == nullptr) continue;
        qstring nm;
        if (get_func_name(&nm, f->start_ea) <= 0) continue;
        out.insert(oxi::demangle(nm.c_str()));
    }
    return out;
}

std::optional<std::string> pin_version_by_overlap() {
    std::set<std::string> recovered = collect_recovered_names();
    std::vector<std::string> versions = list_db_versions();
    auto names_for = [&](const std::string& v) -> std::vector<std::string> {
        std::string p = type_db_path(v);
        if (!file_readable(p)) return {};
        try {
            return oxi::TypeDB::load_function_names(p);
        } catch (...) {
            return {};
        }
    };
    auto [ver, overlap] = oxi::pick_version_by_overlap(recovered, versions, names_for);
    if (ver.has_value() && overlap > 0) {
        msg("[oxidizer] pinned rustc version by name overlap: %s (%d std matches)\n", ver->c_str(), overlap);
    }
    return ver;
}

// ---------------------------------------------------------------------------
// orchestration
// ---------------------------------------------------------------------------

// The recovery pass proper: demangle/rename, no-return marking, and type+prototype
// application.  Assumes any FLIRT signatures have already been *applied* so the
// recovered std/core/alloc names are present and can be matched against the type
// database.
void run_recovery(const std::optional<std::string>& version, bool interactive, int flirt_count) {
    RenameStats rs = rename_functions(interactive);
    msg("[oxidizer] renamed %d function(s); marked %d no-return\n", rs.renamed, rs.noret);

    TypeStats ts;
    if (version.has_value()) {
        ts = apply_type_db(*version, rs);
        if (ts.loaded) {
            msg("[oxidizer] types: declared %zu std type(s); applied %d prototype(s)\n",
                ts.types_declared, ts.prototypes_applied);
        }
    }

#ifdef OXIDIZER_WITH_HEXRAYS
    oxidizer::install_idiom_hooks();
#endif

    msg("[oxidizer] done: version=%s flirt=%d renamed=%d noret=%d types=%zu protos=%d\n",
        version.has_value() ? version->c_str() : "(unknown)", flirt_count, rs.renamed, rs.noret,
        ts.types_declared, ts.prototypes_applied);

    if (interactive) {
        info("Oxidizer Rust recovery complete:\n\n"
             "  rustc version : %s\n"
             "  FLIRT files   : %d\n"
             "  renamed funcs : %d\n"
             "  no-return     : %d\n"
             "  std types     : %zu\n"
             "  prototypes    : %d\n",
             version.has_value() ? version->c_str() : "(unknown)",
             flirt_count, rs.renamed, rs.noret, ts.types_declared, ts.prototypes_applied);
    }
}

// Interactive path: plan FLIRT, force it to apply, then recover -- all in one go.
void run_pipeline_interactive() {
    std::optional<std::string> version = detect_version();
    int flirt = version.has_value() ? apply_flirt(*version) : apply_all_flirt();
    if (flirt > 0) auto_wait();  // force planned sigs to apply before recovery
    if (!version.has_value()) version = pin_version_by_overlap();  // robust fallback
    run_recovery(version, /*interactive=*/true, flirt);
}

// ---------------------------------------------------------------------------
// plugin entry
//
// The plugin auto-runs after IDA finishes auto-analysis (the idb_event
// auto_empty_finally hook) so it works in headless / idalib tools such as
// `idump` as well as interactively (menu / Ctrl-Alt-R).
// ---------------------------------------------------------------------------

// The context object is both the plugmod (per-database instance, created by IDA
// at database open for PLUGIN_MULTI plugins) and the event listener.  It hooks
// the analysis-complete event so the pipeline runs automatically, which is what
// lets headless tools like `idump` benefit without an interactive invocation.
struct oxidizer_ctx_t : public plugmod_t, public event_listener_t {
    // Two-phase headless flow (so FLIRT-recovered names exist before type/prototype
    // matching, which the single-pass approach could not guarantee):
    //   * auto_empty          -> detect version + PLAN FLIRT signatures
    //   * (IDA applies the planned sigs during continued analysis)
    //   * auto_empty_finally  -> run the recovery pass (names now present)
    bool flirt_planned = false;
    bool recovered = false;
    bool fallback = false;  // version unknown -> applied all-versions FLIRT, pin later
    int flirt_count = 0;
    std::optional<std::string> version;

    oxidizer_ctx_t() {
        // PLUGIN_FIX keeps us resident from IDA startup; HKCB_GLOBAL makes the
        // listener survive database open/close so events arrive for every database
        // (incl. headless idalib tools like idump).
        hook_event_listener(HT_IDB, this, HKCB_GLOBAL);
        msg("[oxidizer] plugin loaded (Rust recovery armed)\n");
    }

    void do_recover() {
        if (recovered) return;
        recovered = true;
        run_recovery(version, /*interactive=*/false, flirt_count);
    }

    ssize_t idaapi on_event(ssize_t code, va_list) override {
        if (code == idb_event::auto_empty) {
            if (!flirt_planned) {
                flirt_planned = true;
                version = detect_version();
                if (version.has_value()) {
                    flirt_count = apply_flirt(*version);  // plan only; IDA applies next pass
                    msg("[oxidizer] detected rustc %s; planned %d FLIRT file(s)\n",
                        version->c_str(), flirt_count);
                } else {
                    // Unknown version: apply ALL versions' FLIRT (only the matching
                    // one fires); the exact version is pinned later by name overlap.
                    fallback = true;
                    flirt_count = apply_all_flirt();
                    msg("[oxidizer] no rustc version string; planned %d FLIRT file(s) across all versions\n",
                        flirt_count);
                }
                // If there is no FLIRT to wait for, recover immediately.
                if (flirt_count == 0) do_recover();
            }
        } else if (code == idb_event::auto_empty_finally) {
            // Definitive end of analysis: FLIRT is applied, names are present.
            if (fallback && !version.has_value()) version = pin_version_by_overlap();
            do_recover();
        } else if (code == idb_event::closebase) {
            flirt_planned = recovered = fallback = false;
            flirt_count = 0;
            version.reset();
        }
        return 0;
    }

    bool idaapi run(size_t) override {
        recovered = true;  // manual invocation supersedes the auto path
        run_pipeline_interactive();
        return true;
    }
};

plugmod_t* idaapi oxidizer_init() {
    return new oxidizer_ctx_t;
}

}  // namespace

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_FIX | PLUGIN_MULTI,          // resident from startup; init() returns the plugmod
    oxidizer_init,                      // init -> plugmod_t*
    nullptr,                            // term  (must be nullptr for PLUGIN_MULTI)
    nullptr,                            // run   (must be nullptr for PLUGIN_MULTI)
    "Oxidizer: recover Rust names, types and idioms",  // comment
    "Oxidizer brings angr/Oxidizer Rust decompilation aids to IDA",  // help
    "Oxidizer (Rust)",                  // wanted name (menu)
    "Ctrl-Alt-R",                       // wanted hotkey
};
