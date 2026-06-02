// rustc version identification (IDA-independent core).  Two strategies:
//   1. string-based: embedded "/rustc/<40-hex>/" commit path or "rustc X.Y.Z".
//   2. FLIRT scoring: two-phase probe + fine-search over per-version sig files,
//      picking the version whose std/core/alloc sigs match the most functions.
// The FLIRT match itself is injected as a callback so this stays testable and the
// IDA glue can supply IDA's own engine.
#pragma once

#include <functional>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace oxi {

// Resolve a 40-hex rustc commit hash to a version by scanning the big
// commit_versions.py map textually (no full import).  nullopt if not found.
std::optional<std::string> lookup_commit_version(const std::string& commit_versions_path,
                                                 const std::string& commit_hash);

// Find a version string in the binary's strings.  `commit_lookup` resolves a
// 40-hex commit hash (inject a closure over lookup_commit_version).
std::optional<std::string> find_version_in_strings(
    const std::vector<std::string>& strings,
    const std::function<std::optional<std::string>(const std::string&)>& commit_lookup = {});

struct SigVersion {
    std::vector<int> version;  // e.g. {1, 75, 0}
    std::string opt_level;     // e.g. "3"
};

// Parse "1.87.0-O3.sig" -> {{1,87,0}, "3"}.
SigVersion parse_sig_filename(const std::string& filename);

// Two-phase FLIRT version search.  `sig_files` are signature *filenames*
// (deduplicated by basename); `count_fn` returns the best std/core/alloc match
// count for a given filename.  Returns {version_or_nullopt, matched_count}.
std::pair<std::optional<std::string>, int> identify_version_by_flirt(
    const std::vector<std::string>& sig_files,
    const std::function<int(const std::string&)>& count_fn,
    const std::string& probe_opt = "3");

// Pin the rustc version when no version string is available, by overlap: choose
// the candidate version whose type-DB function-name set shares the most names
// with the (FLIRT-recovered, demangled) function names actually present in the
// binary.  `names_for_version` returns a version's DB function names.  This is
// timing-independent (pure set intersection) so it works headless.  Returns the
// best version and its overlap count; version is nullopt if nothing overlaps.
std::pair<std::optional<std::string>, int> pick_version_by_overlap(
    const std::set<std::string>& recovered,
    const std::vector<std::string>& candidate_versions,
    const std::function<std::vector<std::string>(const std::string&)>& names_for_version);

}  // namespace oxi
