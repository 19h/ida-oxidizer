#include "version_id.h"

#include <algorithm>
#include <fstream>
#include <map>
#include <regex>
#include <set>

namespace oxi {
namespace {

const std::regex kCommitRe(R"(/rustc/([0-9a-f]{40})[/\\])");
const std::regex kRustcRe(R"(rustc\s+([0-9]+\.[0-9]+\.[0-9]+))");
const std::regex kRustDashRe(R"(rust-([0-9]+\.[0-9]+\.[0-9]+))");

std::string basename_of(const std::string& path) {
    size_t slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

}  // namespace

std::optional<std::string> lookup_commit_version(const std::string& commit_versions_path,
                                                 const std::string& commit_hash) {
    if (commit_versions_path.empty()) return std::nullopt;
    std::ifstream f(commit_versions_path);
    if (!f) return std::nullopt;
    // Match either '<hash>': '<ver>' or "<hash>": "<ver>".
    std::regex pat(commit_hash + R"(['"]\s*:\s*['"]([0-9]+\.[0-9]+\.[0-9]+))");
    std::string line;
    while (std::getline(f, line)) {
        if (line.find(commit_hash) == std::string::npos) continue;
        std::smatch m;
        if (std::regex_search(line, m, pat)) {
            return m[1].str();
        }
    }
    return std::nullopt;
}

std::optional<std::string> find_version_in_strings(
    const std::vector<std::string>& strings,
    const std::function<std::optional<std::string>(const std::string&)>& commit_lookup) {
    for (const auto& s : strings) {
        std::smatch m;
        if (std::regex_search(s, m, kCommitRe)) {
            std::string commit = m[1].str();
            if (commit_lookup) {
                auto v = commit_lookup(commit);
                if (v.has_value()) return v;
            }
            // A commit was found but unresolved -- stop here, like Oxidizer does.
            return std::nullopt;
        }
    }
    for (const auto& re : {kRustcRe, kRustDashRe}) {
        for (const auto& s : strings) {
            std::smatch m;
            if (std::regex_search(s, m, re)) {
                return m[1].str();
            }
        }
    }
    return std::nullopt;
}

SigVersion parse_sig_filename(const std::string& filename) {
    std::string name = basename_of(filename);
    const std::string suffix = ".sig";
    if (name.size() >= suffix.size() && name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0) {
        name = name.substr(0, name.size() - suffix.size());
    }
    std::string version = name;
    std::string opt;
    size_t pos = name.rfind("-O");
    if (pos != std::string::npos) {
        version = name.substr(0, pos);
        opt = name.substr(pos + 2);
    }
    SigVersion sv;
    sv.opt_level = opt;
    size_t start = 0;
    while (start <= version.size()) {
        size_t dot = version.find('.', start);
        std::string part = version.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
        if (!part.empty()) {
            try {
                sv.version.push_back(std::stoi(part));
            } catch (...) {
                sv.version.push_back(0);
            }
        }
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    return sv;
}

std::pair<std::optional<std::string>, int> identify_version_by_flirt(
    const std::vector<std::string>& sig_files,
    const std::function<int(const std::string&)>& count_fn,
    const std::string& probe_opt) {
    // Deduplicate by basename.
    std::set<std::string> unique;
    for (const auto& f : sig_files) unique.insert(basename_of(f));
    if (unique.empty()) return {std::nullopt, 0};

    std::map<std::string, std::vector<std::string>> sigs_by_opt;
    for (const char* opt : {"0", "1", "2", "3"}) sigs_by_opt[opt] = {};
    for (const auto& f : unique) {
        SigVersion sv = parse_sig_filename(f);
        auto it = sigs_by_opt.find(sv.opt_level);
        if (it != sigs_by_opt.end()) it->second.push_back(f);
    }
    auto cmp_desc = [](const std::string& a, const std::string& b) {
        return parse_sig_filename(a).version > parse_sig_filename(b).version;  // newest first
    };
    for (auto& [opt, vec] : sigs_by_opt) std::sort(vec.begin(), vec.end(), cmp_desc);

    std::vector<std::string>* probe_sigs = nullptr;
    auto pit = sigs_by_opt.find(probe_opt);
    if (pit != sigs_by_opt.end() && !pit->second.empty()) {
        probe_sigs = &pit->second;
    } else {
        for (auto& [opt, vec] : sigs_by_opt) {
            if (!vec.empty()) { probe_sigs = &vec; break; }
        }
    }
    if (!probe_sigs || probe_sigs->empty()) return {std::nullopt, 0};
    const std::vector<std::string>& ps = *probe_sigs;

    std::map<std::string, int> cache;
    auto cached = [&](const std::string& sig) -> int {
        auto it = cache.find(sig);
        if (it != cache.end()) return it->second;
        int v = count_fn(sig);
        cache[sig] = v;
        return v;
    };

    // Phase 1: coarse probe across up to 10 evenly-spaced versions.
    size_t n = ps.size();
    size_t n_samples = std::min<size_t>(10, n);
    size_t step = std::max<size_t>(1, n / n_samples);
    std::vector<size_t> sample_indices;
    for (size_t idx = 0; idx < n && sample_indices.size() < n_samples; idx += step) {
        sample_indices.push_back(idx);
    }
    size_t best_probe_idx = sample_indices.empty() ? 0 : sample_indices[0];
    int best_probe_score = -1;
    for (size_t idx : sample_indices) {
        int c = cached(ps[idx]);
        if (c > best_probe_score) {
            best_probe_score = c;
            best_probe_idx = idx;
        }
    }

    // Phase 2: fine search around the best probe.
    size_t left = best_probe_idx >= step ? best_probe_idx - step : 0;
    size_t right = std::min(n - 1, best_probe_idx + step);
    size_t best_idx = best_probe_idx;
    int best_count = cached(ps[best_probe_idx]);
    for (size_t i = left; i <= right; ++i) {
        int c = cached(ps[i]);
        if (c > best_count) {
            best_count = c;
            best_idx = i;
        }
    }

    SigVersion best = parse_sig_filename(ps[best_idx]);
    std::string vstr;
    for (size_t i = 0; i < best.version.size(); ++i) {
        if (i) vstr += ".";
        vstr += std::to_string(best.version[i]);
    }
    return {vstr, best_count};
}

}  // namespace oxi
