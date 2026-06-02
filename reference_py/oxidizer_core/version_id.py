"""rustc version identification (IDA-independent core).

Two independent strategies, mirroring Oxidizer:

1. *String based* (``angr/rust/analyses/type_db_loader.py::RustVersionIdentifier``)
   — look for an embedded ``/rustc/<40-hex-commit>/`` path or a ``rustc X.Y.Z``
   banner in the binary's strings.  The 40-hex commit is resolved through
   Oxidizer's 151k-entry ``commit_versions.py`` map; to avoid importing that
   8.8 MB module we scan it textually only when a hash is actually found.

2. *FLIRT scoring* (``angr/rust/analyses/rustc_version_identification.py``) — the
   two-phase probe + fine-search over the per-version signature files, selecting
   the version whose std/core/alloc signatures match the most functions.  The
   actual matching is injected as a callback so the algorithm is testable and the
   IDA glue can supply either IDA's own FLIRT engine or a standalone matcher.
"""

from __future__ import annotations

import os
import re
from typing import Callable, Iterable

# ---------------------------------------------------------------------------
# 1. string-based detection
# ---------------------------------------------------------------------------

_RUSTC_COMMIT_RE = re.compile(r"/rustc/([0-9a-f]{40})[/\\]")
_VERSION_RES = [
    re.compile(r"rustc\s+([0-9]+\.[0-9]+\.[0-9]+)"),
    re.compile(r"rust-([0-9]+\.[0-9]+\.[0-9]+)"),
]


def lookup_commit_version(commit_versions_path: str, commit_hash: str) -> str | None:
    """Resolve a 40-hex rustc commit hash to a version by scanning the big map
    file textually (no full import).  Returns ``None`` if not found."""
    if not commit_versions_path or not os.path.exists(commit_versions_path):
        return None
    needle = f"'{commit_hash}'"
    pat = re.compile(re.escape(commit_hash) + r"['\"]\s*:\s*['\"]([0-9]+\.[0-9]+\.[0-9]+)")
    try:
        with open(commit_versions_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if needle in line or commit_hash in line:
                    m = pat.search(line)
                    if m:
                        return m.group(1)
    except OSError:
        return None
    return None


def find_version_in_strings(
    strings: Iterable[str],
    commit_lookup: Callable[[str], str | None] | None = None,
) -> str | None:
    """Return a version string discovered in *strings*, or ``None``.

    *commit_lookup* maps a 40-hex commit hash to a version (inject a closure over
    :func:`lookup_commit_version` so the big map is only touched when needed).
    """
    strings = list(strings)
    for s in strings:
        m = _RUSTC_COMMIT_RE.search(s)
        if m:
            commit = m.group(1)
            if commit_lookup is not None:
                v = commit_lookup(commit)
                if v:
                    return v
            # A commit was found but unresolved — stop here, like Oxidizer does.
            return None
    for pat in _VERSION_RES:
        for s in strings:
            m = pat.search(s)
            if m:
                return m.group(1)
    return None


# ---------------------------------------------------------------------------
# 2. FLIRT-scoring detection (ported two-phase search)
# ---------------------------------------------------------------------------

OPT_LEVELS = ["0", "1", "2", "3"]


def parse_sig_filename(filename: str) -> tuple[tuple[int, ...], str]:
    """Parse ``'1.87.0-O3.sig'`` -> ((1, 87, 0), '3'). Mirrors ``_parse_version``."""
    name = os.path.basename(filename).replace(".sig", "")
    parts = name.rsplit("-O", 1)
    version = parts[0]
    opt_level = parts[1] if len(parts) > 1 else ""
    v_parts = version.split(".")
    return tuple(int(x) for x in v_parts), opt_level


def identify_version_by_flirt(
    sig_files: Iterable[str],
    count_fn: Callable[[str], int],
    probe_opt: str = "3",
) -> tuple[str | None, int]:
    """Two-phase FLIRT version search.

    * *sig_files* — available signature **filenames** (e.g. ``1.75.0-O3.sig``),
      possibly spanning multiple directories (deduplicate by basename first).
    * *count_fn* — returns the best std/core/alloc match count for a given sig
      filename (the IDA glue or a test supplies this).

    Returns ``(version_string_or_None, matched_count)``.  Ported from
    ``RustcVersionIdentification._identify_rustc_version``.
    """
    sig_files = list({os.path.basename(f) for f in sig_files})
    if not sig_files:
        return None, 0

    sigs_by_opt: dict[str, list[str]] = {opt: [] for opt in OPT_LEVELS}
    for f in sig_files:
        _, opt = parse_sig_filename(f)
        if opt in sigs_by_opt:
            sigs_by_opt[opt].append(f)
    for opt in OPT_LEVELS:
        sigs_by_opt[opt].sort(key=lambda x: parse_sig_filename(x)[0], reverse=True)

    probe_sigs = sigs_by_opt.get(probe_opt) or next((v for v in sigs_by_opt.values() if v), [])
    if not probe_sigs:
        return None, 0

    cache: dict[str, int] = {}

    def cached(sig: str) -> int:
        if sig not in cache:
            cache[sig] = count_fn(sig)
        return cache[sig]

    # Phase 1: coarse probe across up to 10 evenly-spaced versions
    n_samples = min(10, len(probe_sigs))
    step = max(1, len(probe_sigs) // n_samples)
    sample_indices = list(range(0, len(probe_sigs), step))[:n_samples]
    version_scores = [(idx, cached(probe_sigs[idx])) for idx in sample_indices]
    best_probe_idx = max(version_scores, key=lambda x: x[1])[0]

    # Phase 2: fine search around the best probe
    left = max(0, best_probe_idx - step)
    right = min(len(probe_sigs) - 1, best_probe_idx + step)
    best_idx = best_probe_idx
    best_count = cached(probe_sigs[best_probe_idx])
    for i in range(left, right + 1):
        c = cached(probe_sigs[i])
        if c > best_count:
            best_count = c
            best_idx = i

    best_version, _ = parse_sig_filename(probe_sigs[best_idx])
    return ".".join(str(x) for x in best_version), best_count
