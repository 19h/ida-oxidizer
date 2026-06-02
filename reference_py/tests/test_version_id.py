"""Tests for rustc version identification (core)."""

from __future__ import annotations

import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from oxidizer_core.version_id import (  # noqa: E402
    find_version_in_strings,
    identify_version_by_flirt,
    lookup_commit_version,
    parse_sig_filename,
)

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
SIG_DIR = os.path.join(REPO, "angr", "rust", "analyses", "flirt_sigs")
COMMIT_VERSIONS = os.path.join(REPO, "angr", "rust", "definitions", "commit_versions.py")


# -- string detection -------------------------------------------------------


def test_string_rustc_banner():
    strings = ["garbage", "compiled by rustc 1.72.1 (deadbeef)", "more"]
    assert find_version_in_strings(strings) == "1.72.1"


def test_string_rust_dash():
    assert find_version_in_strings(["/home/user/rust-1.65.0/library/std"]) == "1.65.0"


def test_string_commit_hash_with_lookup():
    h = "a" * 40
    strings = [f"/rustc/{h}/library/core/src/panic.rs"]
    out = find_version_in_strings(strings, commit_lookup=lambda c: "1.70.0" if c == h else None)
    assert out == "1.70.0"


def test_string_commit_hash_unresolved_stops():
    h = "b" * 40
    strings = [f"/rustc/{h}/library/core/src/panic.rs", "rustc 1.50.0"]
    # Per Oxidizer: a found-but-unresolved commit short-circuits to None.
    assert find_version_in_strings(strings, commit_lookup=lambda c: None) is None


def test_string_none():
    assert find_version_in_strings(["nothing", "useful", "here"]) is None


# -- real commit map --------------------------------------------------------


@pytest.mark.skipif(not os.path.exists(COMMIT_VERSIONS), reason="commit_versions.py not present")
def test_real_commit_lookup():
    # Pull a real (hash, version) pair straight from the map file, then resolve it.
    import re

    pair = None
    with open(COMMIT_VERSIONS, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = re.search(r"['\"]([0-9a-f]{40})['\"]\s*:\s*['\"]([0-9.]+)['\"]", line)
            if m:
                pair = (m.group(1), m.group(2))
                break
    assert pair is not None
    h, ver = pair
    assert lookup_commit_version(COMMIT_VERSIONS, h) == ver


@pytest.mark.skipif(not os.path.exists(COMMIT_VERSIONS), reason="commit_versions.py not present")
def test_real_commit_lookup_miss():
    assert lookup_commit_version(COMMIT_VERSIONS, "f" * 40) is None


# -- filename parsing -------------------------------------------------------


def test_parse_sig_filename():
    assert parse_sig_filename("1.87.0-O3.sig") == ((1, 87, 0), "3")
    assert parse_sig_filename("/x/y/1.39.0-O0.sig") == ((1, 39, 0), "0")


# -- FLIRT scoring algorithm ------------------------------------------------


def test_flirt_scoring_peaks_at_target():
    # Simulate sig files for versions 1.40 .. 1.90 at O3 and a binary that was
    # built with 1.70.0: the score peaks there and falls off with distance.
    target = (1, 70, 0)
    sigs = [f"1.{minor}.0-O3.sig" for minor in range(40, 91)]

    def count_fn(sig: str) -> int:
        v, _ = parse_sig_filename(sig)
        return max(0, 1000 - abs(v[1] - target[1]) * 50)

    version, count = identify_version_by_flirt(sigs, count_fn)
    assert version == "1.70.0"
    assert count == 1000


def test_flirt_scoring_dedup_across_dirs():
    sigs = ["1.50.0-O3.sig", "1.50.0-O3.sig", "1.60.0-O3.sig"]

    def count_fn(sig: str) -> int:
        return 5 if sig.startswith("1.60") else 1

    version, _ = identify_version_by_flirt(sigs, count_fn)
    assert version == "1.60.0"


def test_flirt_scoring_empty():
    assert identify_version_by_flirt([], lambda s: 0) == (None, 0)


@pytest.mark.skipif(not os.path.isdir(SIG_DIR), reason="flirt_sigs not present")
def test_flirt_scoring_with_real_filenames():
    # Use the real on-disk sig filenames; mock the match counts to peak at 1.75.0.
    sigs = [os.path.basename(p) for p in glob.glob(os.path.join(SIG_DIR, "*.sig"))]
    assert len(sigs) > 100

    def count_fn(sig: str) -> int:
        v, _ = parse_sig_filename(sig)
        return max(0, 500 - abs(v[1] - 75) * 10)

    version, _ = identify_version_by_flirt(sigs, count_fn)
    # The fine-search may land within a step of the true peak depending on
    # sampling; assert it is at least in the right neighbourhood.
    major, minor, _ = (int(x) for x in version.split("."))
    assert major == 1 and 70 <= minor <= 80


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
