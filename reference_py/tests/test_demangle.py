"""Tests for the self-contained Rust demangler.

Run with:  pytest oxidizer_ida/tests/test_demangle.py
These tests import only ``oxidizer_core`` (no IDA dependency).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oxidizer_core.demangle import demangle, normalize  # noqa: E402


# ---------------------------------------------------------------------------
# legacy (_ZN ... E)
# ---------------------------------------------------------------------------


def test_legacy_basic_drops_hash():
    sym = "_ZN4core3fmt9Formatter3pad17h05af221ea0b56f8aE"
    assert demangle(sym) == "core::fmt::Formatter::pad"


def test_legacy_without_leading_underscore():
    sym = "ZN3std2rt10lang_start17h0123456789abcdefE"
    assert demangle(sym) == "std::rt::lang_start"


def test_legacy_escapes_generics():
    # <alloc::vec::Vec<T>>::push  — the impl element is "_$LT$...$GT$$GT$" (33 chars),
    # leading "_" is an escape and is dropped.
    sym = "_ZN33_$LT$alloc..vec..Vec$LT$T$GT$$GT$4push17habcdef0123456789E"
    out = demangle(sym)
    assert out == "<alloc::vec::Vec<T>>::push"


def test_legacy_keeps_non_hash_tail():
    # last component is not a 17-char hash, so it must be kept
    sym = "_ZN3foo3barE"
    assert demangle(sym) == "foo::bar"


def test_legacy_unicode_escape():
    # component "baz$u20$qux" is 11 chars
    sym = "_ZN3foo11baz$u20$qux17h05af221ea0b56f8aE"
    assert demangle(sym) == "foo::baz qux"


# ---------------------------------------------------------------------------
# v0 (_R ...)
# ---------------------------------------------------------------------------


def test_v0_nested_path():
    # mycrate::foo::bar  with a crate disambiguator
    sym = "_RNvNtCs1234_7mycrate3foo3bar"
    assert demangle(sym) == "mycrate::foo::bar"


def test_v0_crate_root_only():
    sym = "_RC7mycrate"  # bare crate root (no disambiguator)
    assert demangle(sym) == "mycrate"


def test_v0_generic_args():
    # Vec::<u8>::new  ->  std::vec::Vec::<u8>::new style rendering
    sym = "_RINvNtCs1_5alloc3vec3VechE"
    out = demangle(sym)
    assert out.startswith("alloc::vec::Vec")
    assert "<u8>" in out


def test_v0_reference_type_in_generics():
    sym = "_RINvNtCs1_4core3mem4swapRlE"  # core::mem::swap::<&i32>
    out = demangle(sym)
    assert "core::mem::swap" in out
    assert "&i32" in out


# ---------------------------------------------------------------------------
# normalize() — generic / trait stripping
# ---------------------------------------------------------------------------


def test_normalize_strips_generics():
    assert normalize("alloc::vec::Vec<u8>::push") == "alloc::vec::Vec::push"


def test_normalize_strips_as_trait_keeps_type():
    assert normalize("<alloc::vec::Vec<u8> as core::ops::Drop>::drop") == "alloc::vec::Vec::drop"


def test_normalize_as_trait_use_trait_name():
    assert (
        normalize("<alloc::vec::Vec<u8> as core::ops::Drop>::drop", use_trait_name=True)
        == "core::ops::Drop::drop"
    )


def test_normalize_impl_block_uses_trait():
    # IMPL_XXX_AS_YYY_PATTERN: "<impl X as Y>" collapses to Y (the trait)
    assert normalize("<impl Foo as core::fmt::Display>::fmt") == "core::fmt::Display::fmt"


def test_normalize_concise():
    assert normalize("core::fmt::Formatter::pad", concise=True) == "pad"


def test_normalize_idempotent_on_plain():
    assert normalize("core::ptr::drop_in_place") == "core::ptr::drop_in_place"


# ---------------------------------------------------------------------------
# robustness
# ---------------------------------------------------------------------------


def test_non_rust_returns_input():
    assert demangle("main") == "main"
    assert demangle("_GLOBAL_OFFSET_TABLE_") == "_GLOBAL_OFFSET_TABLE_"


def test_garbage_v0_falls_back():
    # malformed v0 must not raise; falls back to the raw symbol
    assert demangle("_R!!!broken") == "_R!!!broken"


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
