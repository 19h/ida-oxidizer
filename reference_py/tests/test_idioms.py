"""Tests for Rust idiom recognition."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oxidizer_core import idioms  # noqa: E402


def test_panic_exact():
    assert idioms.classify("core::panicking::panic_fmt") == idioms.PANIC
    assert idioms.is_noreturn("core::panicking::panic_fmt")


def test_panic_from_mangled_legacy():
    # _ZN4core9panicking9panic_fmt17h...E  -> core::panicking::panic_fmt
    sym = "_ZN4core9panicking9panic_fmt17h05af221ea0b56f8aE"
    assert idioms.classify(sym) == idioms.PANIC
    assert idioms.is_noreturn(sym)


def test_bounds_check_noreturn():
    assert idioms.classify("core::panicking::panic_bounds_check") == idioms.BOUNDS
    assert idioms.is_noreturn("core::panicking::panic_bounds_check")


def test_unwrap_failed_is_panic():
    assert idioms.is_noreturn("core::result::unwrap_failed")
    assert idioms.is_noreturn("core::option::expect_failed")


def test_drop_in_place_substring():
    assert idioms.classify("core::ptr::drop_in_place<alloc::string::String>") == idioms.DROP
    assert not idioms.is_noreturn("core::ptr::drop_in_place<alloc::string::String>")


def test_alloc_dealloc():
    assert idioms.classify("alloc::alloc::exchange_malloc") == idioms.ALLOC
    assert idioms.classify("alloc::alloc::box_free") == idioms.DEALLOC


def test_format_machinery():
    assert idioms.classify("core::fmt::Arguments::new_v1") == idioms.FORMAT
    assert idioms.classify("core::fmt::Formatter::pad") == idioms.FORMAT


def test_clone():
    assert idioms.classify("<alloc::string::String as core::clone::Clone>::clone") in (idioms.CLONE, idioms.FORMAT)


def test_unrecognized_returns_none():
    assert idioms.classify("main") is None
    assert idioms.classify("my_app::do_business_logic") is None
    assert not idioms.is_noreturn("main")


def test_comment_for():
    c = idioms.comment_for("core::panicking::panic_fmt")
    assert c and "panic" in c.lower()
    assert idioms.comment_for("main") is None


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
