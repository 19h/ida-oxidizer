"""Rust idiom recognition recipes (IDA-independent).

Oxidizer's outliner/macro passes are welded to angr's AIL and cannot be ported,
but the *domain knowledge* they encode — which std symbols mean "panic", "alloc",
"drop", "format machinery", etc. — is platform-neutral.  This module distils that
knowledge into a small classifier the IDA glue uses to:

* mark panic/abort helpers ``noreturn`` (the single highest-value, fully portable
  improvement: it deletes the dead code Hex-Rays otherwise emits after every
  ``unwrap``/bounds-check),
* tag and comment recognised std calls so the pseudocode reads as Rust,
* drive renaming of compiler-generated helpers.

Names are matched after :func:`oxidizer_core.demangle.normalize`, so both raw
mangled symbols and already-demangled names work.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .demangle import normalize

# Idiom category keys
PANIC = "panic"
BOUNDS = "bounds"
ALLOC = "alloc"
DEALLOC = "dealloc"
DROP = "drop"
FORMAT = "format"
CLONE = "clone"
ITER = "iter"
ASSERT = "assert"
ABORT = "abort"


@dataclass
class Category:
    key: str
    label: str
    comment: str
    exact: set[str] = field(default_factory=set)
    substrings: tuple[str, ...] = ()
    noreturn: bool = False


# ---------------------------------------------------------------------------
# Recipe table
# ---------------------------------------------------------------------------

_PANIC_EXACT = {
    "core::panicking::panic",
    "core::panicking::panic_fmt",
    "core::panicking::panic_nounwind",
    "core::panicking::panic_nounwind_fmt",
    "core::panicking::panic_explicit",
    "core::panicking::panic_cannot_unwind",
    "core::panicking::panic_in_cleanup",
    "core::panicking::panic_misaligned_pointer_dereference",
    "core::option::expect_failed",
    "core::option::unwrap_failed",
    "core::result::unwrap_failed",
    "std::panicking::begin_panic",
    "std::panicking::begin_panic_handler",
    "std::panicking::begin_panic_fmt",
    "std::panicking::rust_panic",
    "std::panicking::rust_panic_with_hook",
    "rust_begin_unwind",
    "rust_panic",
}

_BOUNDS_EXACT = {
    "core::panicking::panic_bounds_check",
    "core::slice::index::slice_index_order_fail",
    "core::slice::index::slice_end_index_len_fail",
    "core::slice::index::slice_start_index_len_fail",
    "core::str::slice_error_fail",
    "alloc::raw_vec::capacity_overflow",
    "alloc::raw_vec::handle_error",
}

_ASSERT_EXACT = {
    "core::panicking::assert_failed",
    "core::panicking::assert_failed_inner",
    "core::panicking::assert_matches_failed",
}

_ABORT_EXACT = {
    "core::intrinsics::abort",
    "std::process::abort",
    "std::sys::abort_internal",
    "abort",
    "core::panicking::panic_no_unwind",
    "alloc::alloc::handle_alloc_error",
    "handle_alloc_error",
    "__rust_alloc_error_handler",
    "rust_oom",
}

_ALLOC_EXACT = {
    "alloc::alloc::alloc",
    "alloc::alloc::alloc_zeroed",
    "alloc::alloc::exchange_malloc",
    "alloc::alloc::__rust_alloc",
    "__rust_alloc",
    "__rust_alloc_zeroed",
    "__rust_realloc",
    "alloc::alloc::realloc",
}

_DEALLOC_EXACT = {
    "alloc::alloc::dealloc",
    "alloc::alloc::box_free",
    "__rust_dealloc",
}

_DROP_SUBSTR = ("::drop_in_place", "::real_drop_in_place")
_FORMAT_EXACT = {
    "core::fmt::Arguments::new_v1",
    "core::fmt::Arguments::new_v1_formatted",
    "core::fmt::Arguments::new_const",
    "core::fmt::write",
    "core::fmt::Write::write_fmt",
    "std::io::Write::write_fmt",
}
_FORMAT_SUBSTR = ("core::fmt::",)

CATEGORIES: dict[str, Category] = {
    PANIC: Category(
        PANIC, "panic!()", "Rust panic — unconditional unwind/abort", exact=_PANIC_EXACT, noreturn=True
    ),
    BOUNDS: Category(
        BOUNDS, "bounds-check panic", "panic: index out of bounds / slice error", exact=_BOUNDS_EXACT, noreturn=True
    ),
    ASSERT: Category(ASSERT, "assert!()", "Rust assertion failure", exact=_ASSERT_EXACT, noreturn=True),
    ABORT: Category(ABORT, "abort()", "process abort / alloc-error handler", exact=_ABORT_EXACT, noreturn=True),
    ALLOC: Category(ALLOC, "alloc", "heap allocation", exact=_ALLOC_EXACT),
    DEALLOC: Category(DEALLOC, "dealloc", "heap deallocation", exact=_DEALLOC_EXACT),
    DROP: Category(DROP, "drop()", "Rust Drop::drop / drop_in_place", substrings=_DROP_SUBSTR),
    FORMAT: Category(FORMAT, "format!()", "Rust formatting machinery", exact=_FORMAT_EXACT, substrings=_FORMAT_SUBSTR),
    CLONE: Category(CLONE, "clone()", "Clone::clone", substrings=("::clone",)),
    ITER: Category(ITER, "iterator", "iterator adapter", substrings=("core::iter::",)),
}

# Order matters: more specific categories first.
_ORDER = [PANIC, BOUNDS, ASSERT, ABORT, ALLOC, DEALLOC, DROP, FORMAT, CLONE, ITER]


def classify(name: str, demangle_first: bool = True) -> str | None:
    """Return the idiom category key for *name*, or ``None``.

    *name* may be a raw mangled symbol or an already-demangled path.
    """
    norm = normalize(name) if demangle_first else name
    for key in _ORDER:
        cat = CATEGORIES[key]
        if norm in cat.exact:
            return key
    for key in _ORDER:
        cat = CATEGORIES[key]
        for sub in cat.substrings:
            if sub in norm:
                return key
    return None


def is_noreturn(name: str, demangle_first: bool = True) -> bool:
    """True if *name* is a panic/abort-class function that never returns."""
    key = classify(name, demangle_first=demangle_first)
    return bool(key and CATEGORIES[key].noreturn)


def describe(key: str) -> Category | None:
    return CATEGORIES.get(key)


def comment_for(name: str, demangle_first: bool = True) -> str | None:
    """A short, human-facing comment for a recognised idiom call, else ``None``."""
    key = classify(name, demangle_first=demangle_first)
    if key is None:
        return None
    cat = CATEGORIES[key]
    return f"[oxidizer] {cat.label}: {cat.comment}"
