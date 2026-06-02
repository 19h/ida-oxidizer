"""Oxidizer-for-IDA core logic.

This package is deliberately free of any ``idaapi``/``ida_*`` imports so that the
hard, value-bearing algorithms (Rust demangling, rustc version identification,
type-database parsing, and idiom recognition) can be unit-tested without an IDA
installation.  The thin glue that actually talks to IDA/Hex-Rays lives in the
``oxidizer_core.ida_*`` modules and is imported lazily by the plugin entry point.
"""

from __future__ import annotations

__all__ = [
    "demangle",
    "normalize",
]

from .demangle import demangle, normalize
