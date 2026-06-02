"""Tests for the type-database parser, run against real Oxidizer JSON files."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from oxidizer_core.typedb import (  # noqa: E402
    RustEnum,
    RustFnProto,
    RustPointer,
    RustSlice,
    RustStrRef,
    RustStruct,
    TypeDB,
)

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
TYPE_DB_DIR = os.path.join(REPO, "angr", "rust", "analyses", "type_db")


def _db_path(ver: str) -> str:
    return os.path.join(TYPE_DB_DIR, f"{ver}.json")


@pytest.mark.skipif(not os.path.isdir(TYPE_DB_DIR), reason="type_db assets not present")
def test_parses_real_db_without_error():
    db = TypeDB.from_file(_db_path("1.75.0"))
    # The 1.75.0 DB has thousands of structs and functions; a healthy parse
    # should recover a large fraction of them.
    assert len(db.types) > 2000
    assert len(db.prototypes) > 2000


@pytest.mark.skipif(not os.path.isdir(TYPE_DB_DIR), reason="type_db assets not present")
def test_slice_and_str_patches_applied():
    db = TypeDB.from_file(_db_path("1.75.0"))
    # &str and &[T] structs in the DB must be folded into dedicated IR nodes.
    saw_strref = any(isinstance(t, RustStrRef) for t in db.types.values())
    saw_slice = any(isinstance(t, RustSlice) for t in db.types.values())
    assert saw_strref, "expected &str to be recognized as RustStrRef"
    assert saw_slice, "expected &[T] to be recognized as RustSlice"


@pytest.mark.skipif(not os.path.isdir(TYPE_DB_DIR), reason="type_db assets not present")
def test_option_and_result_detected():
    db = TypeDB.from_file(_db_path("1.75.0"))
    options = [t for t in db.types.values() if isinstance(t, RustEnum) and t.is_option]
    results = [t for t in db.types.values() if isinstance(t, RustEnum) and t.is_result]
    assert options, "expected at least one Option enum"
    assert results, "expected at least one Result enum"


@pytest.mark.skipif(not os.path.isdir(TYPE_DB_DIR), reason="type_db assets not present")
def test_abi_fit_large_struct_returns_via_retbuf():
    # core::num::flt2dec::round_up returns Option<u8> (small) — no retbuf.
    db = TypeDB.from_file(_db_path("1.75.0"))
    # Find some function whose return aggregate is large and confirm retbuf rule.
    big_retbuf = [p for protos in db.prototypes.values() for p in protos if p.is_retbuf]
    # The DB is large; at least some functions must trip the by-ref-return rule.
    assert big_retbuf, "expected some functions to use a return buffer"
    for p in big_retbuf:
        assert isinstance(p.args[0], RustPointer)
        assert p.ret is None


@pytest.mark.skipif(not os.path.isdir(TYPE_DB_DIR), reason="type_db assets not present")
def test_struct_fields_have_offsets():
    db = TypeDB.from_file(_db_path("1.75.0"))
    structs = [t for t in db.types.values() if isinstance(t, RustStruct) and len(t.fields) >= 2]
    assert structs
    s = structs[0]
    offsets = [f.offset for f in s.fields]
    assert offsets == sorted(offsets) or len(set(offsets)) == len(offsets)


@pytest.mark.skipif(not os.path.isdir(TYPE_DB_DIR), reason="type_db assets not present")
def test_multiple_versions_parse():
    # smoke-test across the version range to catch schema drift
    for ver in ("1.39.0", "1.59.0", "1.75.0"):
        p = _db_path(ver)
        if not os.path.exists(p):
            continue
        db = TypeDB.from_file(p)
        assert db.types, f"{ver} produced no types"
        assert db.prototypes, f"{ver} produced no prototypes"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
