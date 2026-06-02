"""Parser for Oxidizer's per-version Rust type database (``type_db/<ver>.json``).

This is an IDA-independent reimplementation of the parsing half of
``angr/rust/analyses/type_db_loader.py``.  It turns the JSON into a small typed
IR (the ``Rust*`` dataclasses below); the ``oxidizer_core.ida_types`` adapter
then lowers that IR onto Hex-Rays ``tinfo_t`` objects.

Differences from the angr version, all deliberate improvements for IDA output
(angr discarded these because its renderer could not use them):

* ``f32``/``f64`` map to real floats instead of being dropped (angr returned
  ``None``, which silently rejected every struct containing a float).
* ``char`` maps to a 4-byte value (Rust ``char`` is a Unicode scalar) instead of
  a single byte.

All sizes in the JSON — and therefore in this IR — are in **bytes**.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# IR
# ---------------------------------------------------------------------------


@dataclass
class RustType:
    size: int = 0

    def render(self) -> str:  # pragma: no cover - overridden
        return "?"


@dataclass
class RustInt(RustType):
    bits: int = 32
    signed: bool = False
    name: str = ""

    def render(self) -> str:
        if self.name:
            return self.name
        return f"{'i' if self.signed else 'u'}{self.bits}"


@dataclass
class RustFloat(RustType):
    bits: int = 64

    def render(self) -> str:
        return f"f{self.bits}"


@dataclass
class RustBool(RustType):
    def render(self) -> str:
        return "bool"


@dataclass
class RustChar(RustType):
    def render(self) -> str:
        return "char"


@dataclass
class RustPointer(RustType):
    pts_to: RustType | None = None

    def render(self) -> str:
        return f"*{self.pts_to.render() if self.pts_to else '()'}"


@dataclass
class RustArray(RustType):
    ele: RustType | None = None
    length: int = 0

    def render(self) -> str:
        return f"[{self.ele.render() if self.ele else '?'}; {self.length}]"


@dataclass
class RustSlice(RustType):
    ele: RustType | None = None

    def render(self) -> str:
        return f"&[{self.ele.render() if self.ele else '?'}]"


@dataclass
class RustStrRef(RustType):
    def render(self) -> str:
        return "&str"


@dataclass
class RustField:
    offset: int
    name: str
    ty: RustType


@dataclass
class RustStruct(RustType):
    name: str = ""
    fields: list[RustField] = field(default_factory=list)

    def render(self) -> str:
        return self.name or "struct"


@dataclass
class RustVariant:
    name: str
    discriminant: int | None
    discriminant_size: int
    fields: list[RustField] = field(default_factory=list)


@dataclass
class RustEnum(RustType):
    name: str = ""
    variants: list[RustVariant] = field(default_factory=list)
    discriminant_size: int = 0

    @property
    def is_option(self) -> bool:
        return self.name.startswith("core::option::Option") and {v.name for v in self.variants} == {"Some", "None"}

    @property
    def is_result(self) -> bool:
        return self.name.startswith("core::result::Result") and {v.name for v in self.variants} == {"Ok", "Err"}

    @property
    def is_niche_encoded(self) -> bool:
        """True when the enum has no room for a discriminant tag (the payload's
        invalid bit-patterns encode the other variant, e.g. ``Option<&T>``)."""
        payload = max((self._variant_size(v) for v in self.variants), default=0)
        return payload >= self.size > 0

    def _variant_size(self, v: RustVariant) -> int:
        return sum(f.ty.size for f in v.fields)

    def render(self) -> str:
        return self.name or "enum"


@dataclass
class RustBottom(RustType):
    """Placeholder for an in-progress (recursive) type."""

    def render(self) -> str:
        return "_"


@dataclass
class RustFnProto:
    args: list[RustType]
    ret: RustType | None
    is_retbuf: bool = False

    def render(self) -> str:
        a = ", ".join(t.render() for t in self.args)
        if self.is_retbuf:
            return f"fn({a})  /* arg0 = return buffer */"
        return f"fn({a}) -> {self.ret.render() if self.ret else '()'}"


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

_PRIMITIVES = {
    "i8": lambda: RustInt(1, 8, True, "i8"),
    "i16": lambda: RustInt(2, 16, True, "i16"),
    "i32": lambda: RustInt(4, 32, True, "i32"),
    "i64": lambda: RustInt(8, 64, True, "i64"),
    "i128": lambda: RustInt(16, 128, True, "i128"),
    "u8": lambda: RustInt(1, 8, False, "u8"),
    "u16": lambda: RustInt(2, 16, False, "u16"),
    "u32": lambda: RustInt(4, 32, False, "u32"),
    "u64": lambda: RustInt(8, 64, False, "u64"),
    "u128": lambda: RustInt(16, 128, False, "u128"),
    "f32": lambda: RustFloat(4, 32),
    "f64": lambda: RustFloat(8, 64),
    "bool": lambda: RustBool(1),
    "char": lambda: RustChar(4),
}


class TypeDB:
    """Loads and parses a single ``type_db/<version>.json`` file."""

    def __init__(self, arch_bits: int = 64):
        self.arch_bits = arch_bits
        self.arch_bytes = arch_bits // 8
        self.types: dict[str, RustType] = {}  # struct/enum name -> IR
        self.prototypes: dict[str, list[RustFnProto]] = {}
        self._struct_db: dict[str, dict] = {}
        self._pending: set[str] = set()
        self._resolving: set[str] = set()  # guards null-definition forwarding cycles

    # -- entry points ------------------------------------------------------
    @classmethod
    def from_file(cls, path: str | Path, arch_bits: int = 64) -> "TypeDB":
        return cls.from_json(json.loads(Path(path).read_text()), arch_bits)

    @classmethod
    def from_json(cls, data: dict, arch_bits: int = 64) -> "TypeDB":
        db = cls(arch_bits)
        db._load(data)
        return db

    def _load(self, data: dict) -> None:
        self._struct_db = {s["name"]: s for s in data.get("structs", [])}
        for sdata in self._struct_db.values():
            self._parse_type(sdata)
        for fdata in data.get("functions", []):
            proto = self._parse_prototype(fdata.get("prototype"))
            if proto is not None:
                self.prototypes.setdefault(fdata["name"], []).append(proto)

    # -- dispatch ----------------------------------------------------------
    def _parse_type(self, data) -> RustType | None:
        if not isinstance(data, dict):
            return None
        kind = data.get("kind")
        if kind == "Pointer":
            return self._parse_pointer(data)
        if kind == "Primitive":
            return self._parse_primitive(data)
        if kind == "Struct":
            return self._parse_struct(data)
        if kind == "Enumeration":
            return self._parse_enum(data)
        if kind == "Array":
            return self._parse_array(data)
        if kind == "None":
            return None
        return None

    def _parse_pointer(self, data) -> RustPointer:
        pts = self._parse_type(data["pts_to"]) if data.get("pts_to") else None
        return RustPointer(size=self.arch_bytes, pts_to=pts or RustBottom())

    def _parse_primitive(self, data) -> RustType | None:
        name = data.get("name", "")
        ctor = _PRIMITIVES.get(name)
        if ctor is not None:
            return ctor()
        size = data.get("size")
        if size:
            return RustInt(size=size, bits=size * 8, signed=False, name=name)
        return None

    def _parse_array(self, data) -> RustArray | None:
        ele = self._parse_type(data["ele_type"])
        if ele is None:
            return None
        length = data.get("length", 0)
        return RustArray(size=ele.size * length, ele=ele, length=length)

    def _parse_struct(self, data) -> RustType | None:
        name = data["name"]
        if name in self.types:
            return self.types[name]
        if name in self._pending:
            return RustBottom()
        fields_data = data.get("fields")
        if fields_data is None:
            if name in self._resolving:
                return None
            actual = self._struct_db.get(name)
            if not actual or actual is data:
                return None
            self._resolving.add(name)
            try:
                return self._parse_struct(actual)
            finally:
                self._resolving.discard(name)
        self._pending.add(name)
        fields: list[RustField] = []
        ok = True
        for off_key, (fname, fdata) in fields_data.items():
            fty = self._parse_type(fdata)
            if fty is None:
                ok = False
                break
            fields.append(RustField(int(off_key), fname, fty))
        self._pending.discard(name)
        if not ok:
            return None
        result: RustType = RustStruct(size=data.get("size", 0), name=name, fields=fields)
        result = self._apply_patches(result)
        self.types[name] = result
        return result

    def _parse_enum(self, data) -> RustType | None:
        name = data["name"]
        if name in self.types:
            return self.types[name]
        if name in self._pending:
            return RustBottom()
        variants_data = data.get("variants")
        if variants_data is None:
            if name in self._resolving:
                return None
            actual = self._struct_db.get(name)
            if not actual or actual is data:
                return None
            self._resolving.add(name)
            try:
                return self._parse_enum(actual)
            finally:
                self._resolving.discard(name)
        self._pending.add(name)
        disc_size = data.get("discriminant_size", 0)
        variants: list[RustVariant] = []
        ok = True
        for vname, (disc, vfields_data) in variants_data.items():
            vfields: list[RustField] = []
            for fname, fdata in vfields_data:
                fty = self._parse_type(fdata)
                if fty is None:
                    ok = False
                    break
                # variant field offsets are payload-relative; recompute on lowering
                vfields.append(RustField(0, fname, fty))
            if not ok:
                break
            variants.append(RustVariant(vname, disc, disc_size if disc is not None else 0, vfields))
        self._pending.discard(name)
        if not ok:
            return None
        result = RustEnum(size=data.get("size", 0), name=name, variants=variants, discriminant_size=disc_size)
        self.types[name] = result
        return result

    # -- patches (ported from type_db_loader) ------------------------------
    def _apply_patches(self, ty: RustStruct) -> RustType:
        ty2 = self._to_slice(ty)
        if isinstance(ty2, RustStruct):
            ty2 = self._unwrap_argument_type(ty2)
        return ty2

    def _to_slice(self, ty: RustStruct) -> RustType:
        names = {f.name for f in ty.fields}
        if names == {"data_ptr", "length"}:
            data_ptr = next(f.ty for f in ty.fields if f.name == "data_ptr")
            length = next(f.ty for f in ty.fields if f.name == "length")
            if isinstance(data_ptr, RustPointer) and isinstance(length, RustInt) and length.size == self.arch_bytes:
                if ty.name == "&str" and isinstance(data_ptr.pts_to, RustInt) and data_ptr.pts_to.bits == 8:
                    return RustStrRef(size=ty.size)
                return RustSlice(size=ty.size, ele=data_ptr.pts_to)
        return ty

    def _unwrap_argument_type(self, ty: RustStruct) -> RustStruct:
        # core::fmt::rt::Argument { ty: enum { Placeholder{...}, Count(u16) } }
        if ty.name == "core::fmt::rt::Argument" and {f.name for f in ty.fields} == {"ty"}:
            inner = ty.fields[0].ty
            if isinstance(inner, RustEnum):
                for v in inner.variants:
                    if v.name == "Placeholder":
                        return RustStruct(size=ty.size, name="core::fmt::rt::Argument", fields=list(v.fields))
        return ty

    # -- prototypes --------------------------------------------------------
    def _parse_prototype(self, data) -> RustFnProto | None:
        if not data:
            return None
        args = [self._parse_type(a) for a in data.get("args", [])]
        if any(a is None for a in args):
            return None
        ret = self._parse_type(data.get("returnty"))
        return self._fit_abi(args, ret)

    def _fit_abi(self, args: list[RustType], ret: RustType | None) -> RustFnProto:
        """Heuristic Rust ABI fit: aggregates larger than two registers are
        passed/returned by reference (ported from ``_fit_abi``)."""
        big = self.arch_bytes * 2
        new_args: list[RustType] = []
        for a in args:
            if isinstance(a, (RustEnum, RustStruct)) and a.size > big:
                new_args.append(RustPointer(size=self.arch_bytes, pts_to=a))
            else:
                new_args.append(a)
        if isinstance(ret, (RustEnum, RustStruct)) and ret.size > big:
            new_args.insert(0, RustPointer(size=self.arch_bytes, pts_to=ret))
            return RustFnProto(new_args, None, is_retbuf=True)
        return RustFnProto(new_args, ret)
