"""Self-contained Rust symbol demangler (legacy ``_ZN`` + v0 ``_R``).

Oxidizer relies on the ``rust_demangler`` Python package plus a small ``normalize``
helper (``angr/rust/utils/demangler.py``).  IDA's bundled Python usually does not
ship that package, and although recent IDA builds can demangle Rust names, the
result is not guaranteed to match Oxidizer's expectations.  To keep the plugin
self-contained and testable, this module reimplements both manglings from scratch
and ports Oxidizer's ``normalize`` regex pipeline verbatim.

The public surface mirrors Oxidizer:

* :func:`demangle`   -> best-effort human-readable path, trailing legacy hash dropped
* :func:`normalize`  -> demangle + strip generics / ``<X as Y>`` qualifications
"""

from __future__ import annotations

import re
import string

# ---------------------------------------------------------------------------
# normalize() — ported verbatim from angr/rust/utils/demangler.py
# ---------------------------------------------------------------------------

GENERIC_TYPE_PATTERN = re.compile(r"(?:::)?<(?:(?!\sas\s)[^<])*?>")
XXX_AS_YYY_PATTERN = re.compile(r"<(?!impl\s)([^<]+?)\sas\s([^<]+?)>")
IMPL_XXX_AS_YYY_PATTERN = re.compile(r"<impl\s([^<]+?)\sas\s([^<]+?)>")


def _is_rust_hash(s: str) -> bool:
    return len(s) == 17 and s.startswith("h") and all(c in "0123456789abcdef" for c in s[1:])


def demangle(s: str) -> str:
    """Demangle *s* and drop a trailing legacy hash component.

    Mirrors ``angr.rust.utils.demangler.demangle``: on any failure the original
    string is returned unchanged.
    """
    try:
        raw = _demangle_raw(s)
    except Exception:
        return s
    if raw is None:
        return s
    parts = raw.split("::")
    if len(parts) >= 2 and _is_rust_hash(parts[-1]):
        return "::".join(parts[:-1])
    return raw


def normalize(name: str, monopolize: bool = True, concise: bool = False, use_trait_name: bool = False) -> str:
    """Strip generic parameters and ``<X as Y>`` qualifications.

    Ported verbatim from ``angr.rust.utils.demangler.normalize`` so that names
    produced for IDA match the ones Oxidizer's analyses key on.
    """
    demangled = demangle(name)
    if monopolize:
        old_len = 0
        while old_len != len(demangled):
            old_len = len(demangled)
            demangled = GENERIC_TYPE_PATTERN.sub("", demangled)
            demangled = XXX_AS_YYY_PATTERN.sub(lambda m: m.groups()[1 if use_trait_name else 0], demangled)
            demangled = IMPL_XXX_AS_YYY_PATTERN.sub(lambda m: m.groups()[1], demangled)
    if concise:
        demangled = demangled.split("::")[-1]
    return demangled


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------


def _strip_symbol_prefix(s: str) -> str:
    # Mach-O prepends an extra underscore; some toolchains omit the leading one.
    if s.startswith("__"):
        return s[1:]
    return s


def _demangle_raw(s: str) -> str | None:
    s = _strip_symbol_prefix(s)
    if s.startswith("_R"):
        return V0Demangler(s).parse()
    # Legacy: _ZN...E  (or ZN...E without the leading underscore on some platforms)
    if s.startswith("_ZN") or s.startswith("ZN"):
        return _demangle_legacy(s)
    return None


# ---------------------------------------------------------------------------
# Legacy mangling (_ZN <len><ident> ... E)
# ---------------------------------------------------------------------------

_LEGACY_ESCAPES = {
    "SP": "@",
    "BP": "*",
    "RF": "&",
    "LT": "<",
    "GT": ">",
    "LP": "(",
    "RP": ")",
    "C": ",",
    "u7e": "~",
    "u20": " ",
    "u27": "'",
    "u5b": "[",
    "u5d": "]",
    "u7b": "{",
    "u7d": "}",
    "u3b": ";",
    "u2b": "+",
    "u21": "!",
    "u22": '"',
}


def _decode_legacy_ident(ident: str) -> str:
    """Decode the ``$..$`` escapes and ``..`` separators inside one component."""
    # rustc prepends a leading "_" to an element that would otherwise start with a
    # special character (e.g. "<" encoded as "$LT$").  Drop that escape underscore.
    if ident.startswith("_$"):
        ident = ident[1:]
    out = []
    i = 0
    n = len(ident)
    while i < n:
        c = ident[i]
        if c == "$":
            end = ident.find("$", i + 1)
            if end == -1:
                out.append(ident[i:])
                break
            code = ident[i + 1 : end]
            if code in _LEGACY_ESCAPES:
                out.append(_LEGACY_ESCAPES[code])
            elif code.startswith("u") and all(ch in string.hexdigits for ch in code[1:]) and len(code) > 1:
                try:
                    out.append(chr(int(code[1:], 16)))
                except ValueError:
                    out.append("$" + code + "$")
            else:
                out.append("$" + code + "$")
            i = end + 1
        elif c == "." and i + 1 < n and ident[i + 1] == ".":
            out.append("::")
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _demangle_legacy(s: str) -> str | None:
    # Drop the leading optional underscore + 'ZN'
    body = s[3:] if s.startswith("_ZN") else s[2:]
    # body is a run of <len><name> components terminated by 'E'
    comps = []
    i = 0
    n = len(body)
    while i < n:
        if body[i] == "E":  # end marker
            break
        # read a decimal length
        j = i
        while j < n and body[j].isdigit():
            j += 1
        if j == i:
            return None  # not a valid length-prefixed component
        length = int(body[i:j])
        comp = body[j : j + length]
        if len(comp) != length:
            return None
        comps.append(_decode_legacy_ident(comp))
        i = j + length
    if not comps:
        return None
    return "::".join(comps)


# ---------------------------------------------------------------------------
# v0 mangling (RFC 2603) — faithful subset of the rustc-demangle algorithm
# ---------------------------------------------------------------------------

_BASIC_TYPES = {
    "a": "i8",
    "b": "bool",
    "c": "char",
    "d": "f64",
    "e": "str",
    "f": "f32",
    "h": "u8",
    "i": "isize",
    "j": "usize",
    "l": "i32",
    "m": "u32",
    "n": "i128",
    "o": "u128",
    "s": "i16",
    "t": "u16",
    "u": "()",
    "v": "...",
    "x": "i64",
    "y": "u64",
    "z": "!",
    "p": "_",
}


class _Err(Exception):
    pass


class V0Demangler:
    """Recursive-descent decoder for Rust v0 symbol names.

    Implements the common productions: nested paths, generic argument lists,
    impls, the primitive types, references / pointers / slices / arrays / tuples /
    function pointers, backreferences, and punycode identifiers.  Anything
    unrecognised raises and the caller falls back to the raw symbol.
    """

    def __init__(self, sym: str):
        # sym starts with "_R"; an optional decimal encoding-version follows.
        body = sym[2:]
        # optional leading decimal => unsupported newer encoding version; bail.
        if body[:1].isdigit():
            raise _Err("unsupported v0 encoding version")
        self.s = body
        self.pos = 0
        self.depth = 0

    # -- low level cursor helpers ------------------------------------------
    def _peek(self) -> str:
        if self.pos >= len(self.s):
            raise _Err("eof")
        return self.s[self.pos]

    def _next(self) -> str:
        c = self._peek()
        self.pos += 1
        return c

    def _eat(self, c: str) -> bool:
        if self.pos < len(self.s) and self.s[self.pos] == c:
            self.pos += 1
            return True
        return False

    def parse(self) -> str:
        self.depth = 0
        out = self._path()
        return out

    def _guard(self):
        self.depth += 1
        if self.depth > 256:
            raise _Err("recursion")

    # -- base-62 / decimal numbers ----------------------------------------
    def _base62(self) -> int:
        # digits until '_'; value = decoded+1, empty => 0
        if self._eat("_"):
            return 0
        val = 0
        while True:
            c = self._next()
            if c == "_":
                return val + 1
            if c.isdigit():
                val = val * 62 + (ord(c) - ord("0"))
            elif "a" <= c <= "z":
                val = val * 62 + 10 + (ord(c) - ord("a"))
            elif "A" <= c <= "Z":
                val = val * 62 + 36 + (ord(c) - ord("A"))
            else:
                raise _Err("bad base62")

    def _decimal(self) -> int:
        start = self.pos
        while self.pos < len(self.s) and self.s[self.pos].isdigit():
            self.pos += 1
        if self.pos == start:
            raise _Err("expected decimal")
        return int(self.s[start : self.pos])

    # -- identifiers -------------------------------------------------------
    def _disambiguator(self) -> int:
        if self._eat("s"):
            return self._base62()
        return 0

    def _identifier(self) -> str:
        is_punycode = self._eat("u")
        n = self._decimal()
        self._eat("_")  # optional separator
        raw = self.s[self.pos : self.pos + n]
        if len(raw) != n:
            raise _Err("ident underrun")
        self.pos += n
        if is_punycode:
            return _decode_punycode(raw)
        return raw

    # -- paths -------------------------------------------------------------
    def _path(self) -> str:
        self._guard()
        try:
            tag = self._next()
            if tag == "C":  # crate root
                self._disambiguator()
                return self._identifier()
            if tag == "N":  # nested
                ns = self._next()  # namespace char (ignored for display)
                parent = self._path()
                self._disambiguator()
                name = self._identifier()
                if not name:
                    # closures / anonymous items
                    return f"{parent}::{{{ns}}}"
                return f"{parent}::{name}"
            if tag == "M":  # inherent impl  <type>
                self._disambiguator()
                self._path()  # impl-path (disambiguating; not shown)
                ty = self._type()
                return f"<{ty}>"
            if tag == "X":  # trait impl  <type as trait>
                self._disambiguator()
                self._path()  # impl-path
                ty = self._type()
                tr = self._path()
                return f"<{ty} as {tr}>"
            if tag == "Y":  # trait definition  <type as trait>
                ty = self._type()
                tr = self._path()
                return f"<{ty} as {tr}>"
            if tag == "I":  # generic args:  path {arg} E
                base = self._path()
                args = []
                while not self._eat("E"):
                    args.append(self._generic_arg())
                if args:
                    return f"{base}::<{', '.join(args)}>"
                return base
            if tag == "B":  # backref — we cannot resolve without a table; approximate
                self._base62()
                return "_"
            raise _Err(f"unknown path tag {tag}")
        finally:
            self.depth -= 1

    # -- generic args ------------------------------------------------------
    def _generic_arg(self) -> str:
        if self._eat("L"):  # lifetime
            self._base62()
            return "'_"
        if self._eat("K"):  # const
            return self._const()
        return self._type()

    def _const(self) -> str:
        if self._eat("B"):
            self._base62()
            return "_"
        ty = self._type()  # const type
        if self._eat("n"):  # negative
            val = self._hex_const()
            return f"-{val}"
        if self._eat("p"):  # placeholder
            return "_"
        val = self._hex_const()
        if ty == "bool":
            return "true" if val == 1 else "false"
        return str(val)

    def _hex_const(self) -> int:
        start = self.pos
        while self.pos < len(self.s) and self.s[self.pos] != "_":
            self.pos += 1
        hexs = self.s[start : self.pos]
        self._eat("_")
        return int(hexs, 16) if hexs else 0

    # -- types -------------------------------------------------------------
    def _type(self) -> str:
        self._guard()
        try:
            c = self._peek()
            if c in _BASIC_TYPES:
                self.pos += 1
                return _BASIC_TYPES[c]
            tag = self._next()
            if tag == "A":  # array [T; N]
                inner = self._type()
                n = self._const()
                return f"[{inner}; {n}]"
            if tag == "S":  # slice [T]
                return f"[{self._type()}]"
            if tag == "T":  # tuple
                parts = []
                while not self._eat("E"):
                    parts.append(self._type())
                if len(parts) == 1:
                    return f"({parts[0]},)"
                return f"({', '.join(parts)})"
            if tag == "R":  # &T (optional lifetime)
                lt = self._opt_lifetime()
                return f"&{lt}{self._type()}"
            if tag == "Q":  # &mut T
                lt = self._opt_lifetime()
                return f"&{lt}mut {self._type()}"
            if tag == "P":  # *const T
                return f"*const {self._type()}"
            if tag == "O":  # *mut T
                return f"*mut {self._type()}"
            if tag == "F":  # function pointer
                return self._fn_sig()
            if tag == "D":  # dyn trait
                bounds = self._dyn_bounds()
                self._opt_lifetime()  # trailing lifetime
                return f"dyn {bounds}"
            if tag == "B":  # backref
                self._base62()
                return "_"
            # Otherwise it must be a path-type; rewind and parse a path.
            self.pos -= 1
            return self._path()
        finally:
            self.depth -= 1

    def _opt_lifetime(self) -> str:
        if self._eat("L"):
            self._base62()
            return "'_ "
        return ""

    def _fn_sig(self) -> str:
        # binder?  C? extern? args E ret
        if self._eat("G"):  # binder
            self._base62()
        self._eat("U")  # unsafe
        if self._eat("K"):  # abi
            if not self._eat("C"):
                self._identifier()
        args = []
        while not self._eat("E"):
            args.append(self._type())
        ret = self._type()
        return f"fn({', '.join(args)}) -> {ret}"

    def _dyn_bounds(self) -> str:
        if self._eat("G"):  # binder
            self._base62()
        traits = []
        while not self._eat("E"):
            traits.append(self._path())
            # associated bindings: 'p' ident type ...
            while self._eat("p"):
                self._identifier()
                self._type()
        return " + ".join(traits) if traits else "?"


# ---------------------------------------------------------------------------
# punycode decoder (RFC 3492), as used by Rust v0 for non-ASCII identifiers
# ---------------------------------------------------------------------------

_PUNY_BASE = 36
_PUNY_TMIN = 1
_PUNY_TMAX = 26
_PUNY_SKEW = 38
_PUNY_DAMP = 700
_PUNY_INITIAL_BIAS = 72
_PUNY_INITIAL_N = 128


def _puny_adapt(delta: int, numpoints: int, firsttime: bool) -> int:
    delta = delta // _PUNY_DAMP if firsttime else delta // 2
    delta += delta // numpoints
    k = 0
    while delta > ((_PUNY_BASE - _PUNY_TMIN) * _PUNY_TMAX) // 2:
        delta //= _PUNY_BASE - _PUNY_TMIN
        k += _PUNY_BASE
    return k + (_PUNY_BASE - _PUNY_TMIN + 1) * delta // (delta + _PUNY_SKEW)


def _decode_punycode(s: str) -> str:
    # Rust replaces the punycode '_' separator with the last delimiter position.
    # In v0 the encoding uses '_' as the basic/extended separator.
    if "_" in s:
        basic, _, ext = s.rpartition("_")
    else:
        basic, ext = "", s
    output = list(basic)
    n = _PUNY_INITIAL_N
    i = 0
    bias = _PUNY_INITIAL_BIAS
    idx = 0
    ext_chars = ext
    while idx < len(ext_chars):
        oldi = i
        w = 1
        k = _PUNY_BASE
        while True:
            if idx >= len(ext_chars):
                raise _Err("bad punycode")
            c = ext_chars[idx]
            idx += 1
            if "0" <= c <= "9":
                digit = c2d = ord(c) - ord("0") + 26
            elif "a" <= c <= "z":
                digit = ord(c) - ord("a")
            else:
                raise _Err("bad punycode digit")
            i += digit * w
            t = _PUNY_TMIN if k <= bias else (_PUNY_TMAX if k >= bias + _PUNY_TMAX else k - bias)
            if digit < t:
                break
            w *= _PUNY_BASE - t
            k += _PUNY_BASE
        out_len = len(output) + 1
        bias = _puny_adapt(i - oldi, out_len, oldi == 0)
        n += i // out_len
        i %= out_len
        output.insert(i, chr(n))
        i += 1
    return "".join(output)
