# Oxidizer for IDA

A native (C++) IDA Pro / Hex-Rays plugin that ports the practical, high-value
slice of [Oxidizer](../README.md)'s Rust-decompilation aids to IDA — **without**
depending on angr.

Oxidizer proper is an angr-based Rust decompiler: it *owns* the whole decompiler
pipeline (mutable AIL IR, a pluggable type stage, a re-runnable structurer, a Rust
code generator). IDA/Hex-Rays does not expose those seams, so a faithful 1:1 port
is not possible (see the feasibility analysis that motivated this). What *is*
both portable and genuinely useful is ported here:

| Capability | Status | How |
|---|---|---|
| **Rust symbol demangling** (legacy `_ZN` + v0 `_R`) | ✅ | self-contained demangler + Oxidizer's `normalize()` |
| **rustc version identification** | ✅ | embedded `/rustc/<commit>/` + `rustc X.Y.Z` strings → 151k-entry commit map |
| **Function renaming** to demangled Rust paths | ✅ | `set_name` over every function |
| **`no-return` marking** of panic/abort helpers | ✅ | huge decompiler-output cleanup (kills dead code after `unwrap`/bounds checks) |
| **Std type recovery** (structs/enums/`Option`/`Result`/slices/`&str`) | ✅ | per-version type DB → byte-exact C types → IDA local types |
| **Function prototype recovery** | ✅ | type-DB prototypes + Rust-ABI fit → `apply_tinfo` |
| **FLIRT std-library identification** | ✅ (headless-verified) | stages + applies Oxidizer's IDA-format `.sig` files; recovers 900+ names on a stripped test binary |
| **Rust idiom annotation** (`panic!`, `format!`, `drop`, `alloc`…) | ✅ (Hex-Rays) | ctree visitor adds pseudocode comments |
| `match` / `if let` / `?` rendered as real Rust | ❌ | architecturally blocked — Hex-Rays' C printer/structurer are closed |

## Architecture

The hard, value-bearing logic lives in an **IDA-independent core** (`src/core/`)
that compiles and is unit-tested with a plain host compiler — no IDA required.
A thin **glue layer** (`src/ida/`) is the only code that touches the SDK.

```
src/core/        # portable, host-testable (no IDA headers)
  json.{h,cpp}        — dependency-free JSON reader (for the type DB)
  demangle.{h,cpp}    — Rust legacy + v0 demangler + normalize()
  idioms.{h,cpp}      — std-symbol idiom classifier + no-return detection
  version_id.{h,cpp}  — rustc version id (strings + two-phase FLIRT scoring)
  typedb.{h,cpp}      — type-DB JSON → typed Rust IR
  c_render.{h,cpp}    — Rust IR → byte-exact C header + C prototypes
src/ida/         # IDA SDK glue (needs a real SDK to build)
  oxidizer_ida.cpp    — plugin entry + orchestration
  idiom_hooks.{h,cpp} — optional Hex-Rays idiom annotation
tests/           # host tests + minimal SDK stubs for glue syntax-checking
tools/           # dump_types: emit the generated C header / size assertions
reference_py/    # the validated Python reference (oracle) the C++ mirrors
```

Rendering types to a C header (rather than hand-building `tinfo_t`) keeps the hard
work a pure, testable string transform and is portable across SDK versions: the
plugin feeds the header to `parse_decls()` in one call. Exact struct/enum layout
is preserved with `#pragma pack(1)` and explicit padding derived from the type
DB's byte offsets/sizes; zero-sized Rust types (closures, `PhantomData`) are
omitted so they don't perturb the layout.

## Building

### Host core + tests (no IDA SDK needed)

```bash
cd oxidizer_ida
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

This builds the core library, runs the test suite, and compiles the IDA glue
against the bundled SDK stubs as a syntax check.

### The IDA plugin (requires the IDA SDK)

The plugin builds with the SDK's own `ida-cmake` framework (most reliable across
SDK versions). `IDASDK` must point at the directory that contains
`ida-cmake/`, `include/` and `lib/` — in a stock IDA 9.x SDK that is the `src`
subdirectory:

```bash
cd plugin
export IDASDK=/path/to/idasdk/src     # the dir with include/, lib/, ida-cmake/
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The product is `oxidizer.so` (Linux) / `oxidizer.dll` (Windows) /
`oxidizer.dylib` (macOS), written to `<sdk>/bin/plugins/`. Copy it into your IDA
user plugins directory:

```bash
cp <sdk>/bin/plugins/oxidizer.so ~/.idapro/plugins/
```

> Built and tested against **IDA Pro 9.3 / Hex-Rays 9.4** on Linux (clang).
> `CMakeLists.txt` (top level) also offers a hand-rolled `-DOXIDIZER_BUILD_PLUGIN=ON`
> path, but the `plugin/` `ida-cmake` build is preferred.

### Verified end-to-end with `idump`

Confirmed working headless via the `idump` idalib decompiler dumper
(`idump --pseudo`), against IDA Pro 9.3 / Hex-Rays 9.4. The plugin auto-runs in
two phases driven by analysis events, so everything is in place before idump
decompiles — no interactive step needed:

* `auto_empty` → detect rustc version + **plan FLIRT** signatures
* IDA applies the planned signatures during continued analysis
* `auto_empty_finally` → demangle/rename, mark `no-return`, apply std types &
  prototypes (the recovered names are now present)

Measured on the bundled `binaries/FakeCrypt` (Rust 1.87.0), clean A/B with a
fresh database each run (the no-plugin baseline is deterministic — two runs are
byte-identical):

| | **stripped** (4090 funcs, 0 symbols) | non-stripped |
|---|---|---|
| Rust fn names recovered (FLIRT) | **1 → 923** | n/a (symbols present) |
| std types materialised & applied | **51** | 20 |
| prototype-typed signatures | **928** | — |
| demangled std calls in bodies | **867** | — |

The stripped result is the headline: from an *unnamed, symbol-free* binary, FLIRT
recovers 900+ std/core/alloc names, which then cascade into demangling, type and
prototype recovery. Example transformation (non-stripped, but representative):

```c
// plain idump:
void __fastcall <…SetLenOnDrop as …Drop>::drop(_QWORD *a1, __int64 a2)
{ *a1 = a2; }

// with the Oxidizer plugin:
void …SetLenOnDrop…drop(OXI_alloc_vec_set_len_on_drop_SetLenOnDrop *a0)
{ a0->len = v1; }      // recovered struct type + named field access
```

FLIRT signatures are staged into IDA's processor `sig/` dir and applied with
`plan_to_apply_idasgn`; both the inlined and no-inline sig sets across all opt
levels are planned (non-matching patterns simply don't fire), maximising recovery.

## Data assets

The plugin reads three asset sets that ship in the Oxidizer repo under
`angr/rust/analyses/` and `angr/rust/definitions/`:

- `type_db/<version>.json` — per-version Rust std type databases (1.39.0–1.93.0)
- `flirt_sigs/<version>-O{0..3}.sig` — IDA-format FLIRT signatures
- `definitions/commit_versions.py` — rustc commit-hash → version map

Point the plugin at them with the `OXIDIZER_DATA_DIR` environment variable
(defaults to the compiled-in `OXIDIZER_DEFAULT_DATA_DIR`, set from
`OXIDIZER_REPO_ROOT` at configure time):

```bash
export OXIDIZER_DATA_DIR=/path/to/oxidizer/angr/rust/analyses
```

## Usage

Open a stripped Rust binary in IDA, run auto-analysis, then invoke the plugin
(**Edit ▸ Plugins ▸ Oxidizer (Rust)**, or `Ctrl-Alt-R`). It will:

1. detect the rustc version from embedded strings,
2. apply matching std FLIRT signatures (best effort),
3. demangle and rename every function,
4. mark panic/abort helpers `no-return`,
5. load the version's type DB, declare the std types, and apply recovered
   prototypes,
6. (Hex-Rays build) annotate recognised Rust idiom calls in the pseudocode.

A summary dialog reports what was recovered.

## Verification

The core is exhaustively self-checked:

- **1787** host assertions over demangling, idiom classification, version-id,
  JSON, and type-DB parsing (`ctest`).
- **Byte-exact type layout** verified by generating `_Static_assert(sizeof(T)==N)`
  for every named std type and compiling it as C — across **all 55** Rust
  versions (1.39.0 → 1.93.0).
- The IDA glue is syntax-checked against minimal SDK stubs (it still requires a
  real SDK for the final link).

```bash
# Regenerate + verify the C header for one version:
./build/dump_types /path/to/type_db/1.84.0.json --asserts > types.txt
```

## Limitations

- **Output is C, not Rust.** Hex-Rays' microcode→C printer and structurer are
  closed; `match` / `if let` / `?` can only be approximated, not rendered as Rust.
- **Niche-encoded enums are lossy.** `Option<&T>` (where `None` *is* the null
  pointer) has no faithful C type; it degrades to the payload type with a note.
- **Tagged enums render as `{ tag; payload-blob }`** with the variants listed in
  a comment (exact size, approximate interior).
- **FLIRT staging** copies signatures into IDA's `sig/` dir, which must be
  writable; otherwise apply the signatures manually.

## Capability ledger (exhaustive port audit)

Oxidizer's ~55 Rust-decompilation capabilities were audited one-by-one against
this plugin and the IDA/Hex-Rays SDK. Every capability falls into exactly one
bucket below — so the set of things that remain portable-but-unbuilt is bounded
and explicit.

**Ported & verified (this plugin):** Rust symbol/FLIRT recovery, demangling
(legacy + v0 + `j_` thunks) + normalization, function renaming, panic/abort
`no-return` marking, per-version type-DB struct/enum materialisation, function
prototype application (with dedup + Hex-Rays arg-count negotiation), version
identification (embedded commit/string), Hex-Rays idiom annotation.

**Redundant with IDA/Hex-Rays (~16):** e.g. FLIRT propagation, struct-memory
layout, combo-register rewrites, unreachable/redundant-block removal, variable
isolation, call-expression extraction — IDA's own analysis already does these.

**Architecturally blocked (5)** — require Hex-Rays' *closed* microcode→C
structurer/printer or extensible ctree nodes, which no plugin can reach:
Pattern-match/enum recovery, Struct Builder (struct-from-stores rewriting),
struct-return enum/variant simplification, the show-family macro renderer, and
the Typehoon type back-translator (real-Rust output).

**Remaining portable frontier (not built):** per-function calling-convention /
prototype *inference* for arbitrary user functions (Option/Result/retbuf/by-ref
synthesis). This is implementable in principle (it acts before the closed ctree)
but requires porting Oxidizer's AIL dataflow fact-collector onto Hex-Rays
microcode — the "rewrite, not port" cost the original feasibility study
identified. It is a research-grade effort, not a wiring task.

**Attempted, then reverted (kept the port provably correct):**
- *Cleanup-function call-graph propagation* — recovered 0 on the test corpus
  (FLIRT already named all drop glue); unverifiable benefit.
- *Normalized-name prototype fallback* — can mis-type a differently-instantiated
  generic; not provably correct.
- *FLIRT-scoring version fallback* — blocked headless: IDA defers signature
  application past the in-event `auto_wait`, so per-candidate match counts read
  0. (The scoring algorithm itself is ported and unit-tested in `core/`.)
