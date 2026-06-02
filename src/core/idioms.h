// Rust idiom recognition (IDA-independent).
//
// Distils the domain knowledge from Oxidizer's outliner/macro passes — which std
// symbols mean panic / alloc / drop / format / etc. — into a small classifier the
// IDA glue uses to mark panic helpers `noreturn`, comment recognised calls, and
// drive renaming.  Names are matched after demangle+normalize.
#pragma once

#include <string>

namespace oxi {

enum class Idiom {
    None,
    Panic,
    Bounds,
    Assert,
    Abort,
    Alloc,
    Dealloc,
    Drop,
    Format,
    Clone,
    Iter,
};

// Classify a (mangled or demangled) symbol.  Returns Idiom::None if unrecognised.
Idiom classify(const std::string& name, bool demangle_first = true);

// True for panic/abort-class functions that never return (high-value to mark in IDA).
bool is_noreturn(const std::string& name, bool demangle_first = true);

// A short human-facing comment for a recognised idiom, or empty string.
std::string comment_for(const std::string& name, bool demangle_first = true);

// A short display label for an idiom (e.g. "panic!()").  Empty for Idiom::None.
std::string idiom_label(Idiom idiom);

}  // namespace oxi
