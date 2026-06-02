// Self-contained Rust symbol demangler (legacy `_ZN` + v0 `_R`) and Oxidizer's
// `normalize` helper, ported from angr/rust/utils/demangler.py (and the C++
// reimplementation validated against the Python test-suite oracle).
//
// No IDA dependency: testable with a host compiler.
#pragma once

#include <string>

namespace oxi {

// Demangle a Rust symbol, dropping a trailing legacy hash component.
// Returns the input unchanged if it is not a recognised mangling or is malformed.
std::string demangle(const std::string& sym);

// Demangle, then (when monopolize) strip generic parameters and `<X as Y>`
// trait qualifications.  `concise` keeps only the final path component.
// `use_trait_name` keeps the trait side of `<Type as Trait>` instead of the type.
std::string normalize(const std::string& name,
                      bool monopolize = true,
                      bool concise = false,
                      bool use_trait_name = false);

}  // namespace oxi
