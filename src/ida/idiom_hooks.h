// Optional Hex-Rays integration: annotate recognised Rust idiom calls
// (panic!, format!, drop, alloc, ...) in the decompiler pseudocode.
//
// Only compiled when the plugin is built with OXIDIZER_WITH_HEXRAYS and the
// Hex-Rays SDK is available.
#pragma once

namespace oxidizer {

// Initialise Hex-Rays (if present) and install the idiom-annotation callback.
// Safe to call more than once; a no-op if Hex-Rays is unavailable.
void install_idiom_hooks();

}  // namespace oxidizer
