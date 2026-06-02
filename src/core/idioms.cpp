#include "idioms.h"

#include <unordered_set>
#include <vector>

#include "demangle.h"

namespace oxi {
namespace {

struct Category {
    Idiom idiom;
    const char* label;
    const char* comment;
    std::unordered_set<std::string> exact;
    std::vector<std::string> substrings;
    bool noreturn;
};

const std::vector<Category>& categories() {
    // Order matters: more specific categories are checked first.
    static const std::vector<Category> cats = {
        {Idiom::Panic, "panic!()", "Rust panic - unconditional unwind/abort",
         {
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
         },
         {},
         true},
        {Idiom::Bounds, "bounds-check panic", "panic: index out of bounds / slice error",
         {
             "core::panicking::panic_bounds_check",
             "core::slice::index::slice_index_order_fail",
             "core::slice::index::slice_end_index_len_fail",
             "core::slice::index::slice_start_index_len_fail",
             "core::str::slice_error_fail",
             "alloc::raw_vec::capacity_overflow",
             "alloc::raw_vec::handle_error",
         },
         {},
         true},
        {Idiom::Assert, "assert!()", "Rust assertion failure",
         {
             "core::panicking::assert_failed",
             "core::panicking::assert_failed_inner",
             "core::panicking::assert_matches_failed",
         },
         {},
         true},
        {Idiom::Abort, "abort()", "process abort / alloc-error handler",
         {
             "core::intrinsics::abort",
             "std::process::abort",
             "std::sys::abort_internal",
             "abort",
             "core::panicking::panic_no_unwind",
             "alloc::alloc::handle_alloc_error",
             "handle_alloc_error",
             "__rust_alloc_error_handler",
             "rust_oom",
         },
         {},
         true},
        {Idiom::Alloc, "alloc", "heap allocation",
         {
             "alloc::alloc::alloc",
             "alloc::alloc::alloc_zeroed",
             "alloc::alloc::exchange_malloc",
             "alloc::alloc::__rust_alloc",
             "__rust_alloc",
             "__rust_alloc_zeroed",
             "__rust_realloc",
             "alloc::alloc::realloc",
         },
         {},
         false},
        {Idiom::Dealloc, "dealloc", "heap deallocation",
         {
             "alloc::alloc::dealloc",
             "alloc::alloc::box_free",
             "__rust_dealloc",
         },
         {},
         false},
        {Idiom::Drop, "drop()", "Rust Drop::drop / drop_in_place",
         {},
         {"::drop_in_place", "::real_drop_in_place"},
         false},
        {Idiom::Format, "format!()", "Rust formatting machinery",
         {
             "core::fmt::Arguments::new_v1",
             "core::fmt::Arguments::new_v1_formatted",
             "core::fmt::Arguments::new_const",
             "core::fmt::write",
             "core::fmt::Write::write_fmt",
             "std::io::Write::write_fmt",
         },
         {"core::fmt::"},
         false},
        {Idiom::Clone, "clone()", "Clone::clone", {}, {"::clone"}, false},
        {Idiom::Iter, "iterator", "iterator adapter", {}, {"core::iter::"}, false},
    };
    return cats;
}

const Category* find_category(Idiom idiom) {
    for (const auto& c : categories()) {
        if (c.idiom == idiom) return &c;
    }
    return nullptr;
}

}  // namespace

Idiom classify(const std::string& name, bool demangle_first) {
    std::string norm = demangle_first ? normalize(name) : name;
    for (const auto& c : categories()) {
        if (c.exact.count(norm)) return c.idiom;
    }
    for (const auto& c : categories()) {
        for (const auto& sub : c.substrings) {
            if (norm.find(sub) != std::string::npos) return c.idiom;
        }
    }
    return Idiom::None;
}

bool is_noreturn(const std::string& name, bool demangle_first) {
    Idiom idiom = classify(name, demangle_first);
    if (idiom == Idiom::None) return false;
    const Category* c = find_category(idiom);
    return c && c->noreturn;
}

std::string comment_for(const std::string& name, bool demangle_first) {
    Idiom idiom = classify(name, demangle_first);
    if (idiom == Idiom::None) return "";
    const Category* c = find_category(idiom);
    if (!c) return "";
    return std::string("[oxidizer] ") + c->label + ": " + c->comment;
}

std::string idiom_label(Idiom idiom) {
    const Category* c = find_category(idiom);
    return c ? c->label : "";
}

}  // namespace oxi
