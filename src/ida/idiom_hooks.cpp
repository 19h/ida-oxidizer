#include "ida/idiom_hooks.h"

#include <hexrays.hpp>
#include <name.hpp>
#include <pro.h>

#include <string>

#include "core/demangle.h"
#include "core/idioms.h"

// Hex-Rays dispatcher pointer, required by the SDK; populated by
// init_hexrays_plugin().
hexdsp_t* hexdsp = nullptr;

namespace oxidizer {
namespace {

bool g_installed = false;

// Walks a decompiled function's ctree and attaches a comment to every call of a
// recognised Rust std idiom (panic!, format!, drop, alloc, ...).
struct idiom_visitor_t : public ctree_visitor_t {
    cfunc_t* cfunc;
    bool changed = false;

    explicit idiom_visitor_t(cfunc_t* f) : ctree_visitor_t(CV_FAST), cfunc(f) {}

    int idaapi visit_expr(cexpr_t* e) override {
        if (e->op != cot_call || e->x == nullptr) return 0;
        // Only direct calls to a named object.
        if (e->x->op != cot_obj) return 0;
        ea_t target = e->x->obj_ea;
        if (target == BADADDR) return 0;

        qstring nm;
        if (get_name(&nm, target) <= 0) return 0;

        std::string cmt = oxi::comment_for(nm.c_str());
        if (cmt.empty()) return 0;

        treeloc_t loc;
        loc.ea = e->ea;
        loc.itp = ITP_SEMI;
        cfunc->set_user_cmt(loc, cmt.c_str());
        changed = true;
        return 0;
    }
};

ssize_t idaapi hexrays_callback(void*, hexrays_event_t event, va_list va) {
    if (event == hxe_maturity) {
        cfunc_t* cfunc = va_arg(va, cfunc_t*);
        ctree_maturity_t mat = va_argi(va, ctree_maturity_t);
        if (mat == CMAT_FINAL && cfunc != nullptr) {
            idiom_visitor_t v(cfunc);
            v.apply_to(&cfunc->body, nullptr);
            if (v.changed) cfunc->save_user_cmts();
        }
    }
    return 0;
}

}  // namespace

void install_idiom_hooks() {
    if (g_installed) return;
    if (!init_hexrays_plugin()) return;  // Hex-Rays not present
    install_hexrays_callback(hexrays_callback, nullptr);
    g_installed = true;
}

}  // namespace oxidizer
