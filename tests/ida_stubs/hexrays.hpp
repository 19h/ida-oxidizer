// MINIMAL Hex-Rays SDK stub -- host syntax-checking of src/ida/idiom_hooks.cpp.
// Not the real SDK; signatures mirror hexrays.hpp closely enough to catch our
// own mistakes.
#pragma once

#include "pro.h"

struct hexdsp_t;  // opaque dispatcher

#define va_argi(va, type) ((type)va_arg(va, int))

enum hexrays_event_t { hxe_maturity, hxe_func_printed };
enum ctree_maturity_t { CMAT_ZERO, CMAT_BUILT, CMAT_FINAL };
enum ctype_t { cot_empty, cot_call, cot_obj };
enum item_preciser_t { ITP_NONE, ITP_SEMI, ITP_BLOCK1 };
enum { CV_FAST = 0x0001 };

struct citem_t {
    ctype_t op = cot_empty;
    ea_t ea = BADADDR;
};

struct cexpr_t : public citem_t {
    cexpr_t* x = nullptr;
    ea_t obj_ea = BADADDR;
};

struct cinsn_t : public citem_t {};

struct treeloc_t {
    ea_t ea = BADADDR;
    item_preciser_t itp = ITP_NONE;
};

struct cfunc_t {
    cinsn_t body;
    void set_user_cmt(const treeloc_t& loc, const char* cmt);
    void save_user_cmts();
    bool get_func_type(tinfo_t* t) const;
};

#define DECOMP_NO_WAIT 0x04
struct hexrays_failure_t {
    int code = 0;
    ea_t errea = BADADDR;
};
typedef cfunc_t* cfuncptr_t;
cfuncptr_t decompile(func_t* pfn, hexrays_failure_t* hf, int flags);

struct ctree_visitor_t {
    explicit ctree_visitor_t(int flags) { (void)flags; }
    virtual ~ctree_visitor_t() {}
    virtual int idaapi visit_expr(cexpr_t* e) { (void)e; return 0; }
    virtual int idaapi visit_insn(cinsn_t* i) { (void)i; return 0; }
    int apply_to(citem_t* item, citem_t* parent);
};

typedef ssize_t idaapi hexrays_cb_t(void* ud, hexrays_event_t event, va_list va);

bool init_hexrays_plugin(int flags = 0);
bool install_hexrays_callback(hexrays_cb_t* cb, void* ud);
