// MINIMAL IDA SDK STUBS -- for host syntax-checking the plugin glue only.
// These are NOT the real SDK.  They declare just enough of the API surface that
// src/ida/oxidizer_ida.cpp uses, with signatures matching the real IDA SDK as
// closely as practical, so a host `clang++ -fsyntax-only` catches our own C++
// mistakes.  The real plugin must be built against a genuine IDA SDK.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdarg>
#include <cstdio>  // FILE
#include <cstring>
#include <string>
#include <sys/types.h>  // ssize_t

#define idaapi
#define BADADDR ((ea_t)-1)

typedef uint64_t ea_t;
typedef uint32_t uint32;
typedef int32_t int32;
typedef unsigned int uint;

// ---- qstring -------------------------------------------------------------
class qstring {
public:
    qstring() = default;
    qstring(const char* s) : s_(s ? s : "") {}
    const char* c_str() const { return s_.c_str(); }
    void clear() { s_.clear(); }
    size_t length() const { return s_.size(); }
    bool empty() const { return s_.empty(); }
    bool operator==(const char* o) const { return s_ == (o ? o : ""); }
private:
    std::string s_;
};

// ---- kernwin / loader output --------------------------------------------
int msg(const char* format, ...);
int info(const char* format, ...);

// ---- strings list --------------------------------------------------------
struct string_info_t {
    ea_t ea = 0;
    size_t length = 0;
    int type = 0;
};
void build_strlist();
size_t get_strlist_qty();
bool get_strlist_item(string_info_t* si, size_t n);
ssize_t get_strlit_contents(qstring* out, ea_t ea, size_t len, int type, ...);

// ---- functions -----------------------------------------------------------
#define FUNC_NORET 0x00000001u
struct func_t {
    ea_t start_ea = 0;
    ea_t end_ea = 0;
    unsigned int flags = 0;
};
size_t get_func_qty();
func_t* getn_func(size_t n);
func_t* get_func(ea_t ea);
ssize_t get_func_name(qstring* out, ea_t ea);
bool update_func(func_t* fn);
void reanalyze_function(func_t* pfn, ea_t ea1 = 0, ea_t ea2 = BADADDR, bool analyze_parents = false);

// ---- names ---------------------------------------------------------------
// Values match the real IDA SDK (name.hpp) so the stub stays faithful.
#define SN_CHECK 0x00
#define SN_NOCHECK 0x01
#define SN_NOWARN 0x100
#define SN_FORCE 0x800
bool set_name(ea_t ea, const char* name, int flags = 0);
ssize_t get_name(qstring* out, ea_t ea);

// ---- type info -----------------------------------------------------------
#define HTI_DCL 0x00000001
#define HTI_PAKDEF 0x00000000
#define PT_SIL 0x0001
#define TINFO_DEFINITE 0x0001
struct til_t;
struct printer_t;
class tinfo_t {
public:
    bool is_func() const { return is_func_; }
    int get_nargs() const { return nargs_; }
    bool is_func_ = false;
    int nargs_ = -1;
};
til_t* get_idati();
bool get_tinfo(tinfo_t* tif, ea_t ea);
int parse_decls(til_t* til, const char* input, printer_t* printer, int hti_flags);
bool parse_decl(tinfo_t* out, qstring* out_name, til_t* til, const char* decl, int pt_flags);
bool apply_tinfo(ea_t ea, const tinfo_t& tif, uint32 flags);

// ---- inf / config --------------------------------------------------------
bool inf_is_64bit();
qstring inf_get_procname();

// ---- files / env / sigs --------------------------------------------------
#define SIG_SUBDIR "sig"
const char* idadir(const char* subdir);
int plan_to_apply_idasgn(const char* fname);
int auto_wait();
bool qfileexist(const char* file);
struct file_enumerator_t {
    virtual int visit_file(const char* file) = 0;
    virtual ~file_enumerator_t() {}
};
int enumerate_files(char* answer, size_t answer_size, const char* path, const char* fname, file_enumerator_t& fv);
bool qgetenv(const char* varname, qstring* buf = nullptr);
FILE* qfopen(const char* file, const char* mode);
ssize_t qfread(FILE* fp, void* buf, size_t n);
ssize_t qfwrite(FILE* fp, const void* buf, size_t n);
int qfclose(FILE* fp);

// ---- event listeners -----------------------------------------------------
enum hook_type_t { HT_IDP, HT_IDB, HT_UI };
namespace idb_event {
enum event_code_t { closebase, savebase, upgraded, auto_empty, auto_empty_finally };
}
struct event_listener_t {
    virtual ssize_t idaapi on_event(ssize_t code, va_list va) = 0;
    virtual ~event_listener_t() {}
};
#define HKCB_GLOBAL 0x0001
bool hook_event_listener(hook_type_t hook_type, event_listener_t* cb, const void* owner, int flags = 0);
bool unhook_event_listener(hook_type_t hook_type, event_listener_t* cb);

// ---- plugin ABI (modern plugmod_t model, matching IDA 9.x) ----------------
#define IDP_INTERFACE_VERSION 1
#define PLUGIN_PROC 0x0040
#define PLUGIN_FIX 0x0080
#define PLUGIN_MULTI 0x0100

struct plugmod_t {
    virtual bool idaapi run(size_t arg) = 0;
    // plugmod_t helper that auto-supplies the owner (mirrors the real SDK).
    bool hook_event_listener(hook_type_t t, event_listener_t* cb, int flags = 0) {
        return ::hook_event_listener(t, cb, this, flags);
    }
    virtual ~plugmod_t() {}
};

struct plugin_t {
    int version;
    int flags;
    plugmod_t* (idaapi* init)();
    void* term;  // nullptr for PLUGIN_MULTI
    void* run;   // nullptr for PLUGIN_MULTI
    const char* comment;
    const char* help;
    const char* wanted_name;
    const char* wanted_hotkey;
};
