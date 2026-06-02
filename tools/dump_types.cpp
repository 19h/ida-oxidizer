// Dev tool: load a type DB, print the generated C header, and (with --asserts)
// append _Static_assert(sizeof(T)==N) for every named struct/enum so a C
// compiler can verify byte-exact layout fidelity.
//
//   dump_types <type_db.json> [--asserts]
#include <iostream>
#include <string>

#include "../src/core/c_render.h"
#include "../src/core/typedb.h"

using namespace oxi;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: dump_types <type_db.json> [--asserts]\n";
        return 2;
    }
    bool asserts = argc > 2 && std::string(argv[2]) == "--asserts";
    TypeDB db = TypeDB::from_file(argv[1]);
    CRenderer renderer(db);
    std::string header = renderer.render_header();
    std::cout << header;
    if (asserts) {
        std::cout << "\n// ---- layout fidelity assertions ----\n";
        for (const auto& [name, t] : db.types) {
            if ((t->kind == RKind::Struct || t->kind == RKind::Enum) && t->size > 0) {
                std::string cname = renderer.c_name_for(name);
                if (!cname.empty()) {
                    std::cout << "_Static_assert(sizeof(" << cname << ") == " << t->size << ", \"" << cname << "\");\n";
                }
            }
        }
    }
    return 0;
}
