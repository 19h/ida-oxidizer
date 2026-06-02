// Dev tool: read mangled symbols (one per line) from stdin, print
//   <demangled> \t <normalized> \t <idiom>
// for each.  Used to exercise the demangler/idiom classifier against real-world
// symbol tables (e.g. `nm binary | awk '{print $3}' | demangle_cli`).
#include <iostream>
#include <string>

#include "../src/core/demangle.h"
#include "../src/core/idioms.h"

using namespace oxi;

static const char* idiom_name(Idiom i) {
    switch (i) {
        case Idiom::Panic: return "panic";
        case Idiom::Bounds: return "bounds";
        case Idiom::Assert: return "assert";
        case Idiom::Abort: return "abort";
        case Idiom::Alloc: return "alloc";
        case Idiom::Dealloc: return "dealloc";
        case Idiom::Drop: return "drop";
        case Idiom::Format: return "format";
        case Idiom::Clone: return "clone";
        case Idiom::Iter: return "iter";
        default: return "-";
    }
}

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        std::string dem = demangle(line);
        std::string norm = normalize(line);
        Idiom idiom = classify(line);
        std::cout << dem << "\t" << norm << "\t" << idiom_name(idiom) << "\n";
    }
    return 0;
}
