#include <cassert>
#include <iostream>
#include <s2e/Plugins/Core/SparseSymbolicPolicy.h>
using namespace s2e::plugins;
int main() {
    SparseSymbolicPolicy p;
    assert(!p.add("", {{0, 1}}));
    assert(!p.add("ReadFile", {{2, 2}}));
    assert(!p.add("ReadFile", {{0, 3}, {2, 4}}));
    assert(!p.add("ReadFile", {{0, 4097}}));
    assert(!p.add("ReadFile", {}));
    assert(p.add("ReadFile.output", {{0, 2}, {30, 32}}));
    assert(!p.add("ReadFile.output", {{0, 1}}));
    assert(!p.match("OtherReadFile.output"));
    assert(!p.match("ReadFile.outputExtra"));
    assert(!p.match("ReadFile.failure"));
    const auto *r = p.match("ReadFile.output.0");
    assert(r && r->size() == 2);
    auto selected = SparseSymbolicPolicy::clipped(*r, 31);
    assert(selected.size() == 2 && selected[1].second == 31);
    assert(SparseSymbolicPolicy::clipped(*r, 0).empty());
    assert(p.add("ReadFile.output.0", {{4, 8}}));
    assert(p.match("ReadFile.output.0")->front().first == 4);
    assert(p.match("ReadFile.output.1")->front().first == 0);
    std::cout << "Sparse symbolic policy: validation, exact tokens, clipping and precedence passed\n";
}
