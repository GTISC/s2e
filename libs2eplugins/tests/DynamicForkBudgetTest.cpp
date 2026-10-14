#include <s2e/Plugins/Lua/DynamicForkBudget.h>
#include <cassert>
using s2e::plugins::DynamicForkBudget;
int main() {
    DynamicForkBudget b;
    assert(b.grant(10, 1, 20, true, 8, 1, 2));
    for (int i = 0; i < 50; ++i) assert(!b.grant(10, 1, 20, true, 8, 1, 2));
    assert(b.total() == 1); // rejected attempts do not consume global budget
    assert(b.grant(10, 1, 30, true, 8, 1, 2));
    assert(!b.grant(10, 1, 40, true, 8, 1, 2));
    assert(b.grant(10, 1, 40, false, 8, 1, 2));
    assert(b.grant(10, 2, 20, false, 8, 1, 2)); // reallocation
    assert(b.grant(11, 2, 20, false, 8, 1, 2)); // process identity
    assert(b.grant(10, 1, 50, false, 8, 1, 2));
    assert(b.grant(10, 1, 60, false, 8, 1, 2));
    assert(b.grant(10, 1, 70, false, 8, 1, 2));
    assert(!b.grant(10, 1, 80, false, 8, 1, 2));
    DynamicForkBudget disabled;
    assert(!disabled.grant(1, 1, 0, false, 0, 1, 2));
}
