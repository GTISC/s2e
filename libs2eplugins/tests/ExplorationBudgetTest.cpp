#include "../src/s2e/Plugins/ExecutionTracers/ExplorationBudget.h"
#include <cassert>

using namespace s2e::plugins;
static ExplorationBudget policy() {
    ExplorationBudget p;
    p.initial = 30; p.maximum = 90; p.extension = 30; p.window = 20; p.minimum = 10;
    return p;
}
int main() {
    auto p = policy();
    assert(p.tick(1000) == ExplorationBudget::Wait);
    assert(!p.progress(0, "unready", true));
    p.start();
    assert(!p.quiet(19));
    assert(p.quiet(20));
    assert(!p.quiet(21));
    assert(p.progress(22, budgetKey("autorun_configuration", 1), true));
    assert(!p.progress(29, budgetKey("autorun_configuration", 1), true));
    assert(p.tick(29) == ExplorationBudget::Wait);
    assert(p.tick(30) == ExplorationBudget::Extend && p.soft == 60);
    p.start(); // readiness from a sibling cannot reset the budget
    assert(p.soft == 60);
    assert(p.progress(45, budgetKey("file_write", 1), false));
    assert(p.tick(60) == ExplorationBudget::SoftStop); // weak progress earns no extension
    assert(p.progress(70, budgetKey("autorun_configuration", 2), true));
    assert(p.tick(71) == ExplorationBudget::Wait); // shadow counterfactual is terminal
    assert(p.tick(90) == ExplorationBudget::HardStop);
    p = policy(); p.start();
    p.progress(1, "old", true);
    assert(p.tick(30) == ExplorationBudget::SoftStop); // stale strong evidence
    p = policy(); p.start();
    p.progress(10, "boundary", true);
    assert(p.tick(30) == ExplorationBudget::Extend); // inclusive freshness boundary
    p.progress(59, "deeper", true);
    assert(p.tick(60) == ExplorationBudget::Extend && p.soft == 90);
    p.progress(89, "more", true);
    assert(p.tick(90) == ExplorationBudget::HardStop); // hard cap wins
    assert(budgetKey("file_write", 4) == budgetKey("file_write", 999));
    p = policy(); p.start();
    for (unsigned i = 0; i < 256; ++i) assert(p.progress(i, std::to_string(i), false));
    assert(!p.progress(257, "overflow", true));
    assert(p.seen.size() == 256);
}
