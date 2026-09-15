// Standalone test: c++ -std=c++17 -Wall -Wextra -Werror -I libs2eplugins/src
//   libs2eplugins/tests/BehaviorOracleTest.cpp -o /tmp/behavior-oracle-test
#include <cassert>
#include <iostream>
#include <s2e/Plugins/Analyzers/BehaviorOracle.h>

using namespace s2e::plugins;
constexpr auto Local = BehaviorGoal::AllocatedCodeExecution;
constexpr auto Child = BehaviorGoal::ChildRemoteExecution;

int main() {
    BehaviorOracle oracle;
    assert(oracle.stage(Local) == 0 && oracle.stage(Child) == 0);
    assert(oracle.stage(BehaviorGoal::None) == 0);
    oracle.executed(1, 1, 0x1000);
    assert(oracle.stage(Local) == 0);
    oracle.allocated(1, 1, 0x1000, 0x2000, 8);
    assert(oracle.stage(Local) == 1);
    oracle.executed(1, 2, 0x1000); // Wrong process.
    oracle.executed(2, 1, 0x1000); // Wrong allocation source.
    oracle.executed(1, 1, 0x2000); // Exclusive upper bound.
    assert(oracle.stage(Local) == 1);
    auto sibling = oracle;
    oracle.freed(1, 0x1000, 0x1000); // MEM_RELEASE has zero size.
    oracle.executed(1, 1, 0x1000);
    assert(oracle.stage(Local) == 0);
    sibling.executed(1, 1, 0x1000);
    assert(sibling.stage(Local) == 2 && oracle.stage(Local) == 0);

    BehaviorOracle child;
    child.childCreated(1, 2);
    assert(child.stage(Child) == 1);
    child.allocated(3, 2, 0x1000, 0x2000, 8); // Not the child's parent.
    child.executed(3, 2, 0x1000);
    assert(child.stage(Child) == 1);
    child.allocated(1, 2, 0x1000, 0x2000, 8);
    assert(child.stage(Child) == 2);
    auto childSibling = child;
    child.processExited(2);
    child.childCreated(3, 2); // Reused PID cannot inherit the old candidate.
    child.executed(1, 2, 0x1000);
    assert(child.stage(Child) == 1);
    childSibling.executed(1, 2, 0x1000);
    assert(childSibling.stage(Child) == 3 && child.stage(Child) == 1);

    BehaviorOracle reordered;
    reordered.allocated(1, 2, 0x1000, 0x2000, 8);
    reordered.childCreated(1, 2);
    reordered.executed(1, 2, 0x1000);
    assert(reordered.stage(Child) == 1); // No retroactive correlation.
    reordered.allocated(1, 2, 0x1000, 0x2000, 8);
    reordered.freed(2, 0x1800, 0x1900); // Conservative partial free.
    reordered.executed(1, 2, 0x1000);
    assert(reordered.stage(Child) == 1);

    BehaviorOracle bounded;
    bounded.childCreated(0, 2);
    bounded.childCreated(2, 2);
    bounded.allocated(0, 1, 0x1000, 0x2000, 1);
    assert(bounded.stage(Local) == 0 && bounded.stage(Child) == 0);
    bounded.allocated(1, 1, 0x1000, 0x2000, 1);
    bounded.allocated(1, 1, 0x3000, 0x4000, 1);
    bounded.executed(1, 1, 0x1000); // Evicted candidate.
    assert(bounded.stage(Local) == 1);
    bounded.executed(1, 1, 0x3000);
    assert(bounded.stage(Local) == 2);
    bounded.freed(1, 0x3000, 0x4000);
    assert(bounded.stage(Local) == 2); // Historical success remains evidence.
    BehaviorOracle parentReuse;
    parentReuse.childCreated(1, 2);
    parentReuse.allocated(1, 2, 0x1000, 0x2000, 8);
    auto parentExited = parentReuse;
    parentExited.processExited(1);
    parentExited.executed(1, 2, 0x1000);
    assert(parentExited.stage(Child) == 3); // Delayed child execution is valid.
    parentReuse.processExited(1);
    parentReuse.allocated(1, 2, 0x3000, 0x4000, 8);
    parentReuse.executed(1, 2, 0x3000);
    assert(parentReuse.stage(Child) != 3); // New allocation by a reused PID.
    std::cout << "BehaviorOracle: correlation, lifetime, fork isolation and bounds passed\n";
}
