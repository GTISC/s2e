#include <cassert>
#include <cstring>
#include <iostream>
#include "../src/s2e/Plugins/Analyzers/ManagedBindings.h"
using namespace s2e::plugins;
int main() {
    ManagedPolicy p{std::string(32, 'a'),
                    std::string(36, 'b'),
                    std::string(64, 'c'),
                    {{0x06000001, {std::string(64, 'd'), {188, 198, 208}}}}};
    ManagedCommand c = {};
    c.version = 1;
    c.operation = ManagedStart;
    c.pid = 42;
    c.processStart = 123;
    std::strcpy(c.session, p.session.c_str());
    std::strcpy(c.plan, p.plan.c_str());
    ManagedBindings b;
    auto invalid = c;
    invalid.version = 2;
    assert(b.accept(invalid, 42, p) == "wire_identity_or_sequence");
    invalid = c;
    std::memset(invalid.session, 'a', sizeof(invalid.session));
    assert(b.accept(invalid, 42, p) == "wire_identity_or_sequence");
    invalid = c;
    invalid.session[0] = 'f';
    assert(b.accept(invalid, 42, p) == "session_or_plan");
    invalid = c;
    invalid.processStart = 0;
    assert(b.accept(invalid, 42, p) == "duplicate_or_invalid_start");
    assert(b.accept(c, 41, p) == "wire_identity_or_sequence");
    assert(b.accept(c, 42, p).empty());
    c.sequence++;
    c.operation = ManagedProbe;
    c.function = 7;
    c.offset = 188;
    assert(b.accept(c, 42, p) == "unpublished_or_unplanned_probe");
    c.operation = ManagedRegister;
    c.module = 8;
    c.token = 0x06000001;
    c.start = 0x1000;
    c.size = 100;
    std::strcpy(c.mvid, p.mvid.c_str());
    std::strcpy(c.original, p.methods.begin()->second.original.c_str());
    std::strcpy(c.instrumented, std::string(64, 'e').c_str());
    c.probeCount = 3;
    c.probes[0] = 188;
    c.probes[1] = 198;
    c.probes[2] = 208;
    invalid = c;
    invalid.original[0] = 'f';
    assert(b.accept(invalid, 42, p) == "invalid_binding");
    invalid = c;
    invalid.mvid[0] = 'f';
    assert(b.accept(invalid, 42, p) == "invalid_binding");
    invalid = c;
    invalid.start = 0xffffffff;
    assert(b.accept(invalid, 42, p) == "invalid_binding");
    invalid = c;
    invalid.probeCount = 257;
    assert(b.accept(invalid, 42, p) == "invalid_binding");
    invalid = c;
    invalid.probes[1] = 199;
    assert(b.accept(invalid, 42, p) == "invalid_binding");
    invalid = c;
    invalid.processStart++;
    assert(b.accept(invalid, 42, p) == "inactive_process");
    assert(b.accept(c, 42, p).empty());
    assert(b.contains(0x1000) && b.contains(0x1063) && !b.contains(0x1064));
    ManagedBindings childA = b, childB = b;
    // Even a new function ID cannot republish a token or alias a live range.
    invalid = c;
    invalid.sequence++;
    invalid.function++;
    assert(b.accept(invalid, 42, p) == "invalid_binding");
    p.methods[0x06000002] = p.methods.at(0x06000001);
    invalid.token = 0x06000002;
    assert(b.accept(invalid, 42, p) == "overlapping_binding");
    // Ending one fork cannot invalidate a sibling or the parent.
    auto ended = b;
    invalid.operation = ManagedEnd;
    assert(ended.accept(invalid, 42, p).empty());
    assert(!ended.contains(0x1000) && childA.contains(0x1000) && b.contains(0x1000));
    c.sequence++;
    c.operation = ManagedProbe;
    assert(childA.accept(c, 42, p).empty());
    assert(childB.observed.empty() && b.observed.empty());
    c.operation = ManagedInvalidateModule;
    assert(childB.accept(c, 42, p).empty());
    assert(!childB.contains(0x1000) && childA.contains(0x1000));
    c.sequence++;
    c.operation = ManagedProbe;
    assert(childB.accept(c, 42, p) == "unpublished_or_unplanned_probe");
    c.offset = 999;
    assert(childA.accept(c, 42, p) == "unpublished_or_unplanned_probe");
    c.offset = 198;
    assert(childA.accept(c, 42, p).empty());
    assert(childA.observed[7].size() == 2);
    c.sequence++;
    c.operation = ManagedInvalidateFunction;
    assert(childA.accept(c, 42, p).empty());
    c.sequence++;
    c.operation = ManagedRegister;
    assert(childA.accept(c, 42, p) == "invalid_binding");
    c.operation = ManagedEnd;
    assert(childA.accept(c, 42, p).empty());
    c.sequence++;
    c.operation = ManagedProbe;
    assert(childA.accept(c, 42, p) == "inactive_process");
    auto overflow = b;
    overflow.next = UINT32_MAX;
    c.sequence = UINT32_MAX;
    assert(overflow.accept(c, 42, p) == "wire_identity_or_sequence");
    std::cout << "Managed identity, publication, range, fork isolation, invalidation and shutdown controls passed\n";
}
