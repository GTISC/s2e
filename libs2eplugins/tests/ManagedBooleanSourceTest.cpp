#include <cassert>
#include <cstring>
#include "../src/s2e/Plugins/Analyzers/ManagedBindings.h"
using namespace s2e::plugins;
int main() {
    ManagedPolicy p{
        std::string(32, 'a'), std::string(36, 'b'), std::string(64, 'c'), {{0x06000001, {std::string(64, 'd'), {0}}}}};
    ManagedCommand c = {};
    c.version = 1;
    c.pid = 42;
    c.processStart = 123;
    std::strcpy(c.session, p.session.c_str());
    std::strcpy(c.plan, p.plan.c_str());
    ManagedBindings b;
    c.operation = ManagedStart;
    assert(b.accept(c, 42, p).empty());
    c.sequence++;
    c.operation = ManagedRegister;
    c.module = 8;
    c.function = 7;
    c.token = 0x06000001;
    c.start = 0x1000;
    c.size = 100;
    std::strcpy(c.mvid, p.mvid.c_str());
    std::strcpy(c.original, std::string(64, 'd').c_str());
    std::strcpy(c.instrumented, std::string(64, 'e').c_str());
    c.probeCount = 1;
    assert(b.accept(c, 42, p).empty());
    c.sequence++;
    c.operation = ManagedBooleanSource;
    c.start = 0x2000;
    c.size = 4;
    assert(b.accept(c, 42, p) == "invalid_boolean_source"); // disabled policy
    p.booleanSourceToken = c.token;
    assert(b.accept(c, 42, p) == "invalid_boolean_source"); // no getter entry
    c.operation = ManagedProbe;
    assert(b.accept(c, 42, p).empty());
    c.sequence++;
    c.operation = ManagedBooleanSource;
    auto wrong = c;
    wrong.offset = 1;
    assert(b.accept(wrong, 42, p) == "invalid_boolean_source");
    wrong = c;
    wrong.token++;
    assert(b.accept(wrong, 42, p) == "invalid_boolean_source");
    wrong = c;
    wrong.start = 0xffffffff;
    assert(b.accept(wrong, 42, p) == "invalid_boolean_source");
    ManagedBindings sibling = b;
    assert(b.accept(c, 42, p).empty());
    assert(!sibling.sourceConsumed && b.sourceConsumed);
    c.sequence++;
    assert(b.accept(c, 42, p) == "invalid_boolean_source"); // at most once
    c.operation = ManagedEnd;
    assert(b.accept(c, 42, p).empty());
    c.sequence++;
    c.operation = ManagedBooleanSource;
    assert(b.accept(c, 42, p) == "inactive_process");
}
