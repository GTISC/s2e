#include "s2e/Plugins/Analyzers/ExecutableThreadPolicy.h"

#include <cassert>

using s2e::plugins::admitExecutionThread;

int main() {
    assert(admitExecutionThread(false, false, false, false));
    assert(admitExecutionThread(true, true, true, true));
    assert(admitExecutionThread(true, false, true, true));
    assert(!admitExecutionThread(true, false, false, true));
    assert(!admitExecutionThread(true, false, true, false));
    return 0;
}
