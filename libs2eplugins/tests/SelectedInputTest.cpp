#include "s2e/Plugins/SelectedInput.h"
#include <cassert>
using s2e::plugins::SelectedInput;
int main() {
    SelectedInput p; p.api="ReadFile";p.path="C:\\seed.bin";p.scope="root";p.seed="SAFE";p.offsets={0};
    assert(p.valid() && p.accepts("SAFE",0));assert(!p.accepts("DIFF",0));
    p.offsets={0,0};assert(!p.valid());p.offsets={4};assert(!p.valid());p.offsets={0};
    p.api="GetEnvironmentVariableA";assert(p.accepts("SAFE",0));p.seed="S\nFE";assert(!p.accepts(p.seed,0));
    p.api="GetEnvironmentVariableW";p.seed=std::string("S\0A\0",4);assert(p.accepts(p.seed,0));
    p.offsets={1};assert(!p.accepts(p.seed,0));
    p.api="RegQueryValueExW";p.seed=std::string("S\0A\0\0\0",6);p.offsets={0};assert(p.accepts(p.seed,1));
    p.offsets={4};assert(!p.accepts(p.seed,1));p.offsets={0};assert(!p.accepts(p.seed,3));
    p.seed=std::string("\1\0\0\0",4);assert(p.accepts(p.seed,4));
    p.readIndex=9;assert(!p.valid());p.readIndex=1;p.api="GetCommandLineA";assert(!p.valid());
}
