#include <s2e/Plugins/WindowsInputObservation.h>
#include <cassert>
#include <cstdint>
using namespace s2e::plugins::input_observation;

int main() {
    assert(bufferExtent(4, 4, true));
    assert(!bufferExtent(0, 4, true));
    assert(!bufferExtent(5, 4, true));
    assert(!bufferExtent(4097, 8192, true));
    assert(!bufferExtent(4, 4, false));
    assert(!bufferExtent(4, 4, true, true));
    uint32_t bytes = 0, requested = 0;
    assert(environmentExtent(3, 4, 2, bytes, requested));
    assert(bytes == 6 && requested == 8);
    assert(!environmentExtent(0, 4, 1, bytes, requested));
    assert(!environmentExtent(4, 4, 1, bytes, requested));
    assert(!environmentExtent(5, 4, 1, bytes, requested));
    assert(!environmentExtent(129, 256, 2, bytes, requested));
    assert(!environmentExtent(1, UINT32_MAX, 2, bytes, requested));
    assert(!environmentExtent(1, 4, 0, bytes, requested));
}
