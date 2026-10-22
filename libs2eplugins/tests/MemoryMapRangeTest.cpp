#include <cassert>
#include <cstdint>
#include <limits>
#include <s2e/Plugins/OSMonitors/Support/MemoryMapRange.h>

using s2e::plugins::memoryMapPageRange;

int main() {
    uint64_t start = 7, end = 9;
    assert(!memoryMapPageRange(0x1000, 0, 4096, start, end));
    assert(start == 7 && end == 9);
    assert(memoryMapPageRange(1, 2, 4096, start, end));
    assert(start == 0 && end == 4096);
    assert(memoryMapPageRange(0x1000, 4096, 4096, start, end));
    assert(start == 0x1000 && end == 0x2000);
    assert(memoryMapPageRange(0x1fff, 2, 4096, start, end));
    assert(start == 0x1000 && end == 0x3000);
    // A 32-bit top page must not become an empty interval through mask truncation.
    assert(memoryMapPageRange(0xfffff000, 4096, 4096, start, end));
    assert(start == 0xfffff000 && end == 0x100000000ull);
    const auto maximum = std::numeric_limits<uint64_t>::max();
    assert(!memoryMapPageRange(maximum - 3, 8, 4096, start, end));
    assert(!memoryMapPageRange(maximum - 3, 1, 4096, start, end));
    assert(!memoryMapPageRange(1, 2, 0, start, end));
    assert(!memoryMapPageRange(1, 2, 3000, start, end));
    assert(memoryMapPageRange(maximum - 8191, 4096, 4096, start, end));
    assert(start == maximum - 8191 && end == maximum - 4095);
}
