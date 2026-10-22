#ifndef S2E_MEMORY_MAP_RANGE_H
#define S2E_MEMORY_MAP_RANGE_H

#include <cstdint>
#include <limits>

namespace s2e {
namespace plugins {

// Guest notifications are input, including failed calls and malformed ranges.
// Produce a nonempty half-open interval without wrapping the rounding arithmetic.
inline bool memoryMapPageRange(uint64_t address, uint64_t size, uint64_t pageSize,
                               uint64_t &start, uint64_t &end) {
    if (!size || !pageSize || (pageSize & (pageSize - 1))) return false;
    const uint64_t maximum = std::numeric_limits<uint64_t>::max();
    if (size > maximum - address) return false;
    const uint64_t limit = address + size;
    if (pageSize - 1 > maximum - limit) return false;
    start = address & ~(pageSize - 1);
    end = (limit + pageSize - 1) & ~(pageSize - 1);
    return start < end;
}

} // namespace plugins
} // namespace s2e
#endif
