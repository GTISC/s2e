#ifndef S2E_WINDOWS_INPUT_OBSERVATION_H
#define S2E_WINDOWS_INPUT_OBSERVATION_H

#include <cstdint>
#include <limits>

namespace s2e { namespace plugins { namespace input_observation {

// These are observations of completed calls, never models of pending I/O.
inline bool bufferExtent(uint32_t count, uint32_t requested, bool completed, bool overlapped = false) {
    return completed && !overlapped && count && count <= requested && count <= 4096;
}

inline bool environmentExtent(uint32_t returned, uint32_t capacity, unsigned width, uint32_t &bytes,
                              uint32_t &requested) {
    if ((width != 1 && width != 2) || !returned || returned >= capacity ||
        capacity > std::numeric_limits<uint32_t>::max() / width || returned > 256 / width) return false;
    bytes = returned * width;
    requested = capacity * width;
    return true;
}

} } }
#endif
