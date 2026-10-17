#ifndef S2E_DOUBLING_LOOP_H
#define S2E_DOUBLING_LOOP_H
#include <array>
#include <cstdint>

namespace s2e { namespace plugins { namespace doubling_loop {
// At the original dec [ebp-4], EAX has already doubled and EDX holds the
// same value; the saved stack slot holds the pre-doubling value. Resume at that same instruction with one iteration left.
// This preserves the original tail's flags and never changes an instruction.
inline uint32_t shift(uint32_t value, uint32_t count) {
    return count >= 32 ? 0 : uint32_t(value << count);
}
struct Result { uint32_t eax, edx, scratch, skipped; };
inline Result summarize(uint32_t eax, uint32_t count) {
    const uint32_t skipped = count - 1;
    return {shift(eax, skipped), shift(eax, skipped), shift(eax, skipped - 1), skipped};
}
struct Witness {
    std::array<uint32_t, 8> previous = {};
    uint32_t lastCount = 0, seen = 0;
    bool rejected = false, done = false;
    // x86 register order: eax ecx edx ebx esp ebp esi edi.
    bool observe(const std::array<uint32_t, 8> &r, uint32_t count, uint32_t initial) {
        if (rejected || done) return false;
        bool valid = r[6] == 0 && r[0] == r[2];
        if (!seen) valid = valid && count == initial;
        else {
            valid = valid && count + 1 == lastCount && r[0] == uint32_t(previous[0] * 2)
                    && r[2] == r[0];
            for (unsigned i : {1u, 3u, 4u, 5u, 6u, 7u}) valid = valid && r[i] == previous[i];
        }
        if (!valid) { rejected = true; return false; }
        previous = r; lastCount = count; ++seen;
        return true;
    }
};
} } }
#endif
