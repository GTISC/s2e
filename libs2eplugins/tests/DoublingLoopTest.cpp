#include <s2e/Plugins/DoublingLoop.h>
#include <cassert>
#include <random>
using namespace s2e::plugins::doubling_loop;
int main() {
    std::mt19937 rng(17);
    // Compare the closed form with original iterations, including overflow,
    // zero seeds and counts on both sides of the x86 word width.
    for (unsigned n = 2; n < 512; ++n) for (unsigned j = 0; j < 128; ++j) {
        uint32_t seed = rng(), eax = seed, edx = 0;
        for (unsigned i = 1; i < n; ++i) { eax *= 2; edx = eax; }
        auto result = summarize(seed, n);
        assert(result.eax == eax && result.edx == edx && result.scratch == shift(seed, n-2));
        assert(result.skipped == n - 1);
    }
    assert(summarize(1, 1000000000).eax == 0);
    Witness w;
    std::array<uint32_t, 8> r = {2, 9, 2, 3, 1000, 1100, 0, 7};
    assert(w.observe(r, 100, 100));
    r[0] = 4; r[2] = 4; assert(w.observe(r, 99, 100));
    r[1]++; r[0] = 8; r[2] = 8; assert(!w.observe(r, 98, 100));
    assert(w.rejected && !w.observe(r, 100, 100));
    Witness mid; assert(!mid.observe(r, 99, 100));
    Witness wrong; r[6] = 1; assert(!wrong.observe(r, 100, 100));
    Witness repeated; r[6] = 0; assert(repeated.observe(r, 100, 100));
    assert(!repeated.observe(r, 100, 100));
}
