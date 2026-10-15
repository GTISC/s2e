#ifndef KLEE_CONCOLIC_SLICE_H
#define KLEE_CONCOLIC_SLICE_H

#include <klee/Constraints.h>
#include <klee/util/Assignment.h>
#include <string>

namespace klee {

struct ConcolicSliceStats {
    size_t constraints = 0, selectedConstraints = 0;
    size_t arrays = 0, selectedArrays = 0, seedBytes = 0;
    const char *reason = "not_attempted";
};

// Build a complete, verified model by solving the array-level transitive
// closure of added conditions. Disconnected arrays retain their seed values.
// Failure/unknown is never UNSAT: the caller must use its ordinary full solve.
// Neither the path constraints nor the original seed assignment are modified.
bool tryConcolicSlice(Solver &solver, const ConstraintManager &constraints,
                      const std::vector<ref<Expr>> &added, const ArrayVec &objects,
                      const Assignment &seed, std::vector<std::vector<unsigned char>> &values,
                      ConcolicSliceStats &stats);

} // namespace klee
#endif
