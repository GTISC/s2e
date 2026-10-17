#include <klee/ConcolicSlice.h>
#include <klee/SolverImpl.h>
#include <klee/util/ExprUtil.h>
#include <set>

namespace klee {
namespace {
struct Bytes {
    bool whole = false;
    std::set<uint64_t> offsets;
    bool add(const Bytes &other) {
        if (whole) return false;
        if (other.whole) { whole = true; offsets.clear(); return true; }
        bool changed = false;
        for (auto offset : other.offsets) changed |= offsets.insert(offset).second;
        return changed;
    }
    bool intersects(const Bytes &other) const {
        if (whole || other.whole) return true;
        for (auto offset : offsets) if (other.offsets.count(offset)) return true;
        return false;
    }
};
using Dependencies = std::map<ArrayPtr, Bytes, ArrayLt>;
Dependencies readsIn(const ref<Expr> &expression) {
    std::vector<ref<ReadExpr>> reads;
    findReads(expression, true, reads); // Includes indices and update-list dependencies.
    Dependencies result;
    for (const auto &read : reads) {
        auto array = read->getUpdates()->getRoot();
        if (array->isConstantArray()) continue;
        Bytes bytes;
        auto index = dyn_cast<ConstantExpr>(read->getIndex());
        // Unknown indices and out-of-bounds reads retain the entire root.
        // Full model validation still rejects values outside the seed extent.
        if (!index || index->getZExtValue() >= array->getSize()) bytes.whole = true;
        else bytes.offsets.insert(index->getZExtValue());
        result[array].add(bytes);
    }
    return result;
}
}

bool tryConcolicSlice(Solver &solver, const ConstraintManager &constraints,
                      const std::vector<ref<Expr>> &added, const ArrayVec &objects,
                      const Assignment &seed, std::vector<std::vector<unsigned char>> &values,
                      ConcolicSliceStats &stats) {
    stats = ConcolicSliceStats();
    stats.constraints = constraints.size();
    stats.arrays = objects.size();
    values.clear();
    if (objects.size() > 4096 || constraints.size() > 8192 || added.empty()) {
        stats.reason = "analysis_limit_or_no_condition";
        return false;
    }
    Dependencies closure;
    std::vector<ArrayPtr> pending;
    std::set<ArrayPtr, ArrayLt> queued;
    auto extend = [&](const Dependencies &dependencies) {
        for (const auto &entry : dependencies) {
            if (closure[entry.first].add(entry.second) && queued.insert(entry.first).second)
                pending.push_back(entry.first);
        }
    };
    for (const auto &condition : added) extend(readsIn(condition));
    struct Item { ref<Expr> expression; Dependencies dependencies; bool selected = false; };
    std::vector<Item> items;
    std::map<ArrayPtr, std::vector<size_t>, ArrayLt> dependents;
    for (auto it = constraints.begin(); it != constraints.end(); ++it) {
        auto expression = constraints.toExpr(*it);
        auto dependencies = readsIn(expression);
        items.push_back({expression, dependencies, dependencies.empty()});
        for (const auto &entry : dependencies) dependents[entry.first].push_back(items.size()-1);
    }
    // A root may need another visit when a connected constraint adds bytes.
    // Bound rescans independently of SMT time on highly connected inputs.
    size_t visits = 0;
    for (size_t i = 0; i < pending.size(); ++i) {
        auto array = pending[i];
        queued.erase(array);
        for (auto index : dependents[array]) {
            if (++visits > 1000000) { stats.reason = "dependency_visit_limit"; return false; }
            auto &item = items[index];
            if (item.selected || !closure.at(array).intersects(item.dependencies.at(array))) continue;
            item.selected = true;
            extend(item.dependencies);
        }
    }
    std::set<ArrayPtr, ArrayLt> available(objects.begin(), objects.end());
    for (const auto &entry : closure) if (!available.count(entry.first)) {
        stats.reason = "unregistered_dependency";
        return false;
    }
    ArrayVec selected;
    for (const auto &array : objects) {
        if (!array->getSize()) { stats.reason = "zero_sized_object"; return false; }
        stats.bytes += array->getSize();
        auto found = closure.find(array);
        size_t count = found == closure.end() ? 0 : found->second.whole ? array->getSize() : found->second.offsets.size();
        stats.selectedBytes += count;
        if (count) selected.push_back(array);
        if (count < array->getSize()) {
            auto binding = seed.bindings.find(array);
            if (binding == seed.bindings.end() || binding->second.size() != array->getSize()) {
                stats.reason = "incomplete_seed";
                return false;
            }
            stats.seedBytes += array->getSize() - count;
        }
    }
    std::vector<ref<Expr>> required;
    for (const auto &item : items) if (item.selected) required.push_back(item.expression);
    stats.selectedConstraints = required.size();
    stats.selectedArrays = selected.size();
    if (stats.selectedBytes == stats.bytes) { stats.reason = "fully_connected"; return false; }
    ConstraintManager reduced(required);
    std::vector<std::vector<unsigned char>> solved;
    if (!selected.empty()) {
        // Preserve the solver's success/hasSolution distinction. UNSAT of a
        // subset proves the full path infeasible; a timeout or failure does not.
        bool hasSolution = false;
        bool success = solver.impl->computeInitialValues(
            Query(reduced, ConstantExpr::create(0, Expr::Bool)), selected, solved, hasSolution);
        if (!success) { stats.reason = "slice_solver_failed"; return false; }
        if (!hasSolution) { stats.unsat = true; stats.reason = "slice_unsat"; return false; }
    }
    if (solved.size() != selected.size()) { stats.reason = "incomplete_model"; return false; }
    auto candidate = Assignment::create(true);
    size_t index = 0;
    for (const auto &array : objects) {
        auto found = closure.find(array);
        if (found == closure.end()) { candidate->add(array, seed.bindings.at(array)); continue; }
        const auto &bytes = solved[index++];
        if (bytes.size() != array->getSize()) { stats.reason = "incomplete_model"; return false; }
        if (found->second.whole || found->second.offsets.size() == array->getSize()) candidate->add(array, bytes);
        else {
            auto completed = seed.bindings.at(array);
            for (auto offset : found->second.offsets) completed[offset] = bytes[offset];
            candidate->add(array, completed);
        }
    }
    for (const auto &item : items) if (!candidate->evaluate(item.expression)->isTrue()) {
        stats.reason = "full_constraint_validation_failed";
        return false;
    }
    for (const auto &condition : added) if (!candidate->evaluate(condition)->isTrue()) {
        stats.reason = "added_condition_validation_failed";
        return false;
    }
    for (const auto &array : objects) values.push_back(candidate->bindings.at(array));
    stats.reason = "verified_seed_completion";
    return true;
}
} // namespace klee
