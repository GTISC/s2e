#include <klee/ConcolicSlice.h>
#include <klee/util/ExprUtil.h>
#include <set>

namespace klee {
namespace {
using Arrays = std::set<ArrayPtr, ArrayLt>;
Arrays arraysIn(const ref<Expr> &expression) {
    std::vector<ref<ReadExpr>> reads;
    findReads(expression, true, reads); // Includes symbolic indices and update lists.
    Arrays arrays;
    for (const auto &read : reads) {
        auto array = read->getUpdates()->getRoot();
        if (!array->isConstantArray()) arrays.insert(array);
    }
    return arrays;
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
    // Bound the extra dependency analysis, independently of the solver budget.
    if (objects.size() > 4096 || constraints.size() > 8192 || added.empty()) {
        stats.reason = "analysis_limit_or_no_condition";
        return false;
    }
    Arrays closure;
    for (const auto &condition : added) {
        auto roots = arraysIn(condition);
        closure.insert(roots.begin(), roots.end());
    }
    struct Item { ref<Expr> expression; Arrays arrays; bool selected = false; };
    std::vector<Item> items;
    for (auto it = constraints.begin(); it != constraints.end(); ++it) {
        auto expression = constraints.toExpr(*it);
        items.push_back({expression, arraysIn(expression), false});
    }
    std::map<ArrayPtr, std::vector<size_t>, ArrayLt> dependents;
    for (size_t i = 0; i < items.size(); ++i) {
        if (items[i].arrays.empty()) items[i].selected = true;
        for (const auto &array : items[i].arrays) dependents[array].push_back(i);
    }
    std::vector<ArrayPtr> pending(closure.begin(), closure.end());
    for (size_t i = 0; i < pending.size(); ++i) {
        for (size_t index : dependents[pending[i]]) {
            auto &item = items[index];
            if (item.selected) continue;
            item.selected = true;
            for (const auto &array : item.arrays)
                if (closure.insert(array).second) pending.push_back(array);
        }
    }

    ArrayVec selected;
    Arrays available(objects.begin(), objects.end());
    for (const auto &array : closure) {
        if (!available.count(array)) {
            stats.reason = "unregistered_dependency";
            return false;
        }
    }
    for (const auto &array : objects) {
        if (closure.count(array)) selected.push_back(array);
        else {
            auto binding = seed.bindings.find(array);
            if (binding == seed.bindings.end() || binding->second.size() != array->getSize()) {
                stats.reason = "incomplete_seed";
                return false;
            }
            stats.seedBytes += binding->second.size();
        }
    }
    std::vector<ref<Expr>> required;
    for (const auto &item : items) if (item.selected) required.push_back(item.expression);
    stats.selectedConstraints = required.size();
    stats.selectedArrays = selected.size();
    if (selected.size() == objects.size()) {
        stats.reason = "fully_connected";
        return false;
    }
    ConstraintManager reduced(required);
    std::vector<std::vector<unsigned char>> solved;
    if (!selected.empty() &&
        !solver.getInitialValues(Query(reduced, ConstantExpr::create(0, Expr::Bool)), selected, solved)) {
        stats.reason = "slice_solver_failed_or_unsat";
        return false;
    }
    if (solved.size() != selected.size()) {
        stats.reason = "incomplete_model";
        return false;
    }
    auto candidate = Assignment::create(true); // Missing bindings must remain unknown, never become zero.
    size_t index = 0;
    for (const auto &array : objects) {
        const auto &bytes = closure.count(array) ? solved[index++] : seed.bindings.at(array);
        if (bytes.size() != array->getSize()) {
            stats.reason = "incomplete_model";
            return false;
        }
        candidate->add(array, bytes);
    }
    for (const auto &item : items) {
        if (!candidate->evaluate(item.expression)->isTrue()) {
            stats.reason = "full_constraint_validation_failed";
            return false;
        }
    }
    // Independently check raw added predicates, including any simplified away
    // by ConstraintManager. Only a model satisfying all original facts is used.
    for (const auto &condition : added) {
        if (!candidate->evaluate(condition)->isTrue()) {
            stats.reason = "added_condition_validation_failed";
            return false;
        }
    }
    for (const auto &array : objects) values.push_back(candidate->bindings.at(array));
    stats.reason = "verified_seed_completion";
    return true;
}
} // namespace klee
