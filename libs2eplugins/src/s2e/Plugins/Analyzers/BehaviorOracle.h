/// State-local, object-correlated completion evidence for execution goals.
#ifndef S2E_PLUGINS_BEHAVIORORACLE_H
#define S2E_PLUGINS_BEHAVIORORACLE_H

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace s2e {
namespace plugins {

enum class BehaviorGoal { None, AllocatedCodeExecution, ChildRemoteExecution };

inline BehaviorGoal parseBehaviorGoal(const std::string &name) {
    if (name == "allocated_code_execution") {
        return BehaviorGoal::AllocatedCodeExecution;
    }
    if (name == "child_remote_execution") {
        return BehaviorGoal::ChildRemoteExecution;
    }
    return BehaviorGoal::None;
}

inline const char *behaviorGoalName(BehaviorGoal goal) {
    if (goal == BehaviorGoal::None) {
        return "";
    }
    return goal == BehaviorGoal::AllocatedCodeExecution ? "allocated_code_execution" : "child_remote_execution";
}

inline unsigned behaviorGoalStages(BehaviorGoal goal) {
    if (goal == BehaviorGoal::None) {
        return 0;
    }
    return goal == BehaviorGoal::AllocatedCodeExecution ? 2 : 3;
}

class BehaviorOracle {
    struct Allocation {
        uint64_t sourcePid, pid, start, end;
        bool child;
    };
    std::map<uint64_t, uint64_t> m_children;
    std::vector<Allocation> m_allocations;
    bool m_allocatedComplete = false;
    bool m_childComplete = false;
    unsigned m_allocatedStage = 0;
    unsigned m_childStage = 0;

    void refresh() {
        m_allocatedStage = m_allocatedComplete ? 2 : !m_allocations.empty();
        m_childStage = m_childComplete ? 3 : !m_children.empty();
        if (!m_childComplete &&
            std::any_of(m_allocations.begin(), m_allocations.end(), [](const Allocation &a) { return a.child; })) {
            m_childStage = 2;
        }
    }

public:
    // Copying this object on an S2E fork preserves shared prefixes while
    // preventing events on mutually exclusive siblings from being combined.
    unsigned stage(BehaviorGoal goal) const {
        if (goal == BehaviorGoal::None) {
            return 0;
        }
        return goal == BehaviorGoal::AllocatedCodeExecution ? m_allocatedStage : m_childStage;
    }

    void childCreated(uint64_t parent, uint64_t pid) {
        if (!parent || !pid || parent == pid) {
            return;
        }
        processExited(pid); // PID reuse starts a new object lifetime.
        m_children[pid] = parent;
        refresh();
    }

    void allocated(uint64_t sourcePid, uint64_t pid, uint64_t start, uint64_t end, unsigned maxRegions) {
        if (!sourcePid || !pid || start >= end || !maxRegions) {
            return;
        }
        freed(pid, start, end);
        if (m_allocations.size() >= maxRegions) {
            m_allocations.erase(m_allocations.begin());
        }
        auto child = m_children.find(pid);
        m_allocations.push_back(
            {sourcePid, pid, start, end, sourcePid != pid && child != m_children.end() && child->second == sourcePid});
        refresh();
    }

    void freed(uint64_t pid, uint64_t start, uint64_t end) {
        // Partial frees conservatively discard the candidate. We never use a
        // stale allocation to certify execution after its object was freed.
        m_allocations.erase(std::remove_if(m_allocations.begin(), m_allocations.end(),
                                           [&](const Allocation &a) {
                                               return a.pid == pid && (end > start ? start < a.end && a.start < end
                                                                                   : a.start <= start && start < a.end);
                                           }),
                            m_allocations.end());
        refresh();
    }

    void processExited(uint64_t pid) {
        m_children.erase(pid);
        // An allocation made before its parent exits remains valid evidence,
        // but a reused parent PID cannot create new parent/child candidates.
        for (auto it = m_children.begin(); it != m_children.end();) {
            if (it->second == pid) {
                it = m_children.erase(it);
            } else {
                ++it;
            }
        }
        m_allocations.erase(std::remove_if(m_allocations.begin(), m_allocations.end(),
                                           [&](const Allocation &a) { return a.pid == pid; }),
                            m_allocations.end());
        refresh();
    }

    // Called only after the monitor validates actual instruction execution,
    // analysis provenance, and the absence of a registered image at this PC.
    void executed(uint64_t sourcePid, uint64_t pid, uint64_t pc) {
        auto allocation = std::find_if(m_allocations.begin(), m_allocations.end(), [&](const Allocation &a) {
            return a.pid == pid && a.sourcePid == sourcePid && a.start <= pc && pc < a.end;
        });
        if (allocation == m_allocations.end()) {
            return;
        }
        m_allocatedComplete = true;
        m_childComplete |= allocation->child;
        refresh();
    }
};

} // namespace plugins
} // namespace s2e
#endif
