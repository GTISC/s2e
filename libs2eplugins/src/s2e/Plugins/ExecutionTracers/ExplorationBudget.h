#ifndef S2E_EXPLORATION_BUDGET_H
#define S2E_EXPLORATION_BUDGET_H

#include <algorithm>
#include <cstdint>
#include <set>
#include <string>

namespace s2e { namespace plugins {

// One policy per engine instance/run, not per OS process. Novelty is shared
// across sibling states: cloning, duplicate paths and renamed files earn no credit.
class ExplorationBudget {
public:
    uint64_t initial = 300, maximum = 1800, extension = 180, window = 90, minimum = 120;
    uint64_t soft = 300, lastEvidence = 0, lastStrong = 0, strongEpoch = 0, grantedEpoch = 0;
    uint64_t firstStop = UINT64_MAX;
    bool ready = false, softExpired = false, quietReported = false;
    std::set<std::string> seen;

    void start() {
        if (ready) return;
        ready = true;
        soft = initial;
    }
    bool progress(uint64_t elapsed, const std::string &key, bool strong) {
        if (!ready || seen.size() >= 256 || !seen.insert(key).second) return false;
        lastEvidence = elapsed;
        quietReported = false;
        if (strong) { lastStrong = elapsed; ++strongEpoch; }
        return true;
    }
    // quiet is only a recommendation: incomplete observation cannot justify
    // killing early. A known minimum allowance and all hard caps remain intact.
    bool quiet(uint64_t elapsed) {
        if (!ready || quietReported || elapsed < minimum || elapsed < lastEvidence + window) return false;
        quietReported = true;
        firstStop = std::min(firstStop, elapsed);
        return true;
    }
    enum Decision { Wait, Extend, SoftStop, HardStop };
    Decision tick(uint64_t elapsed) {
        if (!ready) return Wait;
        if (elapsed >= maximum) return HardStop;
        if (softExpired || elapsed < soft) return Wait;
        if (strongEpoch > grantedEpoch && elapsed >= lastStrong && elapsed - lastStrong <= window) {
            soft = std::min(maximum, elapsed + extension);
            grantedEpoch = strongEpoch;
            return Extend;
        }
        softExpired = true;
        firstStop = std::min(firstStop, elapsed);
        return SoftStop;
    }
};

// Fixed, bounded vocabulary. Event keys never include PIDs, file names or
// untrusted strings, so repetition cannot purchase unbounded execution time.
inline std::string budgetKey(const std::string &kind, uint64_t depth) {
    return kind + ":depth" + std::to_string(std::min<uint64_t>(depth, 4));
}

} }
#endif
