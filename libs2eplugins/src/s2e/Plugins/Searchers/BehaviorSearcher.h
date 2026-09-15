///
/// Target-directed state scheduling for MalwareLab behavior objectives.
///

#ifndef S2E_PLUGINS_BEHAVIORSEARCHER_H
#define S2E_PLUGINS_BEHAVIORSEARCHER_H

#include <klee/Searcher.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Analyzers/ExecutableRegionMonitor.h>
#include <s2e/Plugins/Coverage/TranslationBlockCoverage.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/Searchers/MultiSearcher.h>
#include <s2e/S2EExecutionState.h>

#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace s2e {
namespace plugins {

class BehaviorSearcher : public Plugin, public klee::Searcher {
    S2E_PLUGIN

private:
    static constexpr uint64_t UNREACHABLE = std::numeric_limits<uint64_t>::max();

    struct DistanceRange {
        uint64_t start;
        uint64_t end;
        uint64_t hops;
    };

    struct StateInfo {
        uint64_t distance = UNREACHABLE;
        uint64_t bestDistance = UNREACHABLE;
        uint64_t newBlocks = 0;
        uint64_t selections = 0;
        uint64_t lastProgressTick = 0;
        uint64_t targetReachedTick = 0;
        uint64_t cooldownUntilTick = 0;
        // A zero-distance successor that has not executed yet. This lets the
        // scheduler distinguish a new target from a target another state has
        // already reached before either successor runs its first block.
        uint64_t frontierTargetKey = 0;
        bool locationKnown = false;
        bool targetReached = false;
        unsigned behaviorStage = 0;
    };

    using States = std::map<S2EExecutionState *, StateInfo>;

    MultiSearcher *m_searchers = nullptr;
    ModuleExecutionDetector *m_detector = nullptr;
    coverage::TranslationBlockCoverage *m_coverage = nullptr;
    ExecutableRegionMonitor *m_regionMonitor = nullptr;
    BehaviorGoal m_behaviorGoal = BehaviorGoal::None;
    std::string m_moduleName;
    std::vector<DistanceRange> m_distances;
    std::set<std::pair<uint64_t, uint64_t>> m_avoidEdges;
    std::vector<std::string> m_symbolicSources;
    std::set<uint64_t> m_reachedTargets;
    States m_states;
    States m_pendingForkStates;
    S2EExecutionState *m_lastSelected = nullptr;
    S2EExecutionState *m_currentState = nullptr;

    uint32_t m_randomSeed = 0;
    double m_epsilon = 0.0;
    double m_plateauEpsilon = 0.0;
    bool m_forkGateEnabled = false;
    double m_unknownForkProbability = 0.0;
    double m_irrelevantForkProbability = 0.0;
    uint64_t m_distanceSlack = 1;
    uint64_t m_plateauSeconds = 0;
    uint64_t m_quantumSeconds = 0;
    uint64_t m_maxStallSeconds = 0;
    uint64_t m_hardStallSeconds = 0;
    uint64_t m_cooldownSeconds = 1;
    uint64_t m_targetGraceSeconds = 0;

    uint64_t m_timerTicks = 0;
    uint64_t m_lastGlobalProgressTick = 0;
    uint64_t m_selectedAtTick = 0;
    uint64_t m_selectionCalls = 0;
    uint64_t m_randomSelections = 0;
    uint64_t m_quantumYields = 0;
    uint64_t m_stallYields = 0;
    uint64_t m_hardStallYields = 0;
    uint64_t m_targetYields = 0;
    uint64_t m_forkGateDecisions = 0;
    uint64_t m_forkGateAllowed = 0;
    uint64_t m_forkGateDeniedCfg = 0;
    uint64_t m_forkGateDeniedSource = 0;
    uint64_t m_forkGateEscapes = 0;
    uint64_t m_forkGateForced = 0;

    bool parseConfig();
    void onInitializationComplete(S2EExecutionState *state);
    uint64_t getDistance(uint64_t nativePc) const;
    uint64_t getTargetKey(uint64_t nativePc) const;
    bool isAvoided(uint64_t source, uint64_t destination) const;
    bool conditionUsesObjectiveSource(const klee::ref<klee::Expr> &condition, std::string &firstRead) const;
    bool takeForkGateEscape(double probability, S2EExecutionState *state, uint64_t nativePc) const;
    uint64_t effectiveDistance(const StateInfo &info) const;
    bool isCoolingDown(const StateInfo &info) const;
    unsigned behaviorStage(S2EExecutionState *state) const;
    bool isTargetSaturated(S2EExecutionState *state, const StateInfo &info) const;
    bool hasUnsaturatedAlternative(S2EExecutionState *current) const;
    bool hasRunnableAlternative(S2EExecutionState *current, uint64_t allowedRegression, bool allowAnyDistance) const;
    double getCurrentEpsilon() const;
    bool isBetter(S2EExecutionState *candidate, const StateInfo &candidateInfo, S2EExecutionState *current,
                  const StateInfo &currentInfo) const;

    void onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, const ModuleDescriptor &module,
                                     TranslationBlock *tb, uint64_t pc);
    void onBlockExecute(S2EExecutionState *state, uint64_t pc, uint64_t nativePc);
    void onStateFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                     const std::vector<klee::ref<klee::Expr>> &newConditions);
    void onStateForkSelect(S2EExecutionState *state, const klee::ref<klee::Expr> &condition,
                           CorePlugin::StateForkPreference &preference);
    void onNewBlockCovered(S2EExecutionState *state);
    void onStateSwitch(S2EExecutionState *current, S2EExecutionState *next);
    void onTimer();
    void logStats();
    void onEngineShutdown();

public:
    BehaviorSearcher(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();
    virtual klee::ExecutionState &selectState();
    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);
    virtual bool empty();
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_BEHAVIORSEARCHER_H
