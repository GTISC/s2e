///
/// Target-directed state scheduling for MalwareLab behavior objectives.
///

#include "BehaviorSearcher.h"

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <klee/util/ExprUtil.h>

#include <algorithm>
#include <iterator>
#include <random>
#include <sstream>
#include <tuple>
#include <utility>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(BehaviorSearcher, "Target-directed behavior searcher", "BehaviorSearcher", "ModuleExecutionDetector",
                  "MultiSearcher", "TranslationBlockCoverage");

bool BehaviorSearcher::parseConfig() {
    ConfigFile *cfg = s2e()->getConfig();
    bool ok = false;
    const auto goal = cfg->getString(getConfigKey() + ".behaviorGoal", "");
    m_behaviorGoal = parseBehaviorGoal(goal);
    if (!goal.empty() && m_behaviorGoal == BehaviorGoal::None) {
        getWarningsStream() << "BehaviorSearcher: unsupported behaviorGoal " << goal << "\n";
        return false;
    }
    m_moduleName = cfg->getString(getConfigKey() + ".moduleName", "", &ok);
    if (!ok || m_moduleName.empty()) {
        getWarningsStream() << "BehaviorSearcher: moduleName is required\n";
        return false;
    }

    const std::string key = getConfigKey() + ".distance";
    int count = cfg->getListSize(key, &ok);
    if (!ok || count <= 0) {
        getWarningsStream() << "BehaviorSearcher: distance must contain at least one range\n";
        return false;
    }

    for (int i = 0; i < count; ++i) {
        std::stringstream item;
        item << key << "[" << (i + 1) << "]";
        DistanceRange range;
        range.start = cfg->getInt(item.str() + "[1]", 0, &ok);
        if (!ok) {
            return false;
        }
        range.end = cfg->getInt(item.str() + "[2]", 0, &ok);
        if (!ok) {
            return false;
        }
        range.hops = cfg->getInt(item.str() + "[3]", 0, &ok);
        if (!ok || range.end < range.start) {
            getWarningsStream() << "BehaviorSearcher: invalid distance range " << hexval(range.start) << "-"
                                << hexval(range.end) << "\n";
            return false;
        }
        m_distances.push_back(range);
    }

    std::sort(m_distances.begin(), m_distances.end(), [](const DistanceRange &a, const DistanceRange &b) {
        return std::tie(a.start, a.end) < std::tie(b.start, b.end);
    });
    for (unsigned i = 1; i < m_distances.size(); ++i) {
        if (m_distances[i - 1].end >= m_distances[i].start) {
            getWarningsStream() << "BehaviorSearcher: distance ranges overlap\n";
            return false;
        }
    }

    // Distance alone cannot encode path semantics. For example, a zero-size
    // file can be fewer CFG hops from WriteFile while still being rejected by
    // ReadFile. Objectives can identify such edges; consume them while
    // scheduling as well as leaving EdgeKiller to enforce them at execution.
    const std::string avoidKey = getConfigKey() + ".avoidEdges";
    int avoidCount = cfg->getListSize(avoidKey, &ok);
    if (!ok) {
        // Keep compatibility with configurations generated before avoidEdges
        // was added to BehaviorSearcher.
        avoidCount = 0;
    }
    for (int i = 0; i < avoidCount; ++i) {
        std::stringstream item;
        item << avoidKey << "[" << (i + 1) << "]";
        uint64_t source = cfg->getInt(item.str() + "[1]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "BehaviorSearcher: invalid avoid-edge source\n";
            return false;
        }
        uint64_t destination = cfg->getInt(item.str() + "[2]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "BehaviorSearcher: invalid avoid-edge destination\n";
            return false;
        }
        m_avoidEdges.emplace(source, destination);
    }

    const std::string sourcesKey = getConfigKey() + ".symbolicSources";
    if (cfg->hasKey(sourcesKey)) {
        m_symbolicSources = cfg->getStringList(sourcesKey, ConfigFile::string_list(), &ok);
        if (!ok) {
            getWarningsStream() << "BehaviorSearcher: symbolicSources must be a list of strings\n";
            return false;
        }
    }

    const std::string randomSeedKey = getConfigKey() + ".randomSeed";
    int64_t randomSeed = cfg->hasKey(randomSeedKey) ? cfg->getInt(randomSeedKey, 0, &ok) : 0;
    ok = !cfg->hasKey(randomSeedKey) || ok;
    if (!ok || randomSeed < 0 || static_cast<uint64_t>(randomSeed) > std::numeric_limits<uint32_t>::max()) {
        getWarningsStream() << "BehaviorSearcher: randomSeed must be a 32-bit unsigned integer\n";
        return false;
    }
    m_randomSeed = randomSeed;

    const std::string epsilonKey = getConfigKey() + ".epsilon";
    m_epsilon = cfg->hasKey(epsilonKey) ? cfg->getDouble(epsilonKey, 0.0, &ok) : 0.0;
    ok = !cfg->hasKey(epsilonKey) || ok;
    if (!ok || m_epsilon < 0.0 || m_epsilon > 1.0) {
        getWarningsStream() << "BehaviorSearcher: epsilon must be between 0 and 1\n";
        return false;
    }
    const std::string plateauEpsilonKey = getConfigKey() + ".plateauEpsilon";
    m_plateauEpsilon = cfg->hasKey(plateauEpsilonKey) ? cfg->getDouble(plateauEpsilonKey, m_epsilon, &ok) : m_epsilon;
    ok = !cfg->hasKey(plateauEpsilonKey) || ok;
    if (!ok || m_plateauEpsilon < m_epsilon || m_plateauEpsilon > 1.0) {
        getWarningsStream() << "BehaviorSearcher: plateauEpsilon must be between epsilon and 1\n";
        return false;
    }

    const std::string forkGateKey = getConfigKey() + ".forkGateEnabled";
    m_forkGateEnabled = cfg->hasKey(forkGateKey) ? cfg->getBool(forkGateKey, false, &ok) : false;
    if (!ok) {
        getWarningsStream() << "BehaviorSearcher: forkGateEnabled must be a boolean\n";
        return false;
    }
    auto readProbability = [&](const char *name, double defaultValue, double &value) {
        const std::string optionKey = getConfigKey() + "." + name;
        value = cfg->hasKey(optionKey) ? cfg->getDouble(optionKey, defaultValue, &ok) : defaultValue;
        ok = !cfg->hasKey(optionKey) || ok;
        if (!ok || value < 0.0 || value > 1.0) {
            getWarningsStream() << "BehaviorSearcher: " << name << " must be between 0 and 1\n";
            return false;
        }
        return true;
    };
    if (!readProbability("unknownForkProbability", 0.0, m_unknownForkProbability) ||
        !readProbability("irrelevantForkProbability", 0.0, m_irrelevantForkProbability)) {
        return false;
    }

    auto readNonNegative = [&](const char *name, uint64_t defaultValue, uint64_t &value) {
        const std::string optionKey = getConfigKey() + "." + name;
        int64_t configured = cfg->hasKey(optionKey) ? cfg->getInt(optionKey, defaultValue, &ok) : defaultValue;
        ok = !cfg->hasKey(optionKey) || ok;
        if (!ok || configured < 0) {
            getWarningsStream() << "BehaviorSearcher: " << name << " must be non-negative\n";
            return false;
        }
        value = configured;
        return true;
    };
    if (!readNonNegative("distanceSlack", 1, m_distanceSlack) ||
        !readNonNegative("plateauSeconds", 0, m_plateauSeconds) ||
        !readNonNegative("quantumSeconds", 0, m_quantumSeconds) ||
        !readNonNegative("maxStallSeconds", 0, m_maxStallSeconds) ||
        !readNonNegative("hardStallSeconds", 0, m_hardStallSeconds) ||
        !readNonNegative("targetGraceSeconds", 0, m_targetGraceSeconds) ||
        !readNonNegative("cooldownSeconds", 1, m_cooldownSeconds)) {
        return false;
    }
    if ((m_quantumSeconds || m_maxStallSeconds || m_hardStallSeconds || m_targetGraceSeconds) && !m_cooldownSeconds) {
        getWarningsStream() << "BehaviorSearcher: cooldownSeconds must be positive when preemption is enabled\n";
        return false;
    }
    if (m_hardStallSeconds && m_maxStallSeconds && m_hardStallSeconds < m_maxStallSeconds) {
        getWarningsStream() << "BehaviorSearcher: hardStallSeconds must not be shorter than maxStallSeconds\n";
        return false;
    }
    return true;
}

void BehaviorSearcher::initialize() {
    if (!parseConfig()) {
        exit(-1);
    }

    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    m_searchers = s2e()->getPlugin<MultiSearcher>();
    m_coverage = s2e()->getPlugin<coverage::TranslationBlockCoverage>();
    if (m_behaviorGoal != BehaviorGoal::None) {
        m_regionMonitor = s2e()->getPlugin<ExecutableRegionMonitor>();
        if (!m_regionMonitor) {
            getWarningsStream() << "BehaviorSearcher: behaviorGoal requires ExecutableRegionMonitor\n";
            exit(-1);
        }
    }
    m_detector->onModuleTranslateBlockStart.connect(
        sigc::mem_fun(*this, &BehaviorSearcher::onModuleTranslateBlockStart));
    m_coverage->onNewBlockCovered.connect(sigc::mem_fun(*this, &BehaviorSearcher::onNewBlockCovered));
    s2e()->getCorePlugin()->onInitializationComplete.connect(
        sigc::mem_fun(*this, &BehaviorSearcher::onInitializationComplete));
    s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &BehaviorSearcher::onStateFork));
    s2e()->getCorePlugin()->onStateForkSelect.connect(sigc::mem_fun(*this, &BehaviorSearcher::onStateForkSelect));
    s2e()->getCorePlugin()->onStateSwitch.connect(sigc::mem_fun(*this, &BehaviorSearcher::onStateSwitch));
    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &BehaviorSearcher::onTimer));
    s2e()->getCorePlugin()->onEngineShutdown.connect(sigc::mem_fun(*this, &BehaviorSearcher::onEngineShutdown));

    if (!m_searchers->registerSearcher("BehaviorSearcher", this)) {
        getWarningsStream() << "BehaviorSearcher: could not register searcher\n";
        exit(-1);
    }

    getInfoStream() << "BehaviorSearcher: registered for " << m_moduleName << " with " << m_distances.size()
                    << " distance ranges and " << m_avoidEdges.size() << " avoid edges"
                    << " seed=" << m_randomSeed << " epsilon=" << m_epsilon << " plateauEpsilon=" << m_plateauEpsilon
                    << " distanceSlack=" << m_distanceSlack << " plateauSeconds=" << m_plateauSeconds
                    << " quantumSeconds=" << m_quantumSeconds << " maxStallSeconds=" << m_maxStallSeconds
                    << " hardStallSeconds=" << m_hardStallSeconds << " targetGraceSeconds=" << m_targetGraceSeconds
                    << " cooldownSeconds=" << m_cooldownSeconds << " forkGate=" << m_forkGateEnabled
                    << " symbolicSources=" << m_symbolicSources.size()
                    << " unknownForkProbability=" << m_unknownForkProbability
                    << " irrelevantForkProbability=" << m_irrelevantForkProbability << "\n";
}

void BehaviorSearcher::onInitializationComplete(S2EExecutionState *state) {
    // CUPASearcher initializes after this plugin and selects itself. Switch
    // only after every plugin has initialized so objective guidance remains
    // the final scheduling policy regardless of Lua plugin order.
    if (!m_searchers->selectSearcher("BehaviorSearcher")) {
        getWarningsStream(state) << "BehaviorSearcher: could not select searcher\n";
        exit(-1);
    }
    getInfoStream(state) << "BehaviorSearcher: active\n";
}

uint64_t BehaviorSearcher::getDistance(uint64_t nativePc) const {
    auto it = std::upper_bound(m_distances.begin(), m_distances.end(), nativePc,
                               [](uint64_t pc, const DistanceRange &range) { return pc < range.start; });
    if (it == m_distances.begin()) {
        return UNREACHABLE;
    }
    --it;
    return nativePc <= it->end ? it->hops : UNREACHABLE;
}

uint64_t BehaviorSearcher::getTargetKey(uint64_t nativePc) const {
    auto it = std::upper_bound(m_distances.begin(), m_distances.end(), nativePc,
                               [](uint64_t pc, const DistanceRange &range) { return pc < range.start; });
    if (it == m_distances.begin()) {
        return 0;
    }
    --it;
    return nativePc <= it->end && it->hops == 0 ? it->start : 0;
}

bool BehaviorSearcher::isAvoided(uint64_t source, uint64_t destination) const {
    return m_avoidEdges.find(std::make_pair(source, destination)) != m_avoidEdges.end();
}

bool BehaviorSearcher::conditionUsesObjectiveSource(const klee::ref<klee::Expr> &condition,
                                                    std::string &firstRead) const {
    if (m_symbolicSources.empty()) {
        return true;
    }

    std::vector<klee::ref<klee::ReadExpr>> reads;
    klee::findReads(condition, true, reads);
    for (const auto &read : reads) {
        const std::string &name = read->getUpdates()->getRoot()->getName();
        if (firstRead.empty()) {
            firstRead = name;
        }
        for (const auto &source : m_symbolicSources) {
            // BaseInstructions namespaces and sanitizes guest names before
            // KLEE sees them (e.g. GetFileSize.failure.0 becomes
            // v2_GetFileSize_failure_0_2). Match a complete API token rather
            // than requiring it at byte zero or accepting a loose substring.
            for (size_t offset = name.find(source); offset != std::string::npos;
                 offset = name.find(source, offset + 1)) {
                const size_t end = offset + source.size();
                const bool leftBoundary = offset == 0 || name[offset - 1] == '.' || name[offset - 1] == '_';
                const bool rightBoundary = end == name.size() || name[end] == '.' || name[end] == '_';
                if (leftBoundary && rightBoundary) {
                    return true;
                }
            }
        }
    }
    return false;
}

bool BehaviorSearcher::takeForkGateEscape(double probability, S2EExecutionState *state, uint64_t nativePc) const {
    if (probability <= 0.0) {
        return false;
    }
    if (probability >= 1.0) {
        return true;
    }

    // Reproducible for a fixed sample/objective, but different across states,
    // locations, instances, and repeated decisions at a looping branch.
    std::seed_seq seed{m_randomSeed,
                       static_cast<uint32_t>(s2e()->getCurrentInstanceIndex()),
                       static_cast<uint32_t>(state->getID()),
                       static_cast<uint32_t>(nativePc),
                       static_cast<uint32_t>(nativePc >> 32),
                       static_cast<uint32_t>(m_forkGateDecisions),
                       static_cast<uint32_t>(m_forkGateDecisions >> 32)};
    std::mt19937 random(seed);
    return std::uniform_real_distribution<double>(0.0, 1.0)(random) < probability;
}

void BehaviorSearcher::onStateForkSelect(S2EExecutionState *state, const klee::ref<klee::Expr> &condition,
                                         CorePlugin::StateForkPreference &preference) {
    if (!m_forkGateEnabled || preference != CorePlugin::StateForkPreference::NONE || !condition) {
        return;
    }

    auto module = m_detector->getCurrentDescriptor(state);
    if (!module || module->Name != m_moduleName) {
        return;
    }

    // The executor also emits this signal for symbolic memory and helper
    // forks. Gate only actual two-way program branches; treating an internal
    // engine choice as a CFG edge could make a required memory value vanish.
    uint64_t runtimeTargets[2];
    if (!state->getCurrentStaticBranchTargets(&runtimeTargets[0], &runtimeTargets[1])) {
        return;
    }

    uint64_t nativeSource = 0;
    if (!module->ToNativeBase(state->regs()->getPc(), nativeSource)) {
        return;
    }
    ++m_forkGateDecisions;

    struct SuccessorImpact {
        bool resolved = false;
        bool avoided = false;
        bool mapped = false;
        uint64_t nativeTarget = 0;
        uint64_t distance = UNREACHABLE;
        uint64_t targetKey = 0;
        bool unsaturatedTarget = false;
        bool valuable = false;
    } impacts[2];

    bool allResolved = true;
    bool allAvoided = true;
    bool anyMapped = false;
    bool anyValuable = false;
    for (unsigned i = 0; i < 2; ++i) {
        const uint64_t runtimeTarget = runtimeTargets[i];
        SuccessorImpact &impact = impacts[i];
        uint64_t nativeTarget = 0;
        if (!module->ToNativeBase(runtimeTarget, nativeTarget)) {
            allResolved = false;
            allAvoided = false;
            continue;
        }
        impact.resolved = true;
        impact.nativeTarget = nativeTarget;
        impact.avoided = isAvoided(nativeSource, nativeTarget);
        allAvoided &= impact.avoided;
        if (impact.avoided) {
            continue;
        }
        impact.distance = getDistance(nativeTarget);
        if (impact.distance == UNREACHABLE) {
            continue;
        }
        impact.mapped = true;
        anyMapped = true;
        impact.targetKey = getTargetKey(nativeTarget);
        impact.unsaturatedTarget =
            impact.targetKey &&
            (m_behaviorGoal != BehaviorGoal::None || m_reachedTargets.find(impact.targetKey) == m_reachedTargets.end());
        if (!impact.targetKey || impact.unsaturatedTarget) {
            impact.valuable = true;
            anyValuable = true;
        }
    }

    std::string firstRead;
    const bool usesObjectiveSource = conditionUsesObjectiveSource(condition, firstRead);
    getInfoStream(state) << "BehaviorSearcher: fork gate decision=" << m_forkGateDecisions
                         << " source=" << hexval(nativeSource) << " firstRead=" << firstRead
                         << " relevantSource=" << usesObjectiveSource
                         << " successor0=" << hexval(impacts[0].nativeTarget) << "/" << impacts[0].resolved << "/"
                         << impacts[0].avoided << "/" << impacts[0].mapped << "/" << impacts[0].distance << "/"
                         << hexval(impacts[0].targetKey) << " successor1=" << hexval(impacts[1].nativeTarget) << "/"
                         << impacts[1].resolved << "/" << impacts[1].avoided << "/" << impacts[1].mapped << "/"
                         << impacts[1].distance << "/" << hexval(impacts[1].targetKey) << "\n";

    if (allAvoided) {
        preference = CorePlugin::StateForkPreference::FOLLOW_CURRENT;
        ++m_forkGateDeniedCfg;
        getDebugStream(state) << "BehaviorSearcher: fork gate concretized branch " << hexval(nativeSource)
                              << " because both successors are avoided\n";
        return;
    }

    // A reached callsite is a prerequisite, not semantic completion. Static
    // distance maps commonly stop at allocation and omit the unpacked code.
    // Preserve continuations while this state holds a live prerequisite;
    // explicit avoid edges remain enforced by EdgeKiller. This conservative
    // fallback is bounded by the normal state/run budgets, not random escape.
    const unsigned stage = behaviorStage(state);
    if (stage && stage < behaviorGoalStages(m_behaviorGoal) && !impacts[0].avoided && !impacts[1].avoided) {
        ++m_forkGateAllowed;
        getInfoStream(state) << "BehaviorSearcher: semantic continuation goal=" << behaviorGoalName(m_behaviorGoal)
                             << " stage=" << stage << " source=" << hexval(nativeSource) << "\n";
        return;
    }

    if (!anyValuable) {
        const bool unknown = !allResolved || !anyMapped;
        const double probability = unknown ? m_unknownForkProbability : m_irrelevantForkProbability;
        if (takeForkGateEscape(probability, state, nativeSource)) {
            ++m_forkGateEscapes;
            getDebugStream(state) << "BehaviorSearcher: fork gate escape at " << hexval(nativeSource)
                                  << " reason=" << (unknown ? "unknown_cfg" : "saturated_target") << "\n";
            return;
        }
        preference = CorePlugin::StateForkPreference::FOLLOW_CURRENT;
        ++m_forkGateDeniedCfg;
        getDebugStream(state) << "BehaviorSearcher: fork gate concretized branch " << hexval(nativeSource)
                              << " reason=" << (unknown ? "no_target_reachable" : "target_saturated") << "\n";
        return;
    }

    const unsigned valuableCount =
        static_cast<unsigned>(impacts[0].valuable) + static_cast<unsigned>(impacts[1].valuable);
    if (valuableCount == 1) {
        const unsigned selected = impacts[0].valuable ? 0 : 1;
        const unsigned discarded = 1 - selected;
        // Select one outcome only when the sibling is explicitly disposable.
        // An absent distance entry may merely be an incomplete CFG, so that
        // case keeps normal forking. Avoid edges and already reached target
        // ranges are strong enough to skip the sibling solver/state.
        const bool discardedIsSaturatedTarget =
            impacts[discarded].mapped && impacts[discarded].targetKey && !impacts[discarded].unsaturatedTarget;
        if (impacts[discarded].resolved && (impacts[discarded].avoided || discardedIsSaturatedTarget)) {
            preference = selected == 0 ? CorePlugin::StateForkPreference::FORCE_TRUE
                                       : CorePlugin::StateForkPreference::FORCE_FALSE;
            ++m_forkGateForced;
            getDebugStream(state) << "BehaviorSearcher: fork gate selected successor" << selected << " at "
                                  << hexval(nativeSource) << " and skipped an "
                                  << (impacts[discarded].avoided ? "avoided" : "saturated") << " sibling\n";
            return;
        }
    }

    // Provenance is not a veto when the branch itself proves useful. An API
    // omitted from objective.symbolize may still be a prerequisite whose
    // return selects the only target-reachable successor. Compare successor
    // impact first; use the configured source roots only when the (possibly
    // coarse) CFG gives both successors the same rank.
    const bool differentImpact =
        impacts[0].resolved != impacts[1].resolved || impacts[0].avoided != impacts[1].avoided ||
        impacts[0].mapped != impacts[1].mapped || impacts[0].distance != impacts[1].distance ||
        impacts[0].targetKey != impacts[1].targetKey || impacts[0].unsaturatedTarget != impacts[1].unsaturatedTarget;
    if (differentImpact) {
        ++m_forkGateAllowed;
        getDebugStream(state) << "BehaviorSearcher: fork gate admitted branch " << hexval(nativeSource)
                              << " because successors have different target impact\n";
        return;
    }

    if (!usesObjectiveSource) {
        if (takeForkGateEscape(m_irrelevantForkProbability, state, nativeSource)) {
            ++m_forkGateEscapes;
            getDebugStream(state) << "BehaviorSearcher: fork gate source escape at " << hexval(nativeSource)
                                  << " firstRead=" << firstRead << "\n";
            return;
        }
        preference = CorePlugin::StateForkPreference::FOLLOW_CURRENT;
        ++m_forkGateDeniedSource;
        getDebugStream(state) << "BehaviorSearcher: fork gate concretized branch " << hexval(nativeSource)
                              << " because condition source " << firstRead << " is outside the objective\n";
        return;
    }

    ++m_forkGateAllowed;
}

uint64_t BehaviorSearcher::effectiveDistance(const StateInfo &info) const {
    return info.locationKnown ? info.distance : info.bestDistance;
}

bool BehaviorSearcher::isCoolingDown(const StateInfo &info) const {
    return info.cooldownUntilTick > m_timerTicks;
}

unsigned BehaviorSearcher::behaviorStage(S2EExecutionState *state) const {
    return m_regionMonitor ? m_regionMonitor->behaviorStage(state, m_behaviorGoal) : 0;
}

bool BehaviorSearcher::isTargetSaturated(S2EExecutionState *state, const StateInfo &info) const {
    if (m_behaviorGoal != BehaviorGoal::None) {
        return behaviorStage(state) == behaviorGoalStages(m_behaviorGoal);
    }
    if (info.frontierTargetKey) {
        return m_reachedTargets.find(info.frontierTargetKey) != m_reachedTargets.end();
    }
    return info.targetReached;
}

bool BehaviorSearcher::hasUnsaturatedAlternative(S2EExecutionState *current) const {
    for (const auto &entry : m_states) {
        if (entry.first == current || isCoolingDown(entry.second) || isTargetSaturated(entry.first, entry.second)) {
            continue;
        }
        if (effectiveDistance(entry.second) != UNREACHABLE || behaviorStage(entry.first)) {
            return true;
        }
    }
    return false;
}

double BehaviorSearcher::getCurrentEpsilon() const {
    if (m_behaviorGoal != BehaviorGoal::None) {
        return 0.0;
    }
    if (m_plateauSeconds && m_timerTicks - m_lastGlobalProgressTick >= m_plateauSeconds) {
        return m_plateauEpsilon;
    }
    return m_epsilon;
}

bool BehaviorSearcher::hasRunnableAlternative(S2EExecutionState *current, uint64_t allowedRegression,
                                              bool allowAnyDistance) const {
    auto currentIt = m_states.find(current);
    if (currentIt == m_states.end()) {
        return false;
    }

    uint64_t currentDistance = effectiveDistance(currentIt->second);
    uint64_t distanceLimit = UNREACHABLE;
    if (!allowAnyDistance && currentDistance != UNREACHABLE && allowedRegression < UNREACHABLE - currentDistance) {
        distanceLimit = currentDistance + allowedRegression;
    }

    for (const auto &entry : m_states) {
        if (entry.first == current || isCoolingDown(entry.second)) {
            continue;
        }
        uint64_t distance = effectiveDistance(entry.second);
        if (distance == UNREACHABLE && !behaviorStage(entry.first)) {
            continue;
        }
        if (allowAnyDistance || currentDistance == UNREACHABLE || distance <= distanceLimit ||
            (behaviorStage(entry.first) && behaviorStage(entry.first) >= behaviorStage(current))) {
            return true;
        }
    }
    return false;
}

bool BehaviorSearcher::isBetter(S2EExecutionState *candidate, const StateInfo &candidateInfo,
                                S2EExecutionState *current, const StateInfo &currentInfo) const {
    uint64_t candidateDistance = effectiveDistance(candidateInfo);
    uint64_t currentDistance = effectiveDistance(currentInfo);
    const unsigned candidateStage = behaviorStage(candidate);
    const unsigned currentStage = behaviorStage(current);
    bool candidateReachable = candidateDistance != UNREACHABLE || candidateStage;
    bool currentReachable = currentDistance != UNREACHABLE || currentStage;

    // A target is an achievement, not a reason to monopolize the rest of the
    // objective. Prefer a reachable state that has not already achieved (or is
    // not about to revisit) a target, then use proximity. A direct successor
    // to an unseen zero-distance range remains best, so target acquisition is
    // never sacrificed for breadth.
    return std::make_tuple(!candidateReachable, isCoolingDown(candidateInfo),
                           isTargetSaturated(candidate, candidateInfo), -static_cast<int>(candidateStage),
                           candidateDistance, -static_cast<int64_t>(candidateInfo.newBlocks),
                           candidate->constraints().size(), candidateInfo.selections, candidate->getID()) <
           std::make_tuple(!currentReachable, isCoolingDown(currentInfo), isTargetSaturated(current, currentInfo),
                           -static_cast<int>(currentStage), currentDistance,
                           -static_cast<int64_t>(currentInfo.newBlocks), current->constraints().size(),
                           currentInfo.selections, current->getID());
}

void BehaviorSearcher::onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                   const ModuleDescriptor &module, TranslationBlock *tb, uint64_t pc) {
    if (module.Name != m_moduleName) {
        return;
    }

    uint64_t nativePc = 0;
    if (!module.ToNativeBase(pc, nativePc)) {
        getWarningsStream(state) << "BehaviorSearcher: could not translate " << hexval(pc) << "\n";
        return;
    }
    signal->connect(sigc::bind(sigc::mem_fun(*this, &BehaviorSearcher::onBlockExecute), nativePc));
}

void BehaviorSearcher::onBlockExecute(S2EExecutionState *state, uint64_t pc, uint64_t nativePc) {
    auto it = m_states.find(state);
    if (it == m_states.end()) {
        return;
    }

    StateInfo &info = it->second;
    const unsigned stage = behaviorStage(state);
    if (stage > info.behaviorStage) {
        info.lastProgressTick = m_timerTicks;
        m_lastGlobalProgressTick = m_timerTicks;
        if (stage == behaviorGoalStages(m_behaviorGoal)) {
            info.targetReachedTick = m_timerTicks;
        }
    }
    info.behaviorStage = stage;
    uint64_t previousBest = info.bestDistance;
    info.distance = getDistance(nativePc);
    info.locationKnown = true;
    info.frontierTargetKey = 0;
    if (info.distance < info.bestDistance) {
        info.bestDistance = info.distance;
    }

    if (info.bestDistance < previousBest) {
        info.lastProgressTick = m_timerTicks;
        m_lastGlobalProgressTick = m_timerTicks;
        getDebugStream(state) << "BehaviorSearcher: distance=" << info.bestDistance << " at " << hexval(nativePc)
                              << "\n";
    }
    if (info.distance == 0) {
        uint64_t targetKey = getTargetKey(nativePc);
        if (!info.targetReached) {
            info.targetReached = true;
            info.targetReachedTick = m_timerTicks;
        }
        if (targetKey && m_reachedTargets.insert(targetKey).second) {
            m_lastGlobalProgressTick = m_timerTicks;
            getInfoStream(state) << "BehaviorSearcher: new target range reached at " << hexval(targetKey) << " via "
                                 << hexval(nativePc) << " uniqueTargets=" << m_reachedTargets.size() << "\n";
        }
    }
}

void BehaviorSearcher::onStateFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                                   const std::vector<klee::ref<klee::Expr>> &newConditions) {
    if (newStates.size() != 2) {
        return;
    }
    auto module = m_detector->getCurrentDescriptor(state);
    if (!module || module->Name != m_moduleName) {
        return;
    }

    uint64_t runtimeTargets[2];
    if (!state->getStaticBranchTargets(&runtimeTargets[0], &runtimeTargets[1])) {
        return;
    }

    uint64_t nativeSource = 0;
    if (!module->ToNativeBase(state->regs()->getPc(), nativeSource)) {
        return;
    }

    StateInfo inherited;
    auto pendingParent = m_pendingForkStates.find(state);
    if (pendingParent != m_pendingForkStates.end()) {
        // Several symbolic branches may execute in one translated block
        // before KLEE calls update(). Preserve guidance learned at the prior
        // branch while keeping all of it outside the live scheduler state.
        inherited = pendingParent->second;
    } else {
        auto parent = m_states.find(state);
        if (parent != m_states.end()) {
            inherited = parent->second;
        }
    }
    for (unsigned i = 0; i < 2; ++i) {
        uint64_t nativeTarget = 0;
        if (!module->ToNativeBase(runtimeTargets[i], nativeTarget)) {
            continue;
        }
        StateInfo child = inherited;
        const bool avoided = isAvoided(nativeSource, nativeTarget);
        child.distance = avoided ? UNREACHABLE : getDistance(nativeTarget);
        child.locationKnown = true;
        child.bestDistance = std::min(child.bestDistance, child.distance);
        child.selections = 0;
        child.frontierTargetKey = avoided ? 0 : getTargetKey(nativeTarget);
        child.lastProgressTick = m_timerTicks;
        child.cooldownUntilTick = 0;
        m_pendingForkStates[newStates[i]] = child;
        getDebugStream(newStates[i]) << "BehaviorSearcher: fork successor=" << hexval(nativeTarget)
                                     << " distance=" << child.distance << " avoided=" << avoided << "\n";
    }

    // S2E normally lets the current state continue after a fork. That state
    // may run through another block (or an expensive call) and improve its
    // apparent CFG distance before selectState is consulted. Yield at the
    // actual decision point when another successor already ranks better.
    S2EExecutionState *preferred = state;
    for (auto candidate : newStates) {
        auto candidateIt = m_pendingForkStates.find(candidate);
        auto preferredIt = m_pendingForkStates.find(preferred);
        if (candidateIt != m_pendingForkStates.end() && preferredIt != m_pendingForkStates.end() &&
            isBetter(candidate, candidateIt->second, preferred, preferredIt->second)) {
            preferred = candidate;
        }
    }
    if (preferred != state) {
        getDebugStream(state) << "BehaviorSearcher: yielding to better fork successor state " << preferred->getID()
                              << "\n";
        state->yield();
    }
}

void BehaviorSearcher::onNewBlockCovered(S2EExecutionState *state) {
    m_lastGlobalProgressTick = m_timerTicks;
    auto it = m_states.find(state);
    if (it != m_states.end()) {
        ++it->second.newBlocks;
        it->second.lastProgressTick = m_timerTicks;
    }
    auto pending = m_pendingForkStates.find(state);
    if (pending != m_pendingForkStates.end()) {
        ++pending->second.newBlocks;
        pending->second.lastProgressTick = m_timerTicks;
    }
}

void BehaviorSearcher::onStateSwitch(S2EExecutionState *current, S2EExecutionState *next) {
    if (next != m_currentState) {
        m_selectedAtTick = m_timerTicks;
    }
    m_currentState = next;
}

void BehaviorSearcher::onTimer() {
    ++m_timerTicks;
    // Objective launches normally end when the host terminates QEMU at the
    // budget. That path does not reliably emit onEngineShutdown, so checkpoint
    // the counters while the VM is alive. The result parser intentionally
    // consumes the last complete line.
    if (m_timerTicks % 30 == 0) {
        logStats();
    }
    if (!m_currentState || m_currentState->isYielded() || m_states.size() < 2) {
        return;
    }

    auto current = m_states.find(m_currentState);
    if (current == m_states.end()) {
        return;
    }

    uint64_t noProgressSeconds = m_timerTicks - current->second.lastProgressTick;
    const bool completed = m_behaviorGoal == BehaviorGoal::None ? current->second.targetReached
                                                                : isTargetSaturated(m_currentState, current->second);
    bool targetGraceExpired =
        m_targetGraceSeconds && completed && m_timerTicks - current->second.targetReachedTick >= m_targetGraceSeconds;
    bool hardStalled = m_hardStallSeconds && noProgressSeconds >= m_hardStallSeconds;
    bool stalled = m_maxStallSeconds && noProgressSeconds >= m_maxStallSeconds;
    bool quantumExpired = m_quantumSeconds && m_timerTicks - m_selectedAtTick >= m_quantumSeconds;
    if (!targetGraceExpired && !hardStalled && !stalled && !quantumExpired) {
        return;
    }

    // Regular time sharing must not sacrifice distance. A soft stall may use
    // the configured near-frontier slack. Only the longer hard-stall deadline
    // admits an arbitrary reachable state, preventing a slow API path from
    // consuming the entire run without making short budgets thrash.
    bool targetYield = targetGraceExpired && hasUnsaturatedAlternative(m_currentState);
    bool hardStallYield = hardStalled && hasRunnableAlternative(m_currentState, 0, true);
    bool stallYield = stalled && hasRunnableAlternative(m_currentState, m_distanceSlack, false);
    bool quantumYield = quantumExpired && hasRunnableAlternative(m_currentState, 0, false);
    if (!targetYield && !hardStallYield && !stallYield && !quantumYield) {
        return;
    }

    current->second.cooldownUntilTick = m_timerTicks + m_cooldownSeconds;
    if (targetYield) {
        ++m_targetYields;
        getDebugStream(m_currentState) << "BehaviorSearcher: target-saturated state " << m_currentState->getID()
                                       << " yielded after " << m_targetGraceSeconds
                                       << " seconds to an unreached-target state\n";
    } else if (hardStallYield) {
        ++m_hardStallYields;
        current->second.lastProgressTick = m_timerTicks;
        getDebugStream(m_currentState) << "BehaviorSearcher: hard-stalled state " << m_currentState->getID()
                                       << " yielded after " << m_hardStallSeconds << " seconds without progress\n";
    } else if (stallYield) {
        ++m_stallYields;
        current->second.lastProgressTick = m_timerTicks;
        getDebugStream(m_currentState) << "BehaviorSearcher: stalled state " << m_currentState->getID()
                                       << " yielded after " << m_maxStallSeconds << " seconds without progress\n";
    } else {
        ++m_quantumYields;
        getDebugStream(m_currentState) << "BehaviorSearcher: quantum expired for state " << m_currentState->getID()
                                       << "\n";
    }
    // onTimer is dispatched from QEMU's timer loop, which does not catch the
    // CpuExitException raised by S2EExecutionState::yield(). Marking the state
    // yielded is sufficient here: cpu_exec checks this flag before re-entering
    // the guest and returns to the executor's normal state-switch path.
    m_currentState->setYieldState(true);
}

void BehaviorSearcher::logStats() {
    getInfoStream() << "BehaviorSearcher: stats selections=" << m_selectionCalls
                    << " randomSelections=" << m_randomSelections << " quantumYields=" << m_quantumYields
                    << " stallYields=" << m_stallYields << " hardStallYields=" << m_hardStallYields
                    << " targetYields=" << m_targetYields << " uniqueTargets=" << m_reachedTargets.size()
                    << " forkGateDecisions=" << m_forkGateDecisions << " forkGateAllowed=" << m_forkGateAllowed
                    << " forkGateDeniedCfg=" << m_forkGateDeniedCfg
                    << " forkGateDeniedSource=" << m_forkGateDeniedSource << " forkGateEscapes=" << m_forkGateEscapes
                    << " forkGateForced=" << m_forkGateForced << "\n";
}

void BehaviorSearcher::onEngineShutdown() {
    logStats();
}

klee::ExecutionState &BehaviorSearcher::selectState() {
    assert(!m_states.empty());
    auto best = m_states.begin();
    for (auto it = std::next(m_states.begin()); it != m_states.end(); ++it) {
        if (isBetter(it->first, it->second, best->first, best->second)) {
            best = it;
        }
    }

    ++m_selectionCalls;
    double epsilon = getCurrentEpsilon();
    if (epsilon > 0.0 && m_states.size() > 1) {
        // Derive each decision from the configured seed, instance index, and
        // selection counter. Unlike a copied mt19937 stream, this gives forked
        // S2E instances distinct but reproducible choices.
        std::seed_seq seed{m_randomSeed, static_cast<uint32_t>(s2e()->getCurrentInstanceIndex()),
                           static_cast<uint32_t>(m_selectionCalls), static_cast<uint32_t>(m_selectionCalls >> 32)};
        std::mt19937 random(seed);
        std::uniform_real_distribution<double> probability(0.0, 1.0);
        if (probability(random) < epsilon) {
            std::vector<States::iterator> candidates;
            uint64_t bestDistance = effectiveDistance(best->second);
            uint64_t distanceLimit = UNREACHABLE;
            if (bestDistance != UNREACHABLE && m_distanceSlack < UNREACHABLE - bestDistance) {
                distanceLimit = bestDistance + m_distanceSlack;
            }
            for (auto it = m_states.begin(); it != m_states.end(); ++it) {
                uint64_t distance = effectiveDistance(it->second);
                if (distance == UNREACHABLE || (isCoolingDown(it->second) && !isCoolingDown(best->second))) {
                    continue;
                }
                if (isTargetSaturated(it->first, it->second) && !isTargetSaturated(best->first, best->second)) {
                    continue;
                }
                if (bestDistance == UNREACHABLE || distance <= distanceLimit) {
                    candidates.push_back(it);
                }
            }
            if (candidates.size() > 1) {
                std::uniform_int_distribution<size_t> choice(0, candidates.size() - 1);
                best = candidates[choice(random)];
                ++m_randomSelections;
                getDebugStream(best->first) << "BehaviorSearcher: bounded-random selection epsilon=" << epsilon
                                            << " candidates=" << candidates.size() << "\n";
            }
        }
    }

    ++best->second.selections;
    if (m_currentState != best->first) {
        m_selectedAtTick = m_timerTicks;
    }
    m_currentState = best->first;
    if (m_lastSelected != best->first) {
        getDebugStream(best->first) << "BehaviorSearcher: selected state " << best->first->getID()
                                    << " distance=" << effectiveDistance(best->second)
                                    << " newBlocks=" << best->second.newBlocks
                                    << " targetSaturated=" << isTargetSaturated(best->first, best->second)
                                    << " behaviorStage=" << behaviorStage(best->first)
                                    << " constraints=" << best->first->constraints().size() << "\n";
        m_lastSelected = best->first;
    }
    return *best->first;
}

void BehaviorSearcher::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                              const klee::StateSet &removedStates) {
    StateInfo inherited;
    auto currentState = dynamic_cast<S2EExecutionState *>(current);
    auto currentIt = m_states.find(currentState);
    if (currentIt != m_states.end()) {
        inherited = currentIt->second;
        inherited.selections = 0;
    }

    // onStateFork may run before S2E knows which successors survive. Keep its
    // scores as metadata only, and attach them here through KLEE's ordinary
    // searcher lifecycle. This avoids retaining live scheduler entries for a
    // successor that was terminated during fork handling.
    auto pendingCurrent = m_pendingForkStates.find(currentState);
    if (currentIt != m_states.end() && pendingCurrent != m_pendingForkStates.end()) {
        currentIt->second = pendingCurrent->second;
        m_pendingForkStates.erase(pendingCurrent);
    }

    for (auto state : addedStates) {
        auto s2eState = static_cast<S2EExecutionState *>(state);
        auto pending = m_pendingForkStates.find(s2eState);
        if (pending != m_pendingForkStates.end()) {
            m_states[s2eState] = pending->second;
            m_pendingForkStates.erase(pending);
        } else {
            inherited.lastProgressTick = m_timerTicks;
            m_states.emplace(s2eState, inherited);
        }
    }
    for (auto state : removedStates) {
        auto s2eState = static_cast<S2EExecutionState *>(state);
        m_states.erase(s2eState);
        m_pendingForkStates.erase(s2eState);
        if (m_lastSelected == s2eState) {
            m_lastSelected = nullptr;
        }
        if (m_currentState == s2eState) {
            m_currentState = nullptr;
        }
    }
}

bool BehaviorSearcher::empty() {
    return m_states.empty();
}

} // namespace plugins
} // namespace s2e
