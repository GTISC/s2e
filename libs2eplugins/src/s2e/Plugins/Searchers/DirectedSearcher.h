#ifndef S2E_PLUGINS_DIRECTEDSEARCHER_H
#define S2E_PLUGINS_DIRECTEDSEARCHER_H

#include <klee/Searcher.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/Plugins/Searchers/MultiSearcher.h>
#include <s2e/Plugins/StaticAnalysis/ControlFlowGraph.h>
#include <s2e/Plugins/Support/KeyValueStore.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Utils.h>

#include "Common.h"

#include <chrono>
#include <memory>
#include <random>
#include <unordered_map>

namespace s2e {
namespace plugins {

class DirectedSearcher : public Plugin, public klee::Searcher {
    S2E_PLUGIN

private:
    std::map<S2EExecutionState *, double> m_branchDistances;
    std::unordered_map<uint64_t, std::vector<uint64_t>> m_cfg;
    S2EExecutionState *m_currentState;
    std::default_random_engine m_randomEngine;

public:
    DirectedSearcher(S2E *s2e);

    void initialize();
    void loadCFG(const std::string &cfgPath) override;
    void calculateBranchDistance(S2EExecutionState *state) override;

    S2EExecutionState *selectState() override;
    void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                const klee::StateSet &removedStates) override;
    bool empty() const override;

    void setActive(S2EExecutionState *state, bool active) override;
    void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) override;
};

} // namespace plugins
} // namespace s2e

#endif
