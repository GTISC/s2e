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
class IDirectedSearcher {
public:
    virtual ~IDirectedSearcher() {
    }
    virtual S2EExecutionState *selectState() = 0;
    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates) = 0;

    virtual void setActive(S2EExecutionState *state, bool active) = 0;
};
class DirectedSearcher : public Plugin, public klee::Searcher, public IPluginInvoker {
    S2E_PLUGIN
public:
    typedef llvm::DenseSet<S2EExecutionState *> States;

private:
    std::map<S2EExecutionState *, double> m_branchDistances;
    std::unordered_map<uint64_t, std::vector<uint64_t>> m_cfg;
    S2EExecutionState *m_currentState;
    std::default_random_engine m_randomEngine;

    States m_activeStates;
    // S2EExecutionState *m_currentState;
    // uint64_t m_nextMergeGroupId;

    IDirectedSearcher *m_selector;

    bool m_debug;

public:
    DirectedSearcher(S2E *s2e) : Plugin(s2e) {
    }
    void initialize();
    void loadCFG(const std::string &cfgPath);
    void calculateBranchDistance(S2EExecutionState *state);

    virtual klee::ExecutionState &selectState();
    virtual void update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                        const klee::StateSet &removedStates);
    virtual bool empty();

    void setActive(S2EExecutionState *state, bool active);

private:
    void suspend(S2EExecutionState *state);
    void resume(S2EExecutionState *state);
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

class DirectedSearcherState : public PluginState {
private:
    uint64_t m_groupId;

public:
    DirectedSearcherState();
    virtual ~DirectedSearcherState();
    virtual DirectedSearcherState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    void setGroupId(uint64_t groupId) {
        m_groupId = groupId;
    }

    uint64_t getGroupId() const {
        return m_groupId;
    }
};
} // namespace plugins
} // namespace s2e

#endif
