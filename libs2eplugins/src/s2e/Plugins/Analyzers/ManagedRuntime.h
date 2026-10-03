#ifndef S2E_MANAGED_RUNTIME_H
#define S2E_MANAGED_RUNTIME_H
#include <fstream>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include "ManagedBindings.h"

namespace s2e {
struct ModuleDescriptor;
namespace plugins {
class OSMonitor;
class ProcessExecutionDetector;
class ManagedRuntime : public Plugin, public IPluginInvoker {
    S2E_PLUGIN
    OSMonitor *m_monitor;
    ProcessExecutionDetector *m_processes;
    ManagedPolicy m_policy;
    std::ofstream m_log;
    unsigned m_maxForks;
    bool m_boundForks;
    void onProcessUnload(S2EExecutionState *, uint64_t, uint64_t, uint64_t);
    void onModuleUnload(S2EExecutionState *, const ModuleDescriptor &);
    void onStateKill(S2EExecutionState *);
    void onForkDecide(S2EExecutionState *, const klee::ref<klee::Expr> &, bool &);
    void onFork(S2EExecutionState *, const std::vector<S2EExecutionState *> &,
                const std::vector<klee::ref<klee::Expr>> &);

public:
    ManagedRuntime(S2E *s2e) : Plugin(s2e) {
    }
    void initialize();
    void handleOpcodeInvocation(S2EExecutionState *, uint64_t, uint64_t);
};
} // namespace plugins
} // namespace s2e
#endif
