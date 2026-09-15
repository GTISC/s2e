///
/// Monitor executable behavior originating in virtual allocations.
///

#ifndef S2E_PLUGINS_EXECUTABLEREGIONMONITOR_H
#define S2E_PLUGINS_EXECUTABLEREGIONMONITOR_H

#include "BehaviorOracle.h"

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>

#include <string>

namespace s2e {
namespace plugins {

class ProcessExecutionDetector;
class ModuleMap;

class ExecutableRegionMonitor : public Plugin, public IPluginInvoker {
    S2E_PLUGIN

    WindowsMonitor *m_windows = nullptr;
    ProcessExecutionDetector *m_process = nullptr;
    ModuleMap *m_modules = nullptr;

    std::string m_moduleName;
    bool m_dumpOnExecute = true;
    bool m_trackChildProcesses = true;
    bool m_requireInstrumentationReady = false;
    bool m_translationEnabled = false;
    uint64_t m_maxDumpBytes = 1024 * 1024;
    uint64_t m_maxRegions = 1024;
    uint64_t m_maxChildDepth = 4;
    uint64_t m_maxChildren = 64;
    uint64_t m_nextAllocationId = 1;

    void onMonitorLoad(S2EExecutionState *state);
    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onBlockExecute(S2EExecutionState *state, uint64_t pc);

    void onNtAllocateVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_ALLOCATE_VM &data);
    void onNtProtectVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_PROTECT_VM &data);
    void onNtFreeVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_FREE_VM &data);
    void onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, const std::string &imageName);
    void onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode);
    void onThreadCreate(S2EExecutionState *state, const ThreadDescriptor &thread);
    void onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread);

public:
    ExecutableRegionMonitor(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();
    unsigned behaviorStage(S2EExecutionState *state, BehaviorGoal goal);
    bool isTrackedDynamicCode(S2EExecutionState *state, uint64_t pc);
    bool getDynamicCodeLocation(S2EExecutionState *state, uint64_t pc, uint64_t &pid,
                                uint64_t &allocation, uint64_t &offset);
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXECUTABLEREGIONMONITOR_H
