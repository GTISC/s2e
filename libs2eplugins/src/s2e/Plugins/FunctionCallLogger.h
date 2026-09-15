///
/// Copyright (C) 2024, Yongheng Chen
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#ifndef S2E_PLUGINS_FUNCTIONCALLLOGGER_H
#define S2E_PLUGINS_FUNCTIONCALLLOGGER_H

#include <s2e/Plugin.h>

#include <map>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <string>

namespace s2e {
namespace plugins {

class ExecutableRegionMonitor;
class Vmi;
struct ObservedWindowsCall {
    std::string api, path, value, data;
    uint64_t pid = 0, lifetime = 0, depth = 0;
    uint32_t args[9] = {};
    bool diagnostic = false;
    bool recordEffect = false;
};

enum S2E_FUNCTIONCALLLOGGER_COMMANDS {
    // TODO: customize list of commands here
    COMMAND_1
};

struct S2E_FUNCTIONCALLLOGGER_COMMAND {
    S2E_FUNCTIONCALLLOGGER_COMMANDS Command;
    union {
        // Command parameters go here
        uint64_t param;
    };
};

class FunctionCallLogger : public Plugin, public IPluginInvoker {

    S2E_PLUGIN
public:
    FunctionCallLogger(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    void onCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source, const ModuleDescriptorConstPtr &dest,
                uint64_t callerPc, uint64_t calleePc, const FunctionMonitor::ReturnSignalPtr &returnSignal);

private:
    ModuleExecutionDetector *m_detector;
    ExecutableRegionMonitor *m_regions = nullptr;
    Vmi *m_vmi = nullptr;
    bool m_observeWindowsEffects = false;
    std::map<std::string, std::map<uint64_t, std::string>> m_exports;
    void onReturn(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                  const ModuleDescriptorConstPtr &dest, uint64_t pc, ObservedWindowsCall call);
    void onProcessUnload(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid, uint64_t returnCode);

    // Allow the guest to communicate with this plugin using s2e_invoke_plugin
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_FUNCTIONCALLLOGGER_H
