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
#include <vector>
#include <klee/Expr.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <string>
#include <tuple>
#include "SelectedInput.h"

namespace s2e {
namespace plugins {

class ExecutableRegionMonitor;
class Vmi;
struct ObservedWindowsCall {
    std::string api, path, value, data, module;
    std::string originalSockaddr, effectiveSockaddr, peerSockaddr, bufferPrefix;
    uint64_t pid = 0, lifetime = 0, depth = 0;
    uint32_t args[9] = {};
    bool diagnostic = false;
    bool recordEffect = false;
    bool network = false;
    bool audio = false;
    bool redirected = false;
    bool bufferConcrete = false;
    uint64_t callerPc = 0, calleePc = 0, entryTime = 0;
    bool lifecycle = false;
    uint32_t requested = 0;
    uint32_t callId = 0, socket = 0, flags = 0, addressLength = 0;
    uint32_t listenerSocket = 0, acceptedSocket = 0, backlog = 0;
    uint32_t targetPid = 0;
    std::vector<std::pair<uint64_t, klee::ref<klee::Expr>>> conversionInput;
    std::vector<klee::ref<klee::Expr>> conversionOutput;
    std::string conversionSeed;
    std::vector<std::string> conversionArrays;
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
    bool m_discoverRootInputs = false;
    bool m_discoverChildInputs = false;
    bool m_observeNetwork = false;
    unsigned m_networkCalls = 0;
    bool m_observeAudio = false;
    unsigned m_audioCalls = 0;
    unsigned m_largeReads = 0;
    std::map<unsigned, unsigned> m_lifecycleCalls;
    void recordLifecycle(S2EExecutionState *state, const ObservedWindowsCall &call, bool returned, uint32_t result);
    void observeLargeRead(S2EExecutionState *state, const ObservedWindowsCall &call, uint32_t result,
                          uint32_t count);
    struct ConnectRedirect {
        bool enabled = false;
        bool loopback = false;
        std::string module, code, sockaddr, scope = "child";
        uint32_t rva = 0;
        bool relocatedOperand = false;
        uint32_t preferredBase = 0, imageSize = 0;
    } m_connectRedirect;
    SelectedInput m_selectedInput;
    unsigned m_modeledInputs = 0;
    bool m_preserveAsciiConversions = true;
    unsigned m_asciiConversions = 0;
    void prepareAsciiConversion(S2EExecutionState *state, ObservedWindowsCall &call);
    void finishAsciiConversion(S2EExecutionState *state, const ObservedWindowsCall &call, uint32_t result);
    void parseSelectedInput();
    void parseConnectRedirect();
    struct DoublingLoop {
        bool enabled = false, accelerate = false;
        std::string module, body;
        uint32_t bodyRva = 0, siteRva = 0, thunkRva = 0, iatRva = 0;
        uint32_t preferredBase = 0, imageSize = 0, initial = 0, stable = 4, maxCalls = 2;
    } m_doublingLoop;
    void parseDoublingLoop();
    void onLoopTranslate(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void onLoopExecute(S2EExecutionState *state, uint64_t pc);
    void modelSelectedInput(S2EExecutionState *state, const ObservedWindowsCall &call,
                            uint64_t buffer, const std::string &seed, unsigned registryType, uint64_t time);
    struct InputJournal {
        bool enabled = false;
        unsigned count = 0;
        std::map<std::tuple<uint64_t, uint64_t, uint64_t, std::string, std::string, std::string>, unsigned> sources;
    };
    std::map<unsigned, InputJournal> m_inputJournals;
    std::map<std::string, std::map<uint64_t, std::string>> m_exports;
    void enableInputJournal();
    struct AccessJournal {
        bool enabled = false;
        unsigned count = 0;
        std::map<std::tuple<uint64_t, uint64_t, uint64_t, std::string, std::string, std::string, uint64_t>, unsigned> sources;
    };
    std::map<unsigned, AccessJournal> m_accessJournals;
    void observeAccess(S2EExecutionState *state, const ObservedWindowsCall &call, uint32_t result);
    void observeInput(S2EExecutionState *state, const ObservedWindowsCall &call, uint32_t result);
    bool prepareNetworkCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                            ObservedWindowsCall &call);
    void recordNetworkEvent(S2EExecutionState *state, const ObservedWindowsCall &call,
                            const char *event, uint32_t result);
    void recordAudioEvent(S2EExecutionState *state, const ObservedWindowsCall &call,
                          const char *event, uint32_t result);
    void onReturn(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                  const ModuleDescriptorConstPtr &dest, uint64_t pc, ObservedWindowsCall call);
    void onProcessUnload(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid, uint64_t returnCode);

    // Allow the guest to communicate with this plugin using s2e_invoke_plugin
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_FUNCTIONCALLLOGGER_H
