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

#include <chrono>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <klee/Expr.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Analyzers/ExecutableRegionMonitor.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/Plugins/ExecutionTracers/TestCaseGenerator.h>
#include <s2e/S2E.h>
#include <s2e/cpu.h>
#include <tuple>

#include "FunctionCallLogger.h"
#include "WindowsInputObservation.h"

namespace s2e {
namespace plugins {

namespace {

//
// This class can optionally be used to store per-state plugin data.
//
// Use it as follows:
// void FunctionCallLogger::onEvent(S2EExecutionState *state, ...) {
//     DECLARE_PLUGINSTATE(FunctionCallLoggerState, state);
//     plgState->...
// }
//
class FunctionCallLoggerState : public PluginState {
    // Declare any methods and fields you need here

public:
    std::map<std::tuple<uint64_t, uint64_t, uint32_t>, std::string> fileHandles, registryHandles;
    uint64_t events = 0;
    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new FunctionCallLoggerState();
    }

    virtual ~FunctionCallLoggerState() {
        // Destroy any object if needed
    }

    virtual FunctionCallLoggerState *clone() const {
        return new FunctionCallLoggerState(*this);
    }
};

} // namespace

S2E_DEFINE_PLUGIN(FunctionCallLogger, "Describe what the plugin does here", "", );

void FunctionCallLogger::initialize() {
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    FunctionMonitor *monitor = s2e()->getPlugin<FunctionMonitor>();
    m_observeWindowsEffects = s2e()->getConfig()->getBool(getConfigKey() + ".observeWindowsEffects", false);
    m_discoverRootInputs = s2e()->getConfig()->getBool(getConfigKey() + ".discoverRootInputs", false);
    m_discoverChildInputs = s2e()->getConfig()->getBool(getConfigKey() + ".discoverChildInputs", false);
    m_regions = s2e()->getPlugin<ExecutableRegionMonitor>();
    m_vmi = s2e()->getPlugin<Vmi>();
    const bool observe = m_observeWindowsEffects || m_discoverRootInputs || m_discoverChildInputs;
    if (observe && (!m_regions || !m_vmi)) {
        getWarningsStream() << "Windows effect observation requires ExecutableRegionMonitor and Vmi\n";
        exit(-1);
    }
    if (observe) {
        auto os = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
        os->onProcessUnload.connect(sigc::mem_fun(*this, &FunctionCallLogger::onProcessUnload));
    }
    monitor->onCall.connect(sigc::mem_fun(*this, &FunctionCallLogger::onCall));
    if (observe) {
        monitor->onTailCall.connect(sigc::mem_fun(*this, &FunctionCallLogger::onCall));
    }
    if (m_discoverRootInputs || m_discoverChildInputs) enableInputJournal();
}

void FunctionCallLogger::onProcessUnload(S2EExecutionState *state, uint64_t addressSpace, uint64_t pid,
                                         uint64_t returnCode) {
    DECLARE_PLUGINSTATE(FunctionCallLoggerState, state);
    for (auto handles : {&plgState->fileHandles, &plgState->registryHandles}) {
        for (auto it = handles->begin(); it != handles->end();) {
            if (std::get<0>(it->first) == pid) it = handles->erase(it);
            else ++it;
        }
    }
}

static std::string inputHex(const std::string &bytes) {
    std::string result;
    result.reserve(bytes.size() * 2);
    for (unsigned char c : bytes) {
        result += "0123456789abcdef"[c >> 4];
        result += "0123456789abcdef"[c & 15];
    }
    return result;
}

void FunctionCallLogger::enableInputJournal() {
    auto &journal = m_inputJournals[s2e()->getCurrentInstanceIndex()];
    if (journal.enabled) return;
    std::ofstream out(s2e()->getOutputFilename("child-input-observations.jsonl"), std::ios::app);
    out << "{\"schema\":3,\"event\":\"enabled\",\"instance\":" << s2e()->getCurrentInstanceIndex()
        << ",\"child_scope\":" << (m_discoverChildInputs ? "true" : "false")
        << ",\"root_scope\":" << (m_discoverRootInputs ? "true" : "false")
        << ",\"input_process_scope\":false,\"source_models\":false}\n";
    out.close();
    journal.enabled = bool(out);
    if (!out) getWarningsStream() << "Could not enable native input observation journal\n";
}

void FunctionCallLogger::observeInput(S2EExecutionState *state, const ObservedWindowsCall &call, uint32_t result) {
    enableInputJournal();
    auto &journal = m_inputJournals[s2e()->getCurrentInstanceIndex()];
    if (!journal.enabled || journal.count >= 256) return;
    const auto key = std::make_tuple(call.pid, call.lifetime, call.depth, call.api, call.path, call.value);
    auto found = journal.sources.find(key);
    if (found != journal.sources.end() && found->second >= 32) return;
    auto read32 = [&](uint64_t address, uint32_t &value) {
        if (!address) return false;
        auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(address, klee::Expr::Int32));
        if (!c) return false;
        value = c->getZExtValue();
        return true;
    };
    uint32_t buffer = 0, count = 0, requested = call.requested, registryType = 0;
    std::string seed;
    const unsigned width = call.api.back() == 'W' ? 2 : 1;
    if (call.api == "ReadFile") {
        if (!read32(call.args[3], count) ||
            !input_observation::bufferExtent(count, requested, result != 0, call.args[4] != 0)) return;
        buffer = call.args[1];
    } else if (call.api.find("RegQueryValueEx") == 0) {
        if (!read32(call.args[5], count) || !input_observation::bufferExtent(count, requested, result == 0) ||
            (call.args[3] && !read32(call.args[3], registryType))) return;
        buffer = call.args[4];
    } else if (call.api.find("GetEnvironmentVariable") == 0) {
        if (!input_observation::environmentExtent(result, call.args[2], width, count, requested)) return;
        buffer = call.args[1];
    } else if (call.api.find("GetCommandLine") == 0) {
        if (!result) return;
        buffer = result;
        // Include the concrete terminator; reject truncated or symbolic strings.
        for (unsigned offset = 0; offset < 256; offset += width) {
            auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(buffer + offset,
                                                       width == 2 ? klee::Expr::Int16 : klee::Expr::Int8));
            if (!c) return;
            if (!c->getZExtValue()) { count = requested = offset + width; break; }
        }
        if (count <= width) return;
    } else return;
    if (!buffer || uint64_t(buffer) + count > (uint64_t(1) << 32)) return;
    for (uint32_t i = 0; i < count; ++i) {
        auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(buffer) + i, klee::Expr::Int8));
        if (!c) return;
        seed += static_cast<char>(c->getZExtValue());
    }
    std::ofstream out(s2e()->getOutputFilename("child-input-observations.jsonl"), std::ios::app);
    out << "{\"schema\":3,\"event\":\"read\",\"instance\":" << s2e()->getCurrentInstanceIndex()
        << ",\"state\":" << state->getID() << ",\"pid\":" << call.pid << ",\"lifetime\":" << call.lifetime
        << ",\"depth\":" << call.depth << ",\"time_ns\":"
        << std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
        << ",\"caller_pc\":" << call.callerPc << ",\"diagnostic_lineage\":false,\"api\":\"" << call.api
        << "\",\"path_hex\":\"" << inputHex(call.path) << "\",\"value_hex\":\"" << inputHex(call.value)
        << "\",\"seed_hex\":\"" << inputHex(seed) << "\",\"count\":" << count << ",\"requested\":" << requested
        << ",\"registry_type\":" << registryType << ",\"return_value\":" << result << ",\"overlapped\":false}\n";
    out.close();
    if (!out) { getWarningsStream(state) << "Could not persist native input observation\n"; return; }
    const unsigned sourceCount = ++journal.sources[key];
    ++journal.count;
    if (sourceCount == 32 || journal.count == 256) {
        std::ofstream cap(s2e()->getOutputFilename("child-input-observations.jsonl"), std::ios::app);
        if (sourceCount == 32) {
            cap << "{\"schema\":3,\"event\":\"source_cap\",\"instance\":" << s2e()->getCurrentInstanceIndex()
                << ",\"pid\":" << call.pid << ",\"lifetime\":" << call.lifetime << ",\"depth\":" << call.depth
                << ",\"api\":\"" << call.api << "\",\"path_hex\":\"" << inputHex(call.path)
                << "\",\"value_hex\":\"" << inputHex(call.value) << "\",\"limit\":32}\n";
        }
        if (journal.count == 256)
            cap << "{\"schema\":3,\"event\":\"cap\",\"instance\":" << s2e()->getCurrentInstanceIndex() << "}\n";
    }
}

void FunctionCallLogger::onCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                                const ModuleDescriptorConstPtr &dest, uint64_t callerPc, uint64_t calleePc,
                                const FunctionMonitor::ReturnSignalPtr &returnSignal) {
    if (!(m_observeWindowsEffects || m_discoverRootInputs || m_discoverChildInputs) ||
        state->getPointerSize() != 4 || !dest)
        return;
    if (dest->Name != "kernel32.dll" && dest->Name != "kernelbase.dll" && dest->Name != "advapi32.dll")
        return;
    ObservedWindowsCall call;
    call.callerPc = callerPc;
    call.recordEffect = !source || source->Name.size() < 4 || source->Name.substr(source->Name.size() - 4) != ".dll";
    if (!m_regions->getProcessContext(state, call.pid, call.lifetime, call.depth, call.diagnostic))
        return;
    auto key = dest->Path + ":" + dest->Name;
    auto exports = m_exports.find(key);
    if (exports == m_exports.end()) {
        auto pe = std::dynamic_pointer_cast<vmi::PEFile>(m_vmi->getFromDisk(dest->Path, dest->Name, true));
        if (!pe)
            return;
        std::map<uint64_t, std::string> entries;
        for (const auto &entry : pe->getExports())
            entries[entry.first] = entry.second;
        exports = m_exports.emplace(key, std::move(entries)).first;
    }
    auto name = exports->second.find(calleePc - dest->NativeBase);
    if (name == exports->second.end())
        return;
    call.api = name->second;
    static const std::map<std::string, unsigned> supported = {
        {"CreateFileA", 7},   {"CreateFileW", 7},     {"CopyFileA", 3},       {"CopyFileW", 3},
        {"WriteFile", 5},     {"CloseHandle", 1},     {"RegCloseKey", 1},     {"RegOpenKeyExA", 5},
        {"RegOpenKeyExW", 5}, {"RegCreateKeyExA", 9}, {"RegCreateKeyExW", 9}, {"RegSetValueExA", 6},
        {"RegSetValueExW", 6}, {"ReadFile", 5}, {"RegQueryValueExA", 6}, {"RegQueryValueExW", 6},
        {"GetEnvironmentVariableA", 3}, {"GetEnvironmentVariableW", 3},
        {"GetCommandLineA", 0}, {"GetCommandLineW", 0}};
    auto count = supported.find(call.api);
    if (count == supported.end())
        return;
    // Inspection must never ask the solver or concretize a symbolic argument.
    auto read32 = [&](uint64_t address, uint32_t &value) {
        auto e = state->mem()->read(address, klee::Expr::Int32);
        auto c = dyn_cast_or_null<klee::ConstantExpr>(e);
        if (!c)
            return false;
        value = c->getZExtValue();
        return true;
    };
    for (unsigned i = 0; i < count->second; ++i)
        if (!read32(state->regs()->getSp() + 4 * (i + 1), call.args[i]))
            return;
    const bool wide = call.api.back() == 'W';
    auto readText = [&](uint64_t address, std::string &text, unsigned bound = 512, bool boundedData = false) {
        if (!address)
            return false;
        for (unsigned i = 0; i < bound; ++i) {
            auto e = state->mem()->read(address + i * (wide ? 2 : 1), wide ? klee::Expr::Int16 : klee::Expr::Int8);
            auto c = dyn_cast_or_null<klee::ConstantExpr>(e);
            if (!c)
                return false;
            auto value = c->getZExtValue();
            if (!value)
                return true;
            // Initial observer explicitly supports ASCII paths only; never invent text.
            if (value > 127)
                return false;
            text += static_cast<char>(value);
        }
        return boundedData;
    };
    DECLARE_PLUGINSTATE(FunctionCallLoggerState, state);
    auto handle = std::make_tuple(call.pid, call.lifetime, call.args[0]);
    auto &handles = call.api.find("Reg") == 0 ? plgState->registryHandles : plgState->fileHandles;
    auto known = handles.find(handle);
    if (known != handles.end())
        call.path = known->second;
    else if (call.args[0] == 0x80000001)
        call.path = "HKEY_CURRENT_USER";
    else if (call.args[0] == 0x80000002)
        call.path = "HKEY_LOCAL_MACHINE";
    else if (call.args[0] == 0x80000000)
        call.path = "HKEY_CLASSES_ROOT";
    if (call.api.find("CreateFile") == 0) {
        call.path.clear();
        if (!readText(call.args[0], call.path))
            return;
    } else if (call.api == "ReadFile") {
        if (call.path.empty() || call.args[4]) return;
        call.requested = call.args[2];
    } else if (call.api.find("RegQueryValueEx") == 0) {
        if (call.path.empty() || (call.args[1] && !readText(call.args[1], call.value)) ||
            !call.args[4] || !read32(call.args[5], call.requested)) return;
    } else if (call.api.find("GetEnvironmentVariable") == 0) {
        call.path.clear();
        if (!readText(call.args[0], call.path)) return;
    } else if (call.api.find("GetCommandLine") == 0) {
        call.path = "process_command_line";
    } else if (call.api.find("CopyFile") == 0) {
        call.path.clear();
        if (!readText(call.args[1], call.path))
            return;
        // Optional source context must not force concretization or hide a
        // completed, concrete destination write.
        if (!readText(call.args[0], call.value))
            call.value.clear();
    } else if (call.api.find("RegOpenKey") == 0 || call.api.find("RegCreateKey") == 0) {
        std::string subkey;
        if (call.path.empty() || !readText(call.args[1], subkey))
            return;
        call.path += "\\" + subkey;
    } else if (call.api.find("RegSetValue") == 0) {
        if (call.path.empty() || (call.args[1] && !readText(call.args[1], call.value)))
            return;
        if (call.args[3] == 1 || call.args[3] == 2) {
            unsigned width = wide ? 2 : 1;
            if (call.args[5] % width || call.args[5] / width > 512 ||
                !readText(call.args[4], call.data, call.args[5] / width, true))
                return;
        }
    }
    returnSignal->stackCleanup = 4 * count->second;
    returnSignal->connect(sigc::bind(sigc::mem_fun(*this, &FunctionCallLogger::onReturn), call));
}

void FunctionCallLogger::onReturn(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                                  const ModuleDescriptorConstPtr &dest, uint64_t pc, ObservedWindowsCall call) {
    uint64_t pid, lifetime, depth;
    bool diagnostic;
    if (!m_regions->getProcessContext(state, pid, lifetime, depth, diagnostic) || pid != call.pid ||
        lifetime != call.lifetime)
        return;
    uint32_t result;
    if (!state->regs()->read(CPU_OFFSET(regs[R_EAX]), &result, sizeof(result), false))
        return;
    DECLARE_PLUGINSTATE(FunctionCallLoggerState, state);
    auto handle = std::make_tuple(pid, lifetime, call.args[0]);
    bool registry = call.api.find("Reg") == 0;
    auto &handles = registry ? plgState->registryHandles : plgState->fileHandles;
    if (call.api == "CloseHandle" || call.api == "RegCloseKey") {
        if (registry ? result == 0 : result != 0)
            handles.erase(handle);
        return;
    }
    auto read32 = [&](uint64_t address, uint32_t &value) {
        auto e = state->mem()->read(address, klee::Expr::Int32);
        auto c = dyn_cast_or_null<klee::ConstantExpr>(e);
        if (!c)
            return false;
        value = c->getZExtValue();
        return true;
    };
    if (call.api.find("CreateFile") == 0) {
        if (result != UINT32_MAX && (handles.size() < 4096 || handles.count(std::make_tuple(pid, lifetime, result))))
            handles[std::make_tuple(pid, lifetime, result)] = call.path;
        return;
    }
    if (call.api == "ReadFile" || call.api.find("RegQueryValueEx") == 0 ||
        call.api.find("GetEnvironmentVariable") == 0 || call.api.find("GetCommandLine") == 0) {
        if (call.recordEffect && !call.diagnostic && (depth ? m_discoverChildInputs : m_discoverRootInputs))
            observeInput(state, call, result);
        return;
    }
    if (registry && result != 0)
        return;
    if (call.api.find("RegOpenKey") == 0 || call.api.find("RegCreateKey") == 0) {
        uint32_t key;
        unsigned index = call.api.find("RegOpenKey") == 0 ? 4 : 7;
        if (read32(call.args[index], key) && (handles.size() < 4096 || handles.count(std::make_tuple(pid, lifetime, key))))
            handles[std::make_tuple(pid, lifetime, key)] = call.path;
        return;
    }
    if (!registry && !result)
        return;
    if (!call.recordEffect || !m_observeWindowsEffects)
        return;
    uint32_t bytes = 0;
    std::string bufferPrefix;
    if (call.api == "WriteFile") {
        // Pending/overlapped writes and unknown handles are not certified effects.
        if (call.path.empty() || call.args[4] || !read32(call.args[3], bytes) || !bytes || bytes > call.args[2])
            return;
        // Observe only already concrete bytes. Evidence collection must never
        // concretize symbolic inputs or certify an unreadable buffer prefix.
        for (uint32_t i = 0; i < std::min(bytes, uint32_t(4096)); ++i) {
            const auto value = state->mem()->read(call.args[1] + i, klee::Expr::Int8);
            const auto constant = dyn_cast_or_null<klee::ConstantExpr>(value);
            if (!constant) break;
            bufferPrefix += static_cast<char>(constant->getZExtValue());
        }
    }
    auto hex = [](const std::string &s) {
        std::string out;
        for (unsigned char c : s) {
            out += "0123456789abcdef"[c >> 4];
            out += "0123456789abcdef"[c & 15];
        }
        return out;
    };
    if (plgState->events++ >= 10000) {
        if (plgState->events == 10001)
            getWarningsStream(state) << "Windows effect journal capped at 10000 events\n";
        return;
    }
    std::ofstream out(s2e()->getOutputFilename("windows-effects.jsonl"), std::ios::app);
    out << "{\"schema\":1,\"instance\":" << s2e()->getCurrentInstanceIndex() << ",\"time_ns\":"
        << std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
               .count()
        << ",\"state\":" << state->getID() << ",\"pid\":" << pid << ",\"lifetime\":" << lifetime
        << ",\"depth\":" << depth << ",\"diagnostic_lineage\":" << (diagnostic ? "true" : "false") << ",\"api\":\""
        << call.api << "\",\"path_hex\":\"" << hex(call.path) << "\",\"value_hex\":\"" << hex(call.value)
        << "\",\"data_hex\":\"" << hex(call.data) << "\",\"bytes_written\":" << bytes
        << ",\"buffer_prefix_hex\":\"" << hex(bufferPrefix) << "\",\"buffer_prefix_bytes\":" << bufferPrefix.size()
        << ",\"registry_type\":" << (registry ? call.args[3] : 0) << ",\"return_value\":" << result << "}\n";
    out.close();
    if (!out)
        getWarningsStream(state) << "Could not persist Windows effect evidence\n";
    // Credit only persisted native observations, never guest log messages.
    // Generic writes are weak evidence; a concrete autorun configuration is
    // a semantic milestone, not proof that persistence actually executed.
    auto controller = s2e()->getPlugin<testcases::TestCaseGenerator>();
    if (!out || diagnostic || !controller) return;
    std::string path = call.path;
    std::transform(path.begin(), path.end(), path.begin(), [](unsigned char c) { return std::tolower(c); });
    if (path.find("\\windows\\wer\\") != std::string::npos ||
        path.find("inventoryapplicationfile") != std::string::npos) return;
    controller->explorationProgress(state, pid, depth, registry ? "registry_write" : "file_write", false);
    if (registry && !call.data.empty() && (call.args[3] == 1 || call.args[3] == 2)) {
        for (const auto *root : {"hkey_current_user", "hkey_local_machine"}) {
            for (const auto *view : {"\\software\\", "\\software\\wow6432node\\"}) {
                const std::string prefix = std::string(root) + view + "microsoft\\windows\\currentversion\\";
                if (path == prefix + "run" || path == prefix + "runonce")
                    controller->explorationProgress(state, pid, depth, "autorun_configuration", true);
            }
        }
    }
}

void FunctionCallLogger::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr,
                                                uint64_t guestDataSize) {
    S2E_FUNCTIONCALLLOGGER_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_FUNCTIONCALLLOGGER_COMMAND size\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        // TODO: add custom commands here
        case COMMAND_1:
            break;
        default:
            getWarningsStream(state) << "Unknown command " << command.Command << "\n";
            break;
    }
}

} // namespace plugins
} // namespace s2e
