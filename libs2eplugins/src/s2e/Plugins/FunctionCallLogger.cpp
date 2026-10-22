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
#include <klee/util/ExprUtil.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/Analyzers/ExecutableRegionMonitor.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/Plugins/ExecutionTracers/TestCaseGenerator.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/cpu.h>
#include <tuple>
#include <set>

#include "FunctionCallLogger.h"
#include "WindowsInputObservation.h"
#include "DoublingLoop.h"
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>

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
    std::set<std::string> asciiInputArrays;
    std::map<std::pair<uint64_t,uint64_t>, unsigned> selectedReads;
    std::set<std::tuple<uint64_t, uint64_t, uint32_t>> redirectedSockets;
    std::map<std::tuple<uint64_t, uint64_t, uint64_t, uint32_t>, doubling_loop::Witness> loopWitnesses;
    unsigned loopCalls = 0;
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
    parseSelectedInput();
    m_observeNetwork = s2e()->getConfig()->getBool(getConfigKey() + ".observeNetwork", false);
    m_observeAudio = s2e()->getConfig()->getBool(getConfigKey() + ".observeAudio", false);
    parseConnectRedirect();
    m_preserveAsciiConversions = s2e()->getConfig()->getBool(getConfigKey() + ".preserveSelectedAsciiConversions", true);
    m_regions = s2e()->getPlugin<ExecutableRegionMonitor>();
    m_vmi = s2e()->getPlugin<Vmi>();
    parseDoublingLoop();
    const bool observe = m_observeWindowsEffects || m_discoverRootInputs || m_discoverChildInputs ||
                         m_observeNetwork || m_observeAudio;
    if (observe && (!m_regions || !m_vmi)) {
        getWarningsStream() << "Windows effect observation requires ExecutableRegionMonitor and Vmi\n";
        exit(-1);
    }
    if (observe) {
        getDebugStream() << "NativeWindowsObservation.runtime-caller.v1\n";
        auto os = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
        os->onProcessUnload.connect(sigc::mem_fun(*this, &FunctionCallLogger::onProcessUnload));
    }
    monitor->onCall.connect(sigc::mem_fun(*this, &FunctionCallLogger::onCall));
    if (observe) {
        monitor->onTailCall.connect(sigc::mem_fun(*this, &FunctionCallLogger::onCall));
    }
    if (m_discoverRootInputs || m_discoverChildInputs) enableInputJournal();
}

void FunctionCallLogger::parseDoublingLoop() {
    auto cfg = s2e()->getConfig();
    const std::string key = getConfigKey() + ".doublingLoopSummary";
    if (!cfg->hasKey(key)) return;
    auto fail = [&]() { getWarningsStream() << "Invalid doublingLoopSummary policy\n"; exit(-1); };
    auto number = [&](const char *name, uint32_t low, uint32_t high) -> uint32_t {
        bool ok; auto n = cfg->getInt(key + "." + name, 0, &ok);
        if (!ok || n < low || n > high) fail();
        return n;
    };
    m_doublingLoop.module = cfg->getString(key + ".module", "");
    const auto mode = cfg->getString(key + ".mode", "");
    m_doublingLoop.bodyRva = number("body_rva", 1, 0x1000000);
    m_doublingLoop.siteRva = number("site_rva", 1, 0x1000000);
    m_doublingLoop.thunkRva = number("thunk_rva", 1, 0x1000000);
    m_doublingLoop.iatRva = number("iat_rva", 1, 0x1000000);
    m_doublingLoop.preferredBase = number("preferred_base", 0x10000, 0xff000000);
    m_doublingLoop.imageSize = number("image_size", 4096, 0x10000000);
    m_doublingLoop.initial = number("initial_count", 16, 1000000000);
    m_doublingLoop.stable = number("stable_iterations", 4, 16);
    m_doublingLoop.maxCalls = number("max_calls", 1, 8);
    const auto body = cfg->getString(key + ".body_code_hex", "");
    // The transfer function is implemented only for this complete instruction
    // shape. A caller cannot authorize a different loop by changing the bytes.
    const std::string first = "8bd08bc903c68bd0908bc9508bc98bd0e8";
    const std::string last = "908bc9588bd08bc903c28bc98bd0ff4dfc837dfc0075d4";
    uint32_t relative = m_doublingLoop.thunkRva - (m_doublingLoop.bodyRva + 21);
    std::string expected = first;
    const char *hex = "0123456789abcdef";
    for (unsigned i = 0; i < 4; ++i) { auto b = (relative >> (i*8)) & 255; expected += hex[b >> 4]; expected += hex[b & 15]; }
    expected += last;
    if (body != expected || m_doublingLoop.siteRva != m_doublingLoop.bodyRva + 35 ||
        m_doublingLoop.module.empty() || m_doublingLoop.module.size() > 128 ||
        (mode != "observe" && mode != "accelerate") || !m_regions || !m_vmi ||
        !s2e()->getPlugin<ModuleMap>() || !s2e()->getPlugin<WindowsMonitor>()) fail();
    for (size_t i = 0; i < body.size(); i += 2)
        m_doublingLoop.body += char(std::stoul(body.substr(i, 2), nullptr, 16));
    m_doublingLoop.accelerate = mode == "accelerate";
    m_doublingLoop.enabled = true;
    getInfoStream() << "NativeDoublingLoopSummary.v1\n";
    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(sigc::mem_fun(*this, &FunctionCallLogger::onLoopTranslate));
}

void FunctionCallLogger::onLoopTranslate(ExecutionSignal *signal, S2EExecutionState *state,
                                        TranslationBlock *tb, uint64_t pc) {
    // No current execution TB exists during the first translation. The event
    // supplies the block whose mode is being translated.
    if (!tb || !(tb->flags & (1 << HF_CS32_SHIFT)) || (tb->flags & (1 << HF_CS64_SHIFT))) return;
    auto module = s2e()->getPlugin<ModuleMap>()->getModule(state, pc);
    if (module && module->Name == m_doublingLoop.module && pc >= module->LoadBase &&
        pc - module->LoadBase == m_doublingLoop.siteRva)
        signal->connect(sigc::mem_fun(*this, &FunctionCallLogger::onLoopExecute));
}

void FunctionCallLogger::onLoopExecute(S2EExecutionState *state, uint64_t pc) {
    uint64_t pid, lifetime, depth; bool diagnostic;
    if (state->getPointerSize() != 4 || !m_regions->getProcessContext(state, pid, lifetime, depth, diagnostic) ||
        depth || diagnostic) return;
    DECLARE_PLUGINSTATE(FunctionCallLoggerState, state);
    if (plgState->loopCalls >= m_doublingLoop.maxCalls) return;
    const auto tid = s2e()->getPlugin<WindowsMonitor>()->getCurrentThreadId(state);
    auto modules = s2e()->getPlugin<ModuleMap>();
    auto module = modules->getModule(state, pid, pc);
    if (!module || module->Name != m_doublingLoop.module || module->NativeBase != m_doublingLoop.preferredBase ||
        module->Size != m_doublingLoop.imageSize || pc - module->LoadBase != m_doublingLoop.siteRva) return;
    auto bytes = [&](uint64_t address, unsigned n, std::string &out) {
        if (!address || address + n > (uint64_t(1) << 32)) return false;
        for (unsigned i = 0; i < n; ++i) {
            auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(address+i, klee::Expr::Int8));
            if (!c) return false;
            out += char(c->getZExtValue());
        }
        return true;
    };
    auto word = [&](uint64_t address, uint32_t &out) {
        auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(address, klee::Expr::Int32));
        if (!c) return false;
        out = c->getZExtValue(); return true;
    };
    std::array<uint32_t, 8> regs;
    for (unsigned i = 0; i < 8; ++i)
        if (!state->regs()->read(CPU_OFFSET(regs[i]), &regs[i], 4, false)) return;
    const auto key = std::make_tuple(pid, lifetime, tid, regs[5]);
    if (!plgState->loopWitnesses.count(key) && plgState->loopWitnesses.size() >= 32) return;
    auto &witness = plgState->loopWitnesses[key];
    if (witness.done || witness.rejected) return;
    std::string body, thunk;
    uint32_t thunkSlot, callee, count, scratch;
    if (regs[5] < 4 || regs[4] < 8 || regs[4] != regs[5] - 8 ||
        !bytes(module->LoadBase + m_doublingLoop.bodyRva, m_doublingLoop.body.size(), body) || body != m_doublingLoop.body ||
        !bytes(module->LoadBase + m_doublingLoop.thunkRva, 6, thunk) ||
        (unsigned char)thunk[0] != 0xff || (unsigned char)thunk[1] != 0x25 ||
        !word(module->LoadBase + m_doublingLoop.thunkRva + 2, thunkSlot) ||
        thunkSlot != module->LoadBase + m_doublingLoop.iatRva || !word(thunkSlot, callee) ||
        !word(regs[5]-4, count) || !word(regs[4]-4, scratch) || uint32_t(scratch * 2) != regs[0]) {
        witness.rejected = true; return;
    }
    // Resolve only the measured kernel32 forwarder and exact read-only
    // Windows 7 GetTickCount implementation. No other API can be summarized.
    auto target = modules->getModule(state, pid, callee);
    if (!target) { witness.rejected = true; return; }
    auto exportedTick = [&](const ModuleDescriptorConstPtr &mod, uint32_t address) {
        auto pe = std::dynamic_pointer_cast<vmi::PEFile>(m_vmi->getFromDisk(mod->Path, mod->Name, true));
        if (!pe) return false;
        auto exports = pe->getExports();
        auto entry = exports.find(address - mod->LoadBase);
        return entry != exports.end() && entry->second == "GetTickCount";
    };
    if (target->Name == "kernel32.dll") {
        std::string wrapper; uint32_t slot;
        if (!exportedTick(target, callee) || !bytes(callee, 9, wrapper) ||
            wrapper != std::string("\xeb\x05\x90\x90\x90\x90\x90\xff\x25", 9) ||
            !word(callee+9, slot) || slot < target->LoadBase || uint64_t(slot)+4 > target->LoadBase+target->Size ||
            !word(slot, callee)) { witness.rejected = true; return; }
        target = modules->getModule(state, pid, callee);
    }
    const std::string tick("\x8b\x0d\x24\x03\xfe\x7f\x8b\x15\x20\x03\xfe\x7f\xa1\x28\x03\xfe\x7f\x3b\xc8\x75\x1b\xa1\x04\x00\xfe\x7f\xf7\xe2\xc1\xe1\x08\x0f\xaf\x0d\x04\x00\xfe\x7f\x0f\xac\xd0\x18\xc1\xea\x18\x03\xc1\xc3\xf3\x90\xeb\xcc", 52);
    std::string implementation;
    if (!target || target->Name != "kernelbase.dll" || !exportedTick(target, callee) ||
        !bytes(callee, tick.size(), implementation) || implementation != tick ||
        !witness.observe(regs, count, m_doublingLoop.initial)) { witness.rejected = true; return; }
    auto result = doubling_loop::summarize(regs[0], count);
    const bool applied = m_doublingLoop.accelerate && witness.seen == m_doublingLoop.stable && count > 1;
    std::ofstream out(s2e()->getOutputFilename("doubling-loop.jsonl"), std::ios::app);
    out << "{\"schema\":1,\"event\":\"iteration\",\"instance\":" << s2e()->getCurrentInstanceIndex()
        << ",\"state\":" << state->getID() << ",\"pid\":" << pid << ",\"lifetime\":" << lifetime << ",\"tid\":" << tid
        << ",\"depth\":" << depth << ",\"pc\":" << pc << ",\"base\":" << module->LoadBase
        << ",\"count\":" << count << ",\"seen\":" << witness.seen << ",\"eax\":" << regs[0] << ",\"edx\":" << regs[2]
        << ",\"ecx\":" << regs[1] << ",\"esp\":" << regs[4] << ",\"ebp\":" << regs[5] << ",\"scratch\":" << scratch
        << ",\"callee\":" << callee << ",\"applied\":" << (applied ? "true" : "false")
        << ",\"skipped\":" << (applied ? result.skipped : 0)
        << ",\"result_eax\":" << (applied ? result.eax : regs[0]) << ",\"result_edx\":" << (applied ? result.edx : regs[2])
        << ",\"result_count\":" << (applied ? 1 : count) << "}\n";
    out.close();
    if (!out) { s2e()->getExecutor()->terminateState(*state, "Doubling loop journal failed"); return; }
    if (witness.seen < m_doublingLoop.stable) return;
    witness.done = true; ++plgState->loopCalls;
    if (applied && (!state->regs()->write(CPU_OFFSET(regs[R_EAX]), &result.eax, 4) ||
                    !state->regs()->write(CPU_OFFSET(regs[R_EDX]), &result.edx, 4) ||
                    !state->mem()->write(regs[4]-4, &result.scratch, 4) ||
                    !state->mem()->write(regs[5]-4, uint32_t(1))))
        s2e()->getExecutor()->terminateState(*state, "Doubling loop update failed");
}

void FunctionCallLogger::parseConnectRedirect() {
    auto cfg = s2e()->getConfig();
    const std::string key = getConfigKey() + ".connectRedirect";
    if (!cfg->hasKey(key)) return;
    bool ok;
    auto fail = [&]() { getWarningsStream() << "Invalid connectRedirect policy\n"; exit(-1); };
    auto text = [&](const char *field) {
        auto value = cfg->getString(key + "." + field, "", &ok);
        if (!ok) fail();
        return value;
    };
    m_connectRedirect.module = text("module");
    const auto mode = text("mode");
    m_connectRedirect.code = text("code_hex");
    const auto endpoint = text("sockaddr_hex");
    m_connectRedirect.scope = cfg->hasKey(key + ".scope") ? text("scope") : "child";
    const auto rva = cfg->getInt(key + ".rva", 0, &ok);
    if (!ok || rva < 1 || rva > 0x1000000 || !m_observeNetwork ||
        (mode != "observe" && mode != "loopback") ||
        (m_connectRedirect.scope != "root" && m_connectRedirect.scope != "child") ||
        m_connectRedirect.module.empty() || m_connectRedirect.module.size() > 128 ||
        m_connectRedirect.code.size() != 12 || endpoint.size() != 32) fail();
    auto decode = [&](const std::string &hex, std::string &bytes) {
        auto digit = [&](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        };
        for (size_t i = 0; i < hex.size(); i += 2) {
            int high = digit(hex[i]), low = digit(hex[i + 1]);
            if (high < 0 || low < 0) fail();
            bytes += char(high * 16 + low);
        }
    };
    decode(endpoint, m_connectRedirect.sockaddr);
    std::string code;
    decode(m_connectRedirect.code, code);
    if (code.size() != 6 || static_cast<unsigned char>(code[0]) != 0xff ||
        (static_cast<unsigned char>(code[1]) != 0x15 &&
         static_cast<unsigned char>(code[1]) != 0x25) ||
        !input_observation::ipv4Sockaddr(m_connectRedirect.sockaddr)) fail();
    m_connectRedirect.rva = rva;
    if (cfg->hasKey(key + ".relocation_rva")) {
        auto relocation = cfg->getInt(key + ".relocation_rva", 0, &ok);
        if (!ok || relocation != rva + 2) fail();
        auto base = cfg->getInt(key + ".preferred_base", 0, &ok);
        if (!ok || base <= 0 || base > UINT32_MAX) fail();
        auto size = cfg->getInt(key + ".image_size", 0, &ok);
        if (!ok || size <= rva + 6 || uint64_t(base) + size > (uint64_t(1) << 32)) fail();
        m_connectRedirect.preferredBase = base;
        m_connectRedirect.imageSize = size;
        m_connectRedirect.relocatedOperand = true;
    } else if (cfg->hasKey(key + ".preferred_base") || cfg->hasKey(key + ".image_size")) fail();
    m_connectRedirect.loopback = mode == "loopback";
    m_connectRedirect.enabled = true;
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
    for (auto it = plgState->redirectedSockets.begin(); it != plgState->redirectedSockets.end();) {
        if (std::get<0>(*it) == pid) it = plgState->redirectedSockets.erase(it);
        else ++it;
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

void FunctionCallLogger::parseSelectedInput() {
    auto cfg = s2e()->getConfig();
    const std::string key = getConfigKey() + ".selectedCompletedInput";
    if (!cfg->hasKey(key)) return;
    bool ok;
    auto fail = [&]() { getWarningsStream() << "Invalid selectedCompletedInput policy\n"; exit(-1); };
    auto text = [&](const char *field) {
        auto value = cfg->getString(key + "." + field, "", &ok);
        if (!ok) fail();
        return value;
    };
    m_selectedInput.api = text("api"); m_selectedInput.path = text("path");
    m_selectedInput.value = text("value"); m_selectedInput.scope = text("scope");
    const auto seedHex = text("seed_hex");
    if (seedHex.empty() || seedHex.size() > 512 || seedHex.size() % 2) fail();
    auto digit = [&](char c) -> unsigned {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        fail(); return 0;
    };
    for (size_t i = 0; i < seedHex.size(); i += 2)
        m_selectedInput.seed += char(digit(seedHex[i])*16 + digit(seedHex[i+1]));
    auto ordinal = cfg->getInt(key + ".read_index", 1, &ok);
    if (!ok || ordinal < 1 || ordinal > 8) fail();
    m_selectedInput.readIndex = ordinal;
    int count = cfg->getListSize(key + ".byte_offsets", &ok);
    if (!ok || count < 1 || count > 16) fail();
    for (int i = 1; i <= count; ++i) {
        auto offset = cfg->getInt(key + ".byte_offsets[" + std::to_string(i) + "]", -1, &ok);
        if (!ok || offset < 0 || offset > 255) fail();
        m_selectedInput.offsets.push_back(offset);
    }
    if (!m_selectedInput.valid() ||
        (m_selectedInput.scope == "root" ? !m_discoverRootInputs : !m_discoverChildInputs)) fail();
    m_selectedInput.enabled = true;
}

void FunctionCallLogger::modelSelectedInput(S2EExecutionState *state, const ObservedWindowsCall &call,
                                           uint64_t buffer, const std::string &seed, unsigned registryType,
                                           uint64_t time) {
    const auto &policy = m_selectedInput;
    if (!policy.enabled || m_modeledInputs >= 64 || call.api != policy.api || call.path != policy.path ||
        call.value != policy.value || (call.depth == 0) != (policy.scope == "root")) return;
    DECLARE_PLUGINSTATE(FunctionCallLoggerState, state);
    auto &ordinal = plgState->selectedReads[std::make_pair(call.pid, call.lifetime)];
    if (++ordinal != policy.readIndex || !policy.accepts(seed, registryType)) return;
    // Only selected bytes become symbolic. Every other byte, API status,
    // length, UTF-16 high byte and terminator retains its actual concrete value.
    std::vector<uint8_t> bytes;
    for (unsigned offset : policy.offsets) bytes.push_back(seed[offset]);
    std::string arrayName;
    auto symbols = state->createSymbolicArray(call.api + "_selected", bytes.size(), bytes, &arrayName);
    state->enableConcretizationAudit();
    const bool text = call.api != "ReadFile" && !(call.api.find("Reg") == 0 && registryType == 4);
    for (size_t i = 0; i < symbols.size(); ++i) {
        if (text) {
            auto domain = klee::AndExpr::create(klee::UleExpr::create(klee::ConstantExpr::create(32,klee::Expr::Int8),symbols[i]),
                          klee::UleExpr::create(symbols[i],klee::ConstantExpr::create(126,klee::Expr::Int8)));
            if (!state->addConstraint(domain)) {
                s2e()->getExecutor()->terminateState(*state, "Selected input domain was infeasible"); return;
            }
        }
        if (!state->mem()->write(buffer + policy.offsets[i], symbols[i])) {
            s2e()->getExecutor()->terminateState(*state, "Selected input write failed"); return;
        }
    }
    if (text) plgState->asciiInputArrays.insert(arrayName);
    ++m_modeledInputs;
    std::ofstream out(s2e()->getOutputFilename("selected-inputs.jsonl"), std::ios::app);
    out << "{\"schema\":1,\"instance\":" << s2e()->getCurrentInstanceIndex() << ",\"state\":" << state->getID()
        << ",\"pid\":" << call.pid << ",\"lifetime\":" << call.lifetime << ",\"depth\":" << call.depth
        << ",\"time_ns\":" << time << ",\"api\":\"" << call.api << "\",\"path_hex\":\"" << inputHex(call.path)
        << "\",\"value_hex\":\"" << inputHex(call.value) << "\",\"seed_hex\":\"" << inputHex(seed)
        << "\",\"array_hex\":\"" << inputHex(arrayName) << "\",\"registry_type\":" << registryType
        << ",\"read_index\":" << ordinal << ",\"byte_offsets\":[";
    for (size_t i=0;i<policy.offsets.size();++i) { if(i) out << ',';out << policy.offsets[i]; }
    out << "]}\n";out.close();
    if (!out) s2e()->getExecutor()->terminateState(*state, "Selected input journal write failed");
}

// Preserve the exact printable-ASCII domain introduced by selected-input
// models through the real Windows conversion. No status or output length is
// invented: the native call runs on its current concrete seed and its output
// is checked before symbolic byte expressions are propagated.
void FunctionCallLogger::prepareAsciiConversion(S2EExecutionState *state, ObservedWindowsCall &call) {
    if (!m_preserveAsciiConversions || !m_selectedInput.enabled || m_asciiConversions >= 64 ||
        call.api != "WideCharToMultiByte" || !call.recordEffect || call.diagnostic ||
        (call.args[0] != 0 && call.args[0] != 3 && call.args[0] != 65001 && call.args[0] != 1252) || call.args[1] ||
        !call.args[2] || ((!call.args[4]) != (!call.args[5])) || call.args[6] ||
        (!call.args[3]) || (call.args[3] != UINT32_MAX && call.args[3] > 128)) return;
    DECLARE_PLUGINSTATE(FunctionCallLoggerState, state);
    if (plgState->asciiInputArrays.empty()) return;
    const unsigned bound = call.args[3] == UINT32_MAX ? 128 : call.args[3];
    std::vector<std::pair<uint64_t, klee::ref<klee::Expr>>> originals;
    std::vector<klee::ref<klee::Expr>> output;
    std::string seed;
    std::set<std::string> arrays;
    bool terminated = false;
    bool symbolicOutput = false;
    for (unsigned i = 0; i < bound; ++i) {
        uint64_t address = uint64_t(call.args[2]) + i * 2;
        if (address + 2 > (uint64_t(1) << 32)) return;
        auto high = state->mem()->read(address + 1, klee::Expr::Int8);
        auto low = state->mem()->read(address, klee::Expr::Int8);
        if (!high || !low) return;
        if (auto constant = dyn_cast<klee::ConstantExpr>(high)) {
            if (!constant->isZero()) return;
        } else {
            klee::ArrayVec dependencies;
            klee::findSymbolicObjects(high, dependencies);
            if (dependencies.empty()) return;
            for (const auto &dependency : dependencies)
                if (!plgState->asciiInputArrays.count(dependency->getName())) return;
            bool isZero = false;
            if (!state->solver()->mustBeTrue(
                    klee::Query(state->constraints(), klee::EqExpr::create(
                        high, klee::ConstantExpr::create(0, klee::Expr::Int8))), isZero) ||
                !isZero) return;
            auto concrete = dyn_cast_or_null<klee::ConstantExpr>(state->concolics->evaluate(high));
            if (!concrete || !concrete->isZero()) return;
            originals.emplace_back(address + 1, high);
            for (const auto &dependency : dependencies) arrays.insert(dependency->getName());
        }
        unsigned byte = 0;
        if (auto constant = dyn_cast<klee::ConstantExpr>(low)) {
            byte = constant->getZExtValue();
            if (byte > 127) return;
        } else {
            auto read = dyn_cast<klee::ReadExpr>(low);
            klee::ArrayVec dependencies;
            klee::findSymbolicObjects(low, dependencies);
            if (dependencies.empty()) return;
            for (const auto &dependency : dependencies)
                if (!plgState->asciiInputArrays.count(dependency->getName())) return;
            // A copied byte may be represented by an Extract/Concat or a read
            // with updates. Propagate it only when every possible value is in
            // the 7-bit identity range shared by ACP, thread ACP, UTF-8 and
            // code page 1252. The native output is checked below as well.
            // Solver failure is a fail-closed rejection and changes no state.
            bool isAscii = false;
            if ((!read || read->getUpdates()->getHead()) &&
                (!state->solver()->mustBeTrue(
                     klee::Query(state->constraints(), klee::UleExpr::create(
                         low, klee::ConstantExpr::create(127, klee::Expr::Int8))), isAscii) ||
                 !isAscii)) return;
            auto concrete = dyn_cast_or_null<klee::ConstantExpr>(state->concolics->evaluate(low));
            if (!concrete || concrete->getZExtValue() > 127) return;
            byte = concrete->getZExtValue();
            originals.emplace_back(address, low);
            for (const auto &dependency : dependencies) arrays.insert(dependency->getName());
            symbolicOutput = true;
        }
        seed += static_cast<char>(byte);
        output.push_back(low);
        if (!byte && call.args[3] == UINT32_MAX) { terminated = true; break; }
    }
    if (!symbolicOutput || (call.args[3] == UINT32_MAX && !terminated) ||
        (call.args[4] && call.args[5] < output.size()) || uint64_t(call.args[4]) + output.size() > (uint64_t(1) << 32)) return;
    uint64_t inputEnd = uint64_t(call.args[2]) + output.size() * 2;
    uint64_t outputEnd = uint64_t(call.args[4]) + output.size();
    if (call.args[4] && call.args[4] < inputEnd && call.args[2] < outputEnd) return;
    if (call.args[7] && ((call.args[7] < inputEnd && uint64_t(call.args[7]) + 4 > call.args[2]) ||
        (call.args[4] && call.args[7] < outputEnd && uint64_t(call.args[7]) + 4 > call.args[4]))) return;
    // All checks precede mutation. Failure restores bytes already changed.
    for (size_t i = 0; i < originals.size(); ++i) {
        auto offset = (originals[i].first - call.args[2]) / 2;
        auto replacement = (originals[i].first - call.args[2]) & 1 ? 0 : (uint8_t) seed[offset];
        if (!state->mem()->write(originals[i].first, klee::ConstantExpr::create(replacement, klee::Expr::Int8))) {
            for (size_t j = 0; j < i; ++j) state->mem()->write(originals[j].first, originals[j].second);
            return;
        }
    }
    call.conversionInput = std::move(originals);
    call.conversionOutput = std::move(output);
    call.conversionSeed = std::move(seed);
    call.conversionArrays.assign(arrays.begin(), arrays.end());
    ++m_asciiConversions;
}

void FunctionCallLogger::finishAsciiConversion(S2EExecutionState *state, const ObservedWindowsCall &call, uint32_t result) {
    if (call.conversionInput.empty()) return;
    bool restored = true;
    // Never overwrite a changed input, even on a failed native conversion.
    for (const auto &entry : call.conversionInput) {
        auto current = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(entry.first, klee::Expr::Int8));
        auto offset = (entry.first - call.args[2]) / 2;
        auto expected = (entry.first - call.args[2]) & 1 ? 0 : (uint8_t) call.conversionSeed[offset];
        if (!current || current->getZExtValue() != expected) restored = false;
    }
    if (restored)
        for (const auto &entry : call.conversionInput) restored = state->mem()->write(entry.first, entry.second) && restored;
    bool applied = restored && result == call.conversionOutput.size();
    for (size_t i = 0; applied && call.args[4] && i < call.conversionSeed.size(); ++i) {
        auto byte = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(call.args[4] + i, klee::Expr::Int8));
        if (!byte || byte->getZExtValue() != (uint8_t) call.conversionSeed[i]) applied = false;
    }
    bool writeFailed = false;
    if (applied && call.args[4])
        for (size_t i = 0; i < call.conversionOutput.size(); ++i)
            if (!state->mem()->write(call.args[4] + i, call.conversionOutput[i])) { applied = false; writeFailed = true; }
    std::ofstream out(s2e()->getOutputFilename("selected-input-conversions.jsonl"), std::ios::app);
    out << "{\"schema\":1,\"event\":\"conversion\",\"instance\":" << s2e()->getCurrentInstanceIndex()
        << ",\"state\":" << state->getID() << ",\"pid\":" << call.pid << ",\"lifetime\":" << call.lifetime
        << ",\"depth\":" << call.depth << ",\"time_ns\":"
        << std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
        << ",\"caller_pc\":" << call.callerPc << ",\"api\":\"WideCharToMultiByte\",\"code_page\":" << call.args[0]
        << ",\"native_return\":" << result << ",\"bytes\":" << call.conversionOutput.size()
        << ",\"input_restored\":" << (restored ? "true" : "false") << ",\"applied\":" << (applied ? "true" : "false")
        << ",\"arrays_hex\":[";
    for (size_t i = 0; i < call.conversionArrays.size(); ++i) { if (i) out << ','; out << '\"' << inputHex(call.conversionArrays[i]) << '\"'; }
    out << "]}\n";out.close();
    if (!restored || writeFailed || !out) s2e()->getExecutor()->terminateState(*state, "Selected ASCII conversion could not restore or journal its input");
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

void FunctionCallLogger::observeAccess(S2EExecutionState *state, const ObservedWindowsCall &call, uint32_t result) {
    uint32_t lastError = 0, tid = 0;
    bool errorValid = false;
    if (input_observation::needsLastError(call.api, result) && state->getPointerSize() == 4) {
        target_ulong fs = 0;
        auto read32 = [&](uint64_t address, uint32_t &value) {
            auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(address, klee::Expr::Int32));
            if (!c) return false;
            value = c->getZExtValue(); return true;
        };
        uint32_t self = 0, owner = 0;
        // Windows x86 TEB: Self=0x18, ClientId=0x20/0x24, LastErrorValue=0x34.
        // Validate the TEB against native process context before trusting it.
        if (state->regs()->read(CPU_OFFSET(segs[R_FS].base), &fs, sizeof(fs), false) && fs &&
            fs <= UINT32_MAX - 0x38 && read32(fs + 0x18, self) && self == fs &&
            read32(fs + 0x20, owner) && owner == call.pid && read32(fs + 0x24, tid) && tid &&
            read32(fs + 0x34, lastError)) errorValid = true;
    }
    const char *outcome = input_observation::accessOutcome(call.api, result, call.args[2], errorValid, lastError);
    if (!outcome || call.path.empty()) return;
    auto &journal = m_accessJournals[s2e()->getCurrentInstanceIndex()];
    if (journal.count >= 1024) return;
    const auto key = std::make_tuple(call.pid, call.lifetime, call.depth, call.api, call.path, call.value, call.callerPc);
    if (journal.sources[key] >= 16) return;
    std::ofstream out(s2e()->getOutputFilename("input-accesses.jsonl"), std::ios::app);
    if (!journal.enabled) {
        out << "{\"schema\":2,\"event\":\"enabled\",\"instance\":" << s2e()->getCurrentInstanceIndex()
            << ",\"root_scope\":" << (m_discoverRootInputs ? "true" : "false")
            << ",\"child_scope\":" << (m_discoverChildInputs ? "true" : "false") << "}\n";
    }
    out << "{\"schema\":2,\"event\":\"access\",\"instance\":" << s2e()->getCurrentInstanceIndex()
        << ",\"state\":" << state->getID() << ",\"pid\":" << call.pid << ",\"lifetime\":" << call.lifetime
        << ",\"depth\":" << call.depth << ",\"caller_pc\":" << call.callerPc << ",\"time_ns\":"
        << std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
        << ",\"diagnostic_lineage\":false,\"api\":\"" << call.api << "\",\"path_hex\":\"" << inputHex(call.path)
        << "\",\"value_hex\":\"" << inputHex(call.value) << "\",\"return_value\":" << result
        << ",\"capacity\":" << (call.api.find("GetEnvironmentVariable") == 0 ? call.args[2] : 0)
        << ",\"last_error\":";
    if (errorValid) out << lastError; else out << "null";
    out << ",\"error_tid\":";
    if (errorValid) out << tid; else out << "null";
    out << ",\"open_parameters\":";
    if (call.api.find("CreateFile") == 0)
        out << "{\"desired_access\":" << call.args[1] << ",\"share_mode\":" << call.args[2]
            << ",\"creation_disposition\":" << call.args[4] << ",\"flags_attributes\":" << call.args[5] << "}";
    else out << "null";
    out << ",\"outcome\":\"" << outcome << "\"}\n";
    const auto sourceCount = journal.sources[key] + 1;
    if (sourceCount == 16)
        out << "{\"schema\":2,\"event\":\"source_cap\",\"instance\":" << s2e()->getCurrentInstanceIndex()
            << ",\"limit\":16}\n";
    if (journal.count + 1 == 1024)
        out << "{\"schema\":2,\"event\":\"cap\",\"instance\":" << s2e()->getCurrentInstanceIndex() << ",\"limit\":1024}\n";
    out.close();
    if (!out) { getWarningsStream(state) << "Could not persist input access observation\n"; return; }
    journal.enabled = true;
    ++journal.sources[key];
    ++journal.count;
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
        if (!read32(call.args[3], count)) return;
        if (input_observation::largeReadExtent(count, requested, result != 0, call.args[4] != 0)) {
            observeLargeRead(state, call, result, count);
            return;
        }
        if (
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
        // Passive capture uses the existing 4 KiB input-observation budget.
        // Selected symbolic sources retain their separate 256-byte/16-offset limits.
        // Include a concrete terminator and reject truncation, symbolic units and wraparound.
        for (unsigned offset = 0; offset < 4096; offset += width) {
            if (uint64_t(buffer) + offset + width > (uint64_t(1) << 32)) return;
            auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(buffer) + offset,
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
    const auto time = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    out << "{\"schema\":3,\"event\":\"read\",\"instance\":" << s2e()->getCurrentInstanceIndex()
        << ",\"state\":" << state->getID() << ",\"pid\":" << call.pid << ",\"lifetime\":" << call.lifetime
        << ",\"depth\":" << call.depth << ",\"time_ns\":"
        << time
        << ",\"caller_pc\":" << call.callerPc << ",\"diagnostic_lineage\":false,\"api\":\"" << call.api
        << "\",\"path_hex\":\"" << inputHex(call.path) << "\",\"value_hex\":\"" << inputHex(call.value)
        << "\",\"seed_hex\":\"" << inputHex(seed) << "\",\"count\":" << count << ",\"requested\":" << requested
        << ",\"registry_type\":" << registryType << ",\"return_value\":" << result << ",\"overlapped\":false}\n";
    out.close();
    if (!out) { getWarningsStream(state) << "Could not persist native input observation\n"; return; }
    modelSelectedInput(state, call, buffer, seed, registryType, time);
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

void FunctionCallLogger::observeLargeRead(S2EExecutionState *state, const ObservedWindowsCall &call,
                                         uint32_t result, uint32_t count) {
    if (m_largeReads >= 256 || !call.args[1] || uint64_t(call.args[1]) + count > (uint64_t(1) << 32)) return;
    std::string prefix, suffix;
    auto capture = [&](uint64_t start, std::string &bytes) {
        for (unsigned i = 0; i < 2048; ++i) {
            auto byte = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(start + i, klee::Expr::Int8));
            if (!byte) return false;
            bytes += static_cast<char>(byte->getZExtValue());
        }
        return true;
    };
    // A symbolic or unreadable sample is not a completed concrete summary.
    if (!capture(call.args[1], prefix) || !capture(uint64_t(call.args[1]) + count - 2048, suffix)) return;
    std::ofstream out(s2e()->getOutputFilename("large-input-reads.jsonl"), std::ios::app);
    out << "{\"schema\":1,\"event\":\"read_summary\",\"instance\":" << s2e()->getCurrentInstanceIndex()
        << ",\"state\":" << state->getID() << ",\"pid\":" << call.pid << ",\"lifetime\":" << call.lifetime
        << ",\"depth\":" << call.depth << ",\"time_ns\":"
        << std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
        << ",\"caller_pc\":" << call.callerPc << ",\"api\":\"ReadFile\",\"diagnostic_lineage\":false"
        << ",\"path_hex\":\"" << inputHex(call.path) << "\",\"handle\":" << call.args[0]
        << ",\"buffer\":" << call.args[1] << ",\"count\":" << count << ",\"requested\":" << call.requested
        << ",\"return_value\":" << result << ",\"overlapped\":false,\"complete_buffer\":false"
        << ",\"prefix_hex\":\"" << inputHex(prefix) << "\",\"suffix_hex\":\"" << inputHex(suffix) << "\"}\n";
    out.close();
    if (!out) s2e()->getExecutor()->terminateState(*state, "Large input summary journal write failed");
    ++m_largeReads;
}

bool FunctionCallLogger::prepareNetworkCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                                            ObservedWindowsCall &call) {
    if (!m_observeNetwork || !source || call.diagnostic || m_networkCalls >= 256) return false;
    call.network = true;
    call.module = source->Name;
    auto readBytes = [&](uint64_t address, uint32_t size, std::string &value) {
        if (!address || uint64_t(address) + size > (uint64_t(1) << 32)) return false;
        for (uint32_t i = 0; i < size; ++i) {
            auto byte = dyn_cast_or_null<klee::ConstantExpr>(
                state->mem()->read(address + i, klee::Expr::Int8));
            if (!byte) return false;
            value += static_cast<char>(byte->getZExtValue());
        }
        return true;
    };
    if (call.api == "socket") {
        call.socket = call.args[1];
    } else if (call.api == "connect" || call.api == "bind") {
        call.socket = call.args[0];
        call.addressLength = call.args[2];
        if (!input_observation::networkAddressExtent(call.addressLength) ||
            !readBytes(call.args[1], call.addressLength, call.originalSockaddr)) return false;
        call.effectiveSockaddr = call.originalSockaddr;
    } else if (call.api == "send" || call.api == "recv") {
        call.socket = call.args[0];
        call.requested = call.args[2];
        call.flags = call.args[3];
        if (call.requested > 65536) return false;
        if (call.api == "send") {
            const uint32_t extent = std::min(call.requested, uint32_t(512));
            call.bufferConcrete = readBytes(call.args[1], extent, call.bufferPrefix);
            if (!call.bufferConcrete) call.bufferPrefix.clear();
        }
    } else if (call.api == "closesocket") {
        call.socket = call.args[0];
    } else if (call.api == "listen") {
        call.socket = call.listenerSocket = call.args[0];
        call.backlog = call.args[1];
    } else if (call.api == "accept") {
        call.socket = call.listenerSocket = call.args[0];
    } else {
        return false;
    }
    const bool scopeMatches = (call.depth == 0) == (m_connectRedirect.scope == "root");
    if (m_connectRedirect.enabled && call.api == "connect" && scopeMatches &&
        call.module == m_connectRedirect.module && call.callerPc >= source->LoadBase &&
        call.callerPc - source->LoadBase == m_connectRedirect.rva &&
        input_observation::sameIpv4Endpoint(call.originalSockaddr, m_connectRedirect.sockaddr)) {
        std::string code;
        std::string original;
        for (unsigned i = 0; i < 12; i += 2)
            original += static_cast<char>(std::stoul(m_connectRedirect.code.substr(i, 2), nullptr, 16));
        if (readBytes(call.callerPc, 6, code) &&
            (m_connectRedirect.relocatedOperand ?
                source->NativeBase == m_connectRedirect.preferredBase && source->Size == m_connectRedirect.imageSize &&
                input_observation::relocatedIndirectCall(code, original, source->NativeBase, source->LoadBase, source->Size) :
                inputHex(code) == m_connectRedirect.code) &&
            m_connectRedirect.loopback) {
            DECLARE_PLUGINSTATE(FunctionCallLoggerState, state);
            auto identity = std::make_tuple(call.pid, call.lifetime, call.socket);
            if (!plgState->redirectedSockets.count(identity) && plgState->redirectedSockets.size() >= 32)
                return false;
            static const unsigned char loopback[16] = {
                0x02, 0x00, 0x7a, 0x69, 0x7f, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            };
            if (call.addressLength != sizeof(loopback) ||
                !state->mem()->write(call.args[1], loopback, sizeof(loopback))) {
                if (!state->mem()->write(call.args[1], call.originalSockaddr.data(), call.originalSockaddr.size()))
                    s2e()->getExecutor()->terminateState(*state, "Network redirect could not restore sockaddr");
                return false;
            }
            call.effectiveSockaddr.assign(reinterpret_cast<const char *>(loopback), sizeof(loopback));
            call.redirected = true;
            plgState->redirectedSockets.insert(identity);
        }
    }
    call.callId = ++m_networkCalls;
    recordNetworkEvent(state, call, "enter", 0);
    return true;
}

void FunctionCallLogger::recordNetworkEvent(S2EExecutionState *state, const ObservedWindowsCall &call,
                                            const char *event, uint32_t result) {
    std::ofstream out(s2e()->getOutputFilename("network-events.jsonl"), std::ios::app);
    out << "{\"schema\":2,\"instance\":" << s2e()->getCurrentInstanceIndex()
        << ",\"state\":" << state->getID() << ",\"pid\":" << call.pid
        << ",\"lifetime\":" << call.lifetime << ",\"depth\":" << call.depth
        << ",\"time_ns\":"
        << std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch()).count()
        << ",\"call_id\":" << call.callId << ",\"event\":\"" << event
        << "\",\"api\":\"" << call.api << "\",\"module_hex\":\"" << inputHex(call.module)
        << "\",\"caller_pc\":" << call.callerPc << ",\"socket\":" << call.socket
        << ",\"requested\":" << call.requested << ",\"flags\":" << call.flags
        << ",\"result\":" << result << ",\"original_sockaddr_hex\":\""
        << inputHex(call.originalSockaddr) << "\",\"effective_sockaddr_hex\":\""
        << inputHex(call.effectiveSockaddr) << "\",\"address_length\":" << call.addressLength
        << ",\"peer_sockaddr_hex\":\"" << inputHex(call.peerSockaddr)
        << "\",\"listener_socket\":" << call.listenerSocket
        << ",\"accepted_socket\":" << call.acceptedSocket << ",\"backlog\":" << call.backlog
        << ",\"redirected\":" << (call.redirected ? "true" : "false")
        << ",\"buffer_prefix_hex\":\"" << inputHex(call.bufferPrefix)
        << "\",\"buffer_concrete\":" << (call.bufferConcrete ? "true" : "false") << "}\n";
    out.close();
    if (!out) s2e()->getExecutor()->terminateState(*state, "Network journal write failed");
}

void FunctionCallLogger::recordAudioEvent(S2EExecutionState *state, const ObservedWindowsCall &call,
                                          const char *event, uint32_t result) {
    std::ofstream out(s2e()->getOutputFilename("audio-events.jsonl"), std::ios::app);
    out << "{\"schema\":1,\"instance\":" << s2e()->getCurrentInstanceIndex()
        << ",\"state\":" << state->getID() << ",\"pid\":" << call.pid
        << ",\"lifetime\":" << call.lifetime << ",\"depth\":" << call.depth
        << ",\"time_ns\":"
        << std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch()).count()
        << ",\"call_id\":" << call.callId << ",\"event\":\"" << event
        << "\",\"api\":\"" << call.api << "\",\"module_hex\":\"" << inputHex(call.module)
        << "\",\"caller_pc\":" << call.callerPc << ",\"result\":" << result
        << ",\"handle\":" << call.socket << ",\"arg0\":" << call.args[0]
        << ",\"arg1\":" << call.args[1] << ",\"arg2\":" << call.args[2]
        << ",\"callback\":" << call.args[3] << ",\"instance_value\":" << call.args[4]
        << ",\"flags\":" << call.args[5] << ",\"format_hex\":\""
        << inputHex(call.bufferPrefix) << "\",\"format_concrete\":"
        << (call.bufferConcrete ? "true" : "false") << "}\n";
    out.close();
    if (!out) s2e()->getExecutor()->terminateState(*state, "Audio journal write failed");
}

// Passive category observations preserve void-return semantics and bounded concrete outputs.
void FunctionCallLogger::recordCategory(S2EExecutionState *state, const ObservedWindowsCall &call,
                                       bool returned, uint32_t result) {
    auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    const bool wallTime = call.api == "GetSystemTime" || call.api == "GetLocalTime";
    const bool fileTime = call.api == "GetSystemTimeAsFileTime" || call.api == "GetSystemTimePreciseAsFileTime";
    const bool computerName = call.api == "GetComputerNameA" || call.api == "GetComputerNameW";
    const bool accountEnum = call.api == "NetUserEnum";
    const bool groupEnum = call.api == "NetGroupEnum" || call.api == "NetLocalGroupEnum";
    const bool enumerated = (accountEnum || groupEnum) && (result == 0 || result == 234);
    const bool voidResult = wallTime || fileTime || call.api == "keybd_event" || call.api == "mouse_event" || call.api == "DeleteProcThreadAttributeList";
    std::ofstream out(s2e()->getOutputFilename("category-observations.jsonl"), std::ios::app);
    out << "{\"schema\":1,\"instance\":" << s2e()->getCurrentInstanceIndex()
        << ",\"state\":" << state->getID() << ",\"pid\":" << call.pid
        << ",\"lifetime\":" << call.lifetime << ",\"depth\":" << call.depth
        << ",\"diagnostic_lineage\":false,\"call_id\":" << call.callId
        << ",\"time_ns\":" << (returned ? now : call.entryTime) << ",\"entry_time_ns\":" << call.entryTime
        << ",\"event\":\"" << (returned ? "return" : "enter") << "\",\"api\":\"" << call.api
        << "\",\"module_hex\":\"" << inputHex(call.module) << "\",\"caller_pc\":" << call.callerPc
        << ",\"callee_pc\":" << call.calleePc << ",\"path_hex\":\"" << inputHex(call.path)
        << "\",\"return_semantics\":\"" << (voidResult ? "void" : "value") << "\",\"args\":[";
    for (unsigned i = 0; i < call.argumentCount; ++i) {
        if (i) out << ',';
        out << call.args[i];
    }
    out << ']';
    if (computerName) out << ",\"input_capacity\":" << call.requested;
    if (accountEnum || groupEnum)
        out << ",\"server_name_concrete\":" << (call.bufferConcrete ? "true" : "false")
            << ",\"server_name_hex\":\"" << inputHex(call.data) << "\"";
    const bool processCreate = call.api == "CreateProcessA" || call.api == "CreateProcessW" ||
        call.api == "CreateProcessAsUserA" || call.api == "CreateProcessAsUserW" || call.api == "CreateProcessWithTokenW";
    if (processCreate)
        out << ",\"process_command_line_hex\":\"" << inputHex(call.value)
            << "\",\"process_startup_info_concrete\":" << (call.bufferConcrete ? "true" : "false")
            << ",\"process_startup_info_hex\":\"" << inputHex(call.bufferPrefix) << "\"";
    if (call.api == "PowerWriteACValueIndex" || call.api == "PowerSetActiveScheme")
        out << ",\"power_input_guids_concrete\":" << (call.bufferConcrete ? "true" : "false")
            << ",\"power_input_guids_hex\":\"" << inputHex(call.bufferPrefix) << "\"";
    if (call.api == "NetScheduleJobAdd")
        out << ",\"schedule_input_fields_concrete\":" << (call.bufferConcrete ? "true" : "false")
            << ",\"schedule_input_fields_hex\":\"" << inputHex(call.bufferPrefix)
            << "\",\"schedule_command_hex\":\"" << inputHex(call.value) << "\"";
    if (call.api == "OpenSCManagerA" || call.api == "OpenSCManagerW")
        out << ",\"service_database_hex\":\"" << inputHex(call.value) << "\"";
    if (call.api == "CreateServiceA" || call.api == "CreateServiceW")
        out << ",\"service_binary_path_hex\":\"" << inputHex(call.value) << "\"";
    if (call.api == "UpdateProcThreadAttribute")
        out << ",\"parent_attribute_concrete\":" << (call.bufferConcrete ? "true" : "false")
            << ",\"parent_attribute_value_hex\":\"" << inputHex(call.bufferPrefix)
            << "\",\"requested_parent_pid\":" << call.targetPid;
    if (call.api == "_write")
        out << ",\"crt_buffer_address\":" << call.args[1]
            << ",\"crt_buffer_concrete\":" << (call.bufferConcrete ? "true" : "false")
            << ",\"crt_buffer_hex\":\"" << inputHex(call.bufferPrefix) << "\"";
    if (call.api == "DllRegisterServer")
        out << ",\"callback_module_base\":" << call.calleeModuleBase
            << ",\"callback_export_rva\":" << (call.calleePc - call.calleeModuleBase)
            << ",\"callback_code_address\":" << call.calleePc
            << ",\"callback_code_concrete\":" << (call.bufferConcrete ? "true" : "false")
            << ",\"callback_code_hex\":\"" << inputHex(call.bufferPrefix) << "\"";
    const bool adminNet = call.api == "NetUserAdd" || call.api == "NetLocalGroupAddMembers" || call.api == "NetUserModalsGet" || call.api == "NetUserGetInfo" || call.api == "NetUserDel";
    if (adminNet)
        out << ",\"server_name_concrete\":" << (call.serverConcrete ? "true" : "false")
            << ",\"server_name_hex\":\"" << inputHex(call.data) << "\"";
    if (call.api == "NetUserAdd" || call.api == "NetLocalGroupAddMembers")
        out << ",\"admin_input_concrete\":" << (call.bufferConcrete ? "true" : "false")
            << ",\"admin_input_hex\":\"" << inputHex(call.bufferPrefix)
            << "\",\"subject_name_hex\":\"" << inputHex(call.value) << "\",\"input_subject_address\":" << call.requested;
    if (call.api == "GetExtendedTcpTable" || call.api == "SetupDiEnumDeviceInfo")
        out << ",\"input_capacity\":" << call.requested;
    if (call.api == "SendInput" || call.api == "SetSecurityInfo")
        out << ",\"input_buffer_concrete\":" << (call.bufferConcrete ? "true" : "false")
            << ",\"input_buffer_hex\":\"" << inputHex(call.bufferPrefix) << "\"";
    if (call.api == "CertAddEncodedCertificateToStore" || call.api == "CertAddCertificateContextToStore")
        out << ",\"certificate_encoding\":" << call.certificateEncoding
            << ",\"certificate_data_address\":" << call.certificateDataAddress
            << ",\"certificate_data_bytes\":" << call.certificateDataBytes
            << ",\"certificate_data_concrete\":" << (call.bufferConcrete ? "true" : "false")
            << ",\"certificate_data_hex\":\"" << inputHex(call.bufferPrefix)
            << "\",\"certificate_context_hex\":\"" << inputHex(call.data) << "\"";
    if (call.api == "EvtQuery") out << ",\"query_hex\":\"" << inputHex(call.value) << "\"";
    if (returned) {
        if (!voidResult) out << ",\"result\":" << result;
        out << ",\"outputs\":[";
        bool first = true;
        auto output = [&](unsigned index, unsigned size) {
            std::string bytes;
            bool concrete = call.args[index] && uint64_t(call.args[index]) + size <= (uint64_t(1) << 32);
            for (unsigned i = 0; concrete && i < size; ++i) {
                auto c = dyn_cast_or_null<klee::ConstantExpr>(
                    state->mem()->read(uint64_t(call.args[index]) + i, klee::Expr::Int8));
                if (!c) { concrete = false; bytes.clear(); break; }
                bytes += char(c->getZExtValue());
            }
            if (!first) out << ',';
            first = false;
            out << "{\"arg_index\":" << index << ",\"address\":" << call.args[index]
                << ",\"size\":" << size << ",\"concrete\":" << (concrete ? "true" : "false")
                << ",\"hex\":\"" << inputHex(bytes) << "\"}";
        };
        if (processCreate && result) output(call.api == "CreateProcessWithTokenW" ? 8 :
            (call.api == "CreateProcessAsUserA" || call.api == "CreateProcessAsUserW" ? 10 : 9), 16);
        if (call.api == "SetupDiEnumDeviceInfo" && result) output(2, 28);
        if (call.api == "GetExtendedTcpTable" && result == 0) output(1, 4);
        if (call.api == "NetUserModalsGet" && result == 0) output(2, 4);
        if (call.api == "NetScheduleJobAdd" && result == 0) output(2, 4);
        if (call.api == "NetUserGetInfo" && result == 0) output(3, 4);
        if (call.api == "PowerGetActiveScheme" && result == 0) output(1, 4);
        if (call.api == "QueryServiceStatus" && result) output(1, 28);
        if (call.api == "QueryServiceStatusEx" && result && call.args[1] == 0 && call.args[3] >= 36) output(2, 36);
        if (wallTime || fileTime) output(0, wallTime ? 16 : 8);
        if ((call.api == "NtOpenFile" || call.api == "ZwOpenFile") && result == 0) {
            output(0, 4);
            output(3, 8);
        }
        if (call.api == "EvtNext" && result) { output(2, 4); output(5, 4); }
        if (computerName && result) {
            output(0, call.api.back() == 'W' ? 32 : 16);
            output(1, 4);
        }
        if (call.api.find("GetDiskFreeSpaceEx") == 0 && result)
            for (unsigned i = 1; i <= 3; ++i) output(i, 8);
        if (call.api.find("GetVolumeInformation") == 0 && result)
            for (unsigned i = 3; i <= 5; ++i) output(i, 4);
        if (enumerated) {
            output(accountEnum ? 3 : 2, 4);
            output(accountEnum ? 5 : 4, 4);
            output(accountEnum ? 6 : 5, 4);
        }
        out << "]";
        if (processCreate) {
            const unsigned index = call.api == "CreateProcessWithTokenW" ? 8 :
                (call.api == "CreateProcessAsUserA" || call.api == "CreateProcessAsUserW" ? 10 : 9);
            auto readInfo32 = [&](unsigned offset, uint32_t &value) {
                if (!result || !call.args[index] || uint64_t(call.args[index]) + 16 > (uint64_t(1) << 32)) return false;
                auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(call.args[index]) + offset, klee::Expr::Int32));
                if (!c) return false;
                value = c->getZExtValue(); return true;
            };
            uint32_t child = 0, handle = 0, parent = 0, handlePid = 0;
            auto monitor = s2e()->getPlugin<WindowsMonitor>();
            bool known = readInfo32(8, child) && child && child != call.pid && readInfo32(0, handle) && handle;
            if (known) {
                uint64_t object = monitor->getProcess(state, child), owner = monitor->getProcessParent(state, child);
                known = object && object != UINT64_MAX && owner && owner <= UINT32_MAX;
                if (known) parent = owner;
                const uint64_t resolved = monitor->getPidFromHandle(state, call.pid, handle);
                if (resolved <= UINT32_MAX) handlePid = resolved;
            }
            out << ",\"created_process_kernel_confirmed\":" << (known ? "true" : "false")
                << ",\"created_process_parent_pid\":" << parent
                << ",\"created_process_handle_pid\":" << handlePid;
        }

        if (call.api == "PowerGetActiveScheme") {
            uint32_t address = 0;
            auto pointer = (result == 0 && call.args[1] && uint64_t(call.args[1]) + 4 <= (uint64_t(1) << 32)) ?
                dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(call.args[1], klee::Expr::Int32)) : nullptr;
            if (pointer) address = pointer->getZExtValue();
            bool concrete = pointer && address && uint64_t(address) + 16 <= (uint64_t(1) << 32);
            std::string data;
            for (unsigned i = 0; concrete && i < 16; ++i) {
                auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(address) + i, klee::Expr::Int8));
                if (!c) { concrete = false; break; }
                data += char(c->getZExtValue());
            }
            if (!concrete) data.clear();
            out << ",\"power_active_guid_address\":" << address
                << ",\"power_active_guid_concrete\":" << (concrete ? "true" : "false")
                << ",\"power_active_guid_hex\":\"" << inputHex(data) << "\"";
        }
        if (call.api == "NetUserModalsGet" || call.api == "GetExtendedTcpTable" || call.api == "NetUserGetInfo") {
            uint32_t address = 0, size = 0;
            auto readConcrete32 = [&](uint64_t p, uint32_t &v) {
                if (!p || p + 4 > (uint64_t(1) << 32)) return false;
                auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(p, klee::Expr::Int32));
                if (!c) return false; v = c->getZExtValue(); return true;
            };
            bool concrete = result == 0;
            if (call.api == "NetUserGetInfo") {
                concrete = concrete && call.args[2] == 3 && readConcrete32(call.args[3], address);
                size = concrete ? 28 : 0;
            } else if (call.api == "NetUserModalsGet") {
                concrete = concrete && call.args[1] == 0 && readConcrete32(call.args[2], address);
                size = concrete ? 20 : 0;
            } else {
                address = call.args[0];
                concrete = concrete && readConcrete32(call.args[1], size) && size <= call.requested;
            }
            concrete = concrete && address && size && size <= 4096 && uint64_t(address) + size <= (uint64_t(1) << 32);
            std::string data;
            for (uint32_t i = 0; concrete && i < size; ++i) {
                auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(address) + i, klee::Expr::Int8));
                if (!c) { concrete = false; break; }
                data += char(c->getZExtValue());
            }
            if (!concrete) data.clear();
            out << ",\"result_buffer_address\":" << address << ",\"result_buffer_bytes\":" << size
                << ",\"result_buffer_concrete\":" << (concrete ? "true" : "false")
                << ",\"result_buffer_hex\":\"" << inputHex(data) << "\"";
            if (call.api == "NetUserGetInfo") {
                uint32_t name = 0;
                bool nameConcrete = concrete && readConcrete32(address, name) && name && uint64_t(name) + 256 <= (uint64_t(1) << 32);
                std::string text;
                bool terminated = false;
                for (unsigned i = 0; nameConcrete && i < 128; ++i) {
                    auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(name) + 2 * i, klee::Expr::Int16));
                    if (!c || c->getZExtValue() > 127) { nameConcrete = false; break; }
                    const uint16_t value = c->getZExtValue();
                    text += char(value); text += char(value >> 8);
                    if (!value) { terminated = true; break; }
                }
                nameConcrete = nameConcrete && terminated;
                if (!nameConcrete) text.clear();
                out << ",\"result_subject_name_address\":" << name
                    << ",\"result_subject_name_concrete\":" << (nameConcrete ? "true" : "false")
                    << ",\"result_subject_name_hex\":\"" << inputHex(text) << "\"";
            }
        }
        if (enumerated) {
            auto read32 = [&](uint32_t address, uint32_t &value) {
                if (!address || uint64_t(address) + 4 > (uint64_t(1) << 32)) return false;
                auto expression = state->mem()->read(address, klee::Expr::Int32);
                auto constant = dyn_cast_or_null<klee::ConstantExpr>(expression);
                if (!constant) return false;
                value = constant->getZExtValue();
                return true;
            };
            uint32_t buffer = 0, entries = 0, name = 0;
            const bool bufferConcrete = read32(call.args[accountEnum ? 3 : 2], buffer);
            const bool entryConcrete = bufferConcrete && read32(call.args[accountEnum ? 5 : 4], entries)
                && entries && call.args[1] <= 1 && read32(buffer, name);
            std::string firstEntry, firstName;
            if (entryConcrete)
                for (unsigned i = 0; i < 4; ++i) firstEntry += char(name >> (8 * i));
            bool nameConcrete = false;
            if (entryConcrete && name && uint64_t(name) + 256 <= (uint64_t(1) << 32)) {
                for (unsigned i = 0; i < 128; ++i) {
                    auto expression = state->mem()->read(uint64_t(name) + 2 * i, klee::Expr::Int16);
                    auto constant = dyn_cast_or_null<klee::ConstantExpr>(expression);
                    if (!constant) { firstName.clear(); break; }
                    const uint16_t value = constant->getZExtValue();
                    firstName += char(value);
                    firstName += char(value >> 8);
                    if (!value) { nameConcrete = true; break; }
                }
            }
            if (!nameConcrete) firstName.clear();
            out << ",\"enumeration\":{\"buffer_address\":" << buffer
                << ",\"buffer_concrete\":" << (bufferConcrete ? "true" : "false")
                << ",\"first_entry_hex\":\"" << inputHex(firstEntry)
                << "\",\"first_entry_concrete\":" << (entryConcrete ? "true" : "false")
                << ",\"first_name_address\":" << name << ",\"first_name_hex\":\"" << inputHex(firstName)
                << "\",\"first_name_concrete\":" << (nameConcrete ? "true" : "false") << '}';
        }
    }
    out << "}\n";
    out.close();
    if (!out) s2e()->getExecutor()->terminateState(*state, "Category observation journal write failed");
}

// Passive, bounded lifecycle evidence. Never chooses symbolic values.
void FunctionCallLogger::recordLifecycle(S2EExecutionState *state, const ObservedWindowsCall &call,
                                         bool returned, uint32_t result) {
    if (!call.lifecycle) return;
    auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    std::ofstream out(s2e()->getOutputFilename("api-lifecycle.jsonl"), std::ios::app);
    out << "{\"schema\":1,\"instance\":" << s2e()->getCurrentInstanceIndex()
        << ",\"state\":" << state->getID() << ",\"pid\":" << call.pid
        << ",\"lifetime\":" << call.lifetime << ",\"depth\":" << call.depth
        << ",\"diagnostic_lineage\":false,\"call_id\":" << call.callId
        << ",\"time_ns\":" << (returned ? now : call.entryTime) << ",\"entry_time_ns\":" << call.entryTime
        << ",\"event\":\"" << (returned ? "return" : "enter") << "\",\"api\":\"" << call.api
        << "\",\"module_hex\":\"" << inputHex(call.module) << "\",\"caller_pc\":" << call.callerPc
        << ",\"callee_pc\":" << call.calleePc << ",\"path_hex\":\"" << inputHex(call.path)
        << "\",\"value_hex\":\"" << inputHex(call.value) << "\",\"requested\":" << call.requested
        << ",\"input_capacity\":0";
    if (call.api == "RegSetValueExA" || call.api == "RegSetValueExW") {
        out << ",\"registry_type\":" << call.args[3]
            << ",\"registry_data_address\":" << call.args[4] << ",\"registry_data_bytes\":" << call.args[5]
            << ",\"registry_data_concrete\":" << (call.bufferConcrete ? "true" : "false")
            << ",\"registry_data_hex\":\"" << inputHex(call.bufferPrefix) << "\"";
    }
    if (call.api.find("Reg") == 0) {
        out << ",\"registry_handle\":" << call.args[0]
            << ",\"registry_arguments\":[";
        for (unsigned i = 0; i < call.argumentCount; ++i) {
            if (i) out << ',';
            out << call.args[i];
        }
        out << ']';
        if (call.api.find("RegOpenKey") == 0 || call.api.find("RegCreateKey") == 0) {
            unsigned index = (call.api == "RegOpenKeyA" || call.api == "RegOpenKeyW") ? 2 :
                             (call.api.find("RegOpenKey") == 0 ? 4 : 7);
            out << ",\"registry_output_address\":" << call.args[index];
            if (returned) {
                auto c = (result == 0 && call.args[index]) ? dyn_cast_or_null<klee::ConstantExpr>(
                    state->mem()->read(call.args[index], klee::Expr::Int32)) : nullptr;
                out << ",\"registry_output_concrete\":" << (c ? "true" : "false")
                    << ",\"registry_output_handle\":" << (c ? c->getZExtValue() : 0);
            }
        }
        if (call.api.find("RegSaveKey") == 0)
            out << ",\"registry_save_flags\":" << (call.api.find("RegSaveKeyEx") == 0 ? call.args[3] : 1);
    }
    const bool io = call.api == "ReadFile" || call.api == "WriteFile";
    if (io || call.api == "CloseHandle") out << ",\"handle\":" << call.args[0];
    if (call.api == "GetProcAddress") out << ",\"module_handle\":" << call.args[0];
    if (io) {
        out << ",\"overlapped\":" << (call.args[4] ? "true" : "false")
            << ",\"count_address\":" << call.args[3];
        if (returned) {
            auto c = call.args[3] ? dyn_cast_or_null<klee::ConstantExpr>(
                state->mem()->read(call.args[3], klee::Expr::Int32)) : nullptr;
            bool valid = result && !call.args[4] && c && c->getZExtValue() <= call.args[2];
            out << ",\"io_count_concrete\":" << (valid ? "true" : "false")
                << ",\"io_count\":" << (valid ? c->getZExtValue() : 0);
        }
    }
    if (call.api == "CredEnumerateA" || call.api == "CredEnumerateW") {
        out << ",\"credential_flags\":" << call.args[1]
            << ",\"credential_count_address\":" << call.args[2]
            << ",\"credential_array_address\":" << call.args[3];
        if (returned) {
            auto read32 = [&](uint32_t address, uint32_t &value) {
                auto c = address ? dyn_cast_or_null<klee::ConstantExpr>(
                    state->mem()->read(address, klee::Expr::Int32)) : nullptr;
                if (!c) return false;
                value = c->getZExtValue(); return true;
            };
            uint32_t count = 0, array = 0;
            bool valid = result && read32(call.args[2], count) && read32(call.args[3], array) &&
                         count <= 4096 && (!count || array);
            out << ",\"credential_count\":" << (valid ? count : 0)
                << ",\"credential_array\":" << (valid ? array : 0)
                << ",\"credential_output_concrete\":" << (valid ? "true" : "false");
        }
    }
    const bool remoteProcess = call.api == "VirtualAllocEx" || call.api == "WriteProcessMemory" ||
                               call.api == "VirtualProtectEx" || call.api == "CreateRemoteThread";
    if (remoteProcess) {
        out << ",\"process_handle\":" << call.args[0] << ",\"target_pid\":" << call.targetPid;
        if (call.api == "VirtualAllocEx") {
            out << ",\"requested_base\":" << call.args[1] << ",\"region_size\":" << call.args[2]
                << ",\"allocation_type\":" << call.args[3] << ",\"protection\":" << call.args[4];
            if (returned) out << ",\"remote_base\":" << result;
        } else if (call.api == "WriteProcessMemory") {
            out << ",\"remote_base\":" << call.args[1] << ",\"source_buffer\":" << call.args[2]
                << ",\"bytes_written_address\":" << call.args[4]
                << ",\"buffer_prefix_hex\":\"" << inputHex(call.bufferPrefix)
                << "\",\"buffer_prefix_concrete\":" << (call.bufferConcrete ? "true" : "false")
                << ",\"buffer_prefix_bytes\":" << call.bufferPrefix.size();
            if (returned) {
                auto count = call.args[4] ? dyn_cast_or_null<klee::ConstantExpr>(
                    state->mem()->read(call.args[4], klee::Expr::Int32)) : nullptr;
                const bool inferred = result && !call.args[4];
                const bool valid = inferred || (result && count && count->getZExtValue() <= call.args[3]);
                out << ",\"bytes_written_concrete\":" << (valid ? "true" : "false")
                    << ",\"bytes_written\":" << (valid ? (inferred ? call.args[3] : count->getZExtValue()) : 0)
                    << ",\"bytes_written_inferred_from_success\":" << (inferred ? "true" : "false");
            }
        } else if (call.api == "VirtualProtectEx") {
            out << ",\"remote_base\":" << call.args[1] << ",\"region_size\":" << call.args[2]
                << ",\"protection\":" << call.args[3]
                << ",\"old_protection_address\":" << call.args[4];
            if (returned) {
                auto old = call.args[4] ? dyn_cast_or_null<klee::ConstantExpr>(
                    state->mem()->read(call.args[4], klee::Expr::Int32)) : nullptr;
                const bool valid = result && old;
                out << ",\"old_protection_concrete\":" << (valid ? "true" : "false")
                    << ",\"old_protection\":" << (valid ? old->getZExtValue() : 0);
            }
        } else {
            out << ",\"stack_size\":" << call.args[2] << ",\"start_address\":" << call.args[3]
                << ",\"parameter\":" << call.args[4] << ",\"creation_flags\":" << call.args[5]
                << ",\"thread_id_address\":" << call.args[6]
                << ",\"thread_start_module_hex\":\"" << inputHex(call.threadStartModule)
                << "\",\"thread_start_symbol_hex\":\"" << inputHex(call.threadStartSymbol)
                << "\",\"thread_start_module_base\":" << call.threadStartModuleBase
                << ",\"thread_start_rva\":" << call.threadStartRva;
            if (returned) {
                auto tid = call.args[6] ? dyn_cast_or_null<klee::ConstantExpr>(
                    state->mem()->read(call.args[6], klee::Expr::Int32)) : nullptr;
                out << ",\"thread_id_concrete\":" << (result && tid ? "true" : "false")
                    << ",\"thread_id\":" << (result && tid ? tid->getZExtValue() : 0);
            }
        }
    }
    if (call.api.find("CreateFile") == 0)
        out << ",\"desired_access\":" << call.args[1] << ",\"creation_disposition\":" << call.args[4]
            << ",\"file_flags\":" << call.args[5];
    if (returned) {
        bool success = call.api.find("Reg") == 0 ? result == 0 :
            (call.api.find("CreateFile") == 0 ? result != UINT32_MAX : result != 0);
        out << ",\"result\":" << result << ",\"success\":" << (success ? "true" : "false")
            << ",\"elapsed_ns\":" << now - call.entryTime;
    }
    out << "}\n";
    out.close();
    if (!out) s2e()->getExecutor()->terminateState(*state, "API lifecycle journal write failed");
}

void FunctionCallLogger::onCall(S2EExecutionState *state, const ModuleDescriptorConstPtr &source,
                                const ModuleDescriptorConstPtr &dest, uint64_t callerPc, uint64_t calleePc,
                                const FunctionMonitor::ReturnSignalPtr &returnSignal) {
    if (!(m_observeWindowsEffects || m_discoverRootInputs || m_discoverChildInputs ||
          m_observeNetwork || m_observeAudio) ||
        state->getPointerSize() != 4 || !dest)
        return;
    const bool networkModule = dest->Name == "ws2_32.dll";
    const bool audioModule = dest->Name == "winmm.dll";
    if (dest->Name != "kernel32.dll" && dest->Name != "kernelbase.dll" && dest->Name != "advapi32.dll" &&
        dest->Name != "user32.dll" && dest->Name != "netapi32.dll" && dest->Name != "samcli.dll" && dest->Name != "wevtapi.dll" && dest->Name != "ntdll.dll" && dest->Name != "crypt32.dll" && dest->Name != "iphlpapi.dll" && dest->Name != "setupapi.dll" && dest->Name != "cryptdlg.dll" && dest->Name != "msvcrt.dll" && dest->Name != "powrprof.dll" && dest->Name != "sechost.dll" && dest->Name != "schedcli.dll" &&
        !(m_observeNetwork && networkModule) && !(m_observeAudio && audioModule))
        return;
    ObservedWindowsCall call;
    call.callerPc = callerPc;
    // FunctionMonitor exposes preferred/native coordinates to its subscribers;
    // memory inspection, RVA gates and native journals require runtime PCs.
    // Keep calleePc native for the PE export lookup below.
    if (source && (!source->ToRuntime(callerPc, call.callerPc) || call.callerPc > UINT32_MAX)) return;
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
    static const std::map<std::string, unsigned> categoryApis = {
        {"GetSystemTime", 1}, {"GetLocalTime", 1}, {"GetSystemTimeAsFileTime", 1},
        {"GetSystemTimePreciseAsFileTime", 1}, {"GetDriveTypeA", 1}, {"GetDriveTypeW", 1},
        {"GetLogicalDrives", 0}, {"GetDiskFreeSpaceExA", 4}, {"GetDiskFreeSpaceExW", 4},
        {"GetVolumeInformationA", 8}, {"GetVolumeInformationW", 8},
        {"keybd_event", 4}, {"mouse_event", 5}, {"SendInput", 3},
        {"GetComputerNameA", 2}, {"GetComputerNameW", 2}, {"EvtClearLog", 4}, {"EvtQuery", 4}, {"EvtNext", 6}, {"EvtClose", 1}, {"NtOpenFile", 6}, {"ZwOpenFile", 6},
        {"NtClose", 1}, {"ZwClose", 1}, {"SetSecurityInfo", 7},
        {"CertOpenStore", 5}, {"CertOpenSystemStoreA", 2}, {"CertOpenSystemStoreW", 2},
        {"CertAddStoreToCollection", 4}, {"CertCloseStore", 2},
        {"CertAddEncodedCertificateToStore", 6}, {"CertAddCertificateContextToStore", 4},
        {"NetUserAdd", 4}, {"NetLocalGroupAddMembers", 5}, {"NetUserModalsGet", 3},
        {"NetUserGetInfo", 4}, {"NetUserDel", 2},
        {"PowerGetActiveScheme", 2}, {"PowerWriteACValueIndex", 5}, {"PowerSetActiveScheme", 2},
        {"NetScheduleJobAdd", 3},
        {"OpenSCManagerA", 3}, {"OpenSCManagerW", 3}, {"CreateServiceA", 13}, {"CreateServiceW", 13},
        {"OpenServiceA", 3}, {"OpenServiceW", 3}, {"StartServiceA", 3}, {"StartServiceW", 3},
        {"QueryServiceStatus", 2}, {"QueryServiceStatusEx", 5}, {"CloseServiceHandle", 1},
        {"SetFileAttributesA", 2}, {"SetFileAttributesW", 2}, {"GetExtendedTcpTable", 6}, {"SetupDiEnumDeviceInfo", 3},
        {"DllRegisterServer", 0},
        {"CreateProcessAsUserA", 11}, {"CreateProcessAsUserW", 11}, {"CreateProcessWithTokenW", 9},
        {"CreateProcessA", 10}, {"CreateProcessW", 10}, {"InitializeProcThreadAttributeList", 4},
        {"UpdateProcThreadAttribute", 7}, {"DeleteProcThreadAttributeList", 1}, {"GetLastError", 0},
        {"_open", 2}, {"_write", 3}, {"_close", 1},
        {"NetGroupEnum", 7}, {"NetLocalGroupEnum", 7}, {"NetUserEnum", 8}};
    static const std::map<std::string, unsigned> supported = {
        {"CredEnumerateA", 4}, {"CredEnumerateW", 4},
        {"CreateFileA", 7},   {"CreateFileW", 7},     {"CopyFileA", 3},       {"CopyFileW", 3},
        {"WriteFile", 5},     {"CloseHandle", 1},     {"RegCloseKey", 1},     {"RegOpenKeyExA", 5},
        {"RegOpenKeyExW", 5}, {"RegOpenKeyA", 3}, {"RegOpenKeyW", 3},
        {"RegSaveKeyA", 3}, {"RegSaveKeyW", 3}, {"RegSaveKeyExA", 4}, {"RegSaveKeyExW", 4}, {"RegCreateKeyExA", 9}, {"RegCreateKeyExW", 9}, {"RegSetValueExA", 6},
        {"RegSetValueExW", 6}, {"RegDeleteValueA", 2}, {"RegDeleteValueW", 2}, {"ReadFile", 5}, {"RegQueryValueExA", 6}, {"RegQueryValueExW", 6},
        {"GetEnvironmentVariableA", 3}, {"GetEnvironmentVariableW", 3}, {"WideCharToMultiByte", 8},
        {"GetCommandLineA", 0}, {"GetCommandLineW", 0},
        {"GetProcAddress", 2},
        {"GetSystemTime", 1}, {"GetLocalTime", 1}, {"GetSystemTimeAsFileTime", 1},
        {"GetSystemTimePreciseAsFileTime", 1}, {"GetDriveTypeA", 1}, {"GetDriveTypeW", 1},
        {"GetLogicalDrives", 0}, {"GetDiskFreeSpaceExA", 4}, {"GetDiskFreeSpaceExW", 4},
        {"GetVolumeInformationA", 8}, {"GetVolumeInformationW", 8},
        {"keybd_event", 4}, {"mouse_event", 5}, {"SendInput", 3},
        {"GetComputerNameA", 2}, {"GetComputerNameW", 2}, {"EvtClearLog", 4}, {"EvtQuery", 4}, {"EvtNext", 6}, {"EvtClose", 1}, {"NtOpenFile", 6}, {"ZwOpenFile", 6},
        {"NtClose", 1}, {"ZwClose", 1}, {"SetSecurityInfo", 7},
        {"CertOpenStore", 5}, {"CertOpenSystemStoreA", 2}, {"CertOpenSystemStoreW", 2},
        {"CertAddStoreToCollection", 4}, {"CertCloseStore", 2},
        {"CertAddEncodedCertificateToStore", 6}, {"CertAddCertificateContextToStore", 4},
        {"NetUserAdd", 4}, {"NetLocalGroupAddMembers", 5}, {"NetUserModalsGet", 3},
        {"NetUserGetInfo", 4}, {"NetUserDel", 2},
        {"PowerGetActiveScheme", 2}, {"PowerWriteACValueIndex", 5}, {"PowerSetActiveScheme", 2},
        {"NetScheduleJobAdd", 3},
        {"OpenSCManagerA", 3}, {"OpenSCManagerW", 3}, {"CreateServiceA", 13}, {"CreateServiceW", 13},
        {"OpenServiceA", 3}, {"OpenServiceW", 3}, {"StartServiceA", 3}, {"StartServiceW", 3},
        {"QueryServiceStatus", 2}, {"QueryServiceStatusEx", 5}, {"CloseServiceHandle", 1},
        {"SetFileAttributesA", 2}, {"SetFileAttributesW", 2}, {"GetExtendedTcpTable", 6}, {"SetupDiEnumDeviceInfo", 3},
        {"DllRegisterServer", 0},
        {"CreateProcessAsUserA", 11}, {"CreateProcessAsUserW", 11}, {"CreateProcessWithTokenW", 9},
        {"CreateProcessA", 10}, {"CreateProcessW", 10}, {"InitializeProcThreadAttributeList", 4},
        {"UpdateProcThreadAttribute", 7}, {"DeleteProcThreadAttributeList", 1}, {"GetLastError", 0},
        {"_open", 2}, {"_write", 3}, {"_close", 1},
        {"NetGroupEnum", 7}, {"NetLocalGroupEnum", 7}, {"NetUserEnum", 8},
        {"GetFileAttributesA", 1}, {"GetFileAttributesW", 1}, {"FindFirstFileA", 2}, {"FindFirstFileW", 2},
        {"VirtualAllocEx", 5}, {"WriteProcessMemory", 5}, {"VirtualProtectEx", 5}, {"CreateRemoteThread", 7},
        {"socket", 3}, {"connect", 3}, {"bind", 3}, {"listen", 2}, {"accept", 3},
        {"send", 4}, {"recv", 4}, {"closesocket", 1},
        {"waveInOpen", 6}, {"waveInPrepareHeader", 3}, {"waveInAddBuffer", 3},
        {"waveInStart", 1}, {"waveInStop", 1}, {"waveInReset", 1}, {"waveInClose", 1}};
    auto count = supported.find(call.api);
    if (count == supported.end())
        return;
    // Ordinary inspection must never choose a model or concretize an argument.
    auto read32 = [&](uint64_t address, uint32_t &value) {
        auto e = state->mem()->read(address, klee::Expr::Int32);
        auto c = dyn_cast_or_null<klee::ConstantExpr>(e);
        // Conversion lengths and buffer pointers may be expressions after a
        // symbolic string-length loop even when the path constraints prove a
        // single value. Recover only such unique values; never select a seed
        // or add a constraint to make an argument concrete.
        if (!c && call.api == "WideCharToMultiByte" && e) {
            auto unique = state->toUnique(e);
            c = dyn_cast<klee::ConstantExpr>(unique);
        }
        if (!c)
            return false;
        value = c->getZExtValue();
        return true;
    };
    if (count->second > sizeof(call.args) / sizeof(call.args[0])) return;
    for (unsigned i = 0; i < count->second; ++i)
        if (!read32(state->regs()->getSp() + 4 * (i + 1), call.args[i]))
            return;
    call.argumentCount = count->second;
    const bool remoteProcess = call.api == "VirtualAllocEx" || call.api == "WriteProcessMemory" ||
                               call.api == "VirtualProtectEx" || call.api == "CreateRemoteThread";
    if (remoteProcess) {
        call.targetPid = s2e()->getPlugin<WindowsMonitor>()->getPidFromHandle(state, call.pid, call.args[0]);
        if (!call.targetPid || call.targetPid == call.pid) return;
        if (call.api == "CreateRemoteThread") {
            auto startModule = s2e()->getPlugin<ModuleMap>()->getModule(state, call.pid, call.args[3]);
            if (startModule && call.args[3] >= startModule->LoadBase &&
                call.args[3] - startModule->LoadBase <= UINT32_MAX) {
                const auto startRva = uint32_t(call.args[3] - startModule->LoadBase);
                const auto startKey = startModule->Path + ":" + startModule->Name;
                auto startExports = m_exports.find(startKey);
                if (startExports == m_exports.end()) {
                    auto pe = std::dynamic_pointer_cast<vmi::PEFile>(
                        m_vmi->getFromDisk(startModule->Path, startModule->Name, true));
                    if (pe) {
                        std::map<uint64_t, std::string> entries;
                        for (const auto &entry : pe->getExports()) entries[entry.first] = entry.second;
                        startExports = m_exports.emplace(startKey, std::move(entries)).first;
                    }
                }
                if (startExports != m_exports.end()) {
                    auto symbol = startExports->second.find(startRva);
                    if (symbol != startExports->second.end()) {
                        call.threadStartModule = startModule->Name;
                        call.threadStartSymbol = symbol->second;
                        call.threadStartModuleBase = startModule->LoadBase;
                        call.threadStartRva = startRva;
                    }
                }
            }
        }
        if (call.api == "WriteProcessMemory") {
            call.requested = call.args[3];
            call.bufferConcrete = call.requested && call.args[2] &&
                                  uint64_t(call.args[2]) + std::min(call.requested, uint32_t(512)) <=
                                      (uint64_t(1) << 32);
            for (uint32_t i = 0; call.bufferConcrete && i < std::min(call.requested, uint32_t(512)); ++i) {
                auto byte = dyn_cast_or_null<klee::ConstantExpr>(
                    state->mem()->read(uint64_t(call.args[2]) + i, klee::Expr::Int8));
                if (!byte) {
                    call.bufferConcrete = false;
                    call.bufferPrefix.clear();
                    break;
                }
                call.bufferPrefix += static_cast<char>(byte->getZExtValue());
            }
        }
    }
    if (audioModule) {
        if (!m_observeAudio || !source || call.diagnostic || !call.recordEffect || m_audioCalls >= 64)
            return;
        call.audio = true;
        call.module = source->Name;
        call.callId = ++m_audioCalls;
        call.socket = call.api == "waveInOpen" ? 0 : call.args[0];
        if (call.api == "waveInOpen" && call.args[2] && uint64_t(call.args[2]) + 18 <= (uint64_t(1) << 32)) {
            call.bufferConcrete = true;
            for (unsigned i = 0; i < 18; ++i) {
                auto byte = dyn_cast_or_null<klee::ConstantExpr>(
                    state->mem()->read(uint64_t(call.args[2]) + i, klee::Expr::Int8));
                if (!byte) {
                    call.bufferConcrete = false;
                    call.bufferPrefix.clear();
                    break;
                }
                call.bufferPrefix += static_cast<char>(byte->getZExtValue());
            }
        }
        recordAudioEvent(state, call, "enter", 0);
        returnSignal->stackCleanup = 4 * count->second;
        returnSignal->connect(sigc::bind(sigc::mem_fun(*this, &FunctionCallLogger::onReturn), call));
        return;
    }
    if (networkModule) {
        if (!prepareNetworkCall(state, source, call)) return;
        returnSignal->stackCleanup = 4 * count->second;
        returnSignal->connect(sigc::bind(sigc::mem_fun(*this, &FunctionCallLogger::onReturn), call));
        return;
    }
    const bool adminNet = call.api == "NetUserAdd" || call.api == "NetLocalGroupAddMembers" || call.api == "NetUserModalsGet" || call.api == "NetUserGetInfo" || call.api == "NetUserDel";
    const bool wide = call.api == "NetScheduleJobAdd" || adminNet || call.api.back() == 'W' || call.api == "EvtClearLog" || call.api == "EvtQuery" || call.api == "NtOpenFile" || call.api == "ZwOpenFile" ||
        (call.api == "CertOpenStore" && (call.args[0] == 10 || call.args[0] == 13));
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
    if (categoryApis.count(call.api)) {
        auto &counted = m_categoryCalls[s2e()->getCurrentInstanceIndex()];
        if ((!call.recordEffect && call.api != "_close" && call.api != "CloseServiceHandle") || call.diagnostic || counted >= 4096) return;
        call.path.clear();
        const bool processCreate = call.api == "CreateProcessA" || call.api == "CreateProcessW" ||
            call.api == "CreateProcessAsUserA" || call.api == "CreateProcessAsUserW" || call.api == "CreateProcessWithTokenW";
        if (processCreate) {
            const bool user = call.api == "CreateProcessAsUserA" || call.api == "CreateProcessAsUserW";
            const bool token = call.api == "CreateProcessWithTokenW";
            const unsigned app = token ? 2 : (user ? 1 : 0), cmd = app + 1;
            const unsigned startup = token ? 7 : (user ? 9 : 8), flags = token ? 4 : (user ? 6 : 5);
            if ((call.args[app] && !readText(call.args[app], call.path)) ||
                (call.args[cmd] && !readText(call.args[cmd], call.value))) return;
            const uint32_t size = call.args[flags] & 0x80000 ? 72 : 68;
            uint32_t cb = 0;
            call.bufferConcrete = call.args[startup] && uint64_t(call.args[startup]) + size <= (uint64_t(1) << 32)
                && read32(call.args[startup], cb) && cb == size;
            for (uint32_t j = 0; call.bufferConcrete && j < size; ++j) {
                auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(call.args[startup]) + j, klee::Expr::Int8));
                if (!c) { call.bufferConcrete = false; call.bufferPrefix.clear(); break; }
                call.bufferPrefix += char(c->getZExtValue());
            }
        }
        if (call.api == "NetScheduleJobAdd") {
            if (call.args[0] && !readText(call.args[0], call.path, 256)) return;
            const uint32_t address = call.args[1];
            call.bufferConcrete = address && uint64_t(address) + 16 <= (uint64_t(1) << 32);
            // AT_INFO Win32 semantic bytes: DWORD time, DWORD month, BYTE week,
            // BYTE flags, LPWSTR command. Never read the two padding bytes.
            for (unsigned j = 0; call.bufferConcrete && j < 16; ++j) {
                if (j == 10 || j == 11) continue;
                auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(address) + j, klee::Expr::Int8));
                if (!c) { call.bufferConcrete = false; break; }
                call.bufferPrefix += char(c->getZExtValue());
            }
            uint32_t command = 0;
            if (!call.bufferConcrete || !read32(uint64_t(address) + 12, command) ||
                !readText(command, call.value, 512)) {
                call.bufferConcrete = false; call.bufferPrefix.clear(); call.value.clear();
            }
        }
        if (call.api == "OpenSCManagerA" || call.api == "OpenSCManagerW") {
            if ((call.args[0] && !readText(call.args[0], call.path, 256)) ||
                (call.args[1] && !readText(call.args[1], call.value, 256))) return;
        }
        if (call.api == "CreateServiceA" || call.api == "CreateServiceW" ||
            call.api == "OpenServiceA" || call.api == "OpenServiceW") {
            if (!readText(call.args[1], call.path, 256)) return;
            if ((call.api == "CreateServiceA" || call.api == "CreateServiceW") &&
                call.args[7] && !readText(call.args[7], call.value, 512)) return;
        }
        if (call.api == "PowerWriteACValueIndex" || call.api == "PowerSetActiveScheme") {
            const unsigned count = call.api == "PowerWriteACValueIndex" ? 3 : 1;
            call.bufferConcrete = true;
            for (unsigned g = 1; call.bufferConcrete && g <= count; ++g) {
                const uint32_t address = call.args[g];
                if (!address || uint64_t(address) + 16 > (uint64_t(1) << 32)) { call.bufferConcrete = false; break; }
                for (unsigned j = 0; j < 16; ++j) {
                    auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(address) + j, klee::Expr::Int8));
                    if (!c) { call.bufferConcrete = false; break; }
                    call.bufferPrefix += char(c->getZExtValue());
                }
            }
            if (!call.bufferConcrete) call.bufferPrefix.clear();
        }
        if (call.api == "UpdateProcThreadAttribute") {
            uint32_t parentHandle = 0;
            call.bufferConcrete = call.args[2] == 0x20000 && call.args[4] == 4 && call.args[3] &&
                uint64_t(call.args[3]) + 4 <= (uint64_t(1) << 32) && read32(call.args[3], parentHandle);
            if (call.bufferConcrete) {
                for (unsigned j = 0; j < 4; ++j) call.bufferPrefix += char(parentHandle >> (8 * j));
                uint64_t parent = s2e()->getPlugin<WindowsMonitor>()->getPidFromHandle(state, call.pid, parentHandle);
                if (parent <= UINT32_MAX) call.targetPid = parent;
            }
        }
        if (call.api == "_open" && !readText(call.args[0], call.path)) return;
        if (call.api == "_write") {
            call.requested = std::min(call.args[2], uint32_t(4096));
            call.bufferConcrete = call.args[1] && call.requested &&
                uint64_t(call.args[1]) + call.requested <= (uint64_t(1) << 32);
            for (uint32_t i = 0; call.bufferConcrete && i < call.requested; ++i) {
                auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(call.args[1]) + i, klee::Expr::Int8));
                if (!c) { call.bufferConcrete = false; call.bufferPrefix.clear(); break; }
                call.bufferPrefix += char(c->getZExtValue());
            }
        }
        if (call.api == "EvtClearLog" && !readText(call.args[1], call.path, 256)) return;
        if (call.api == "EvtQuery") {
            if (!readText(call.args[1], call.path, 256) || (call.args[2] && !readText(call.args[2], call.value, 512))) return;
        }

        if (call.api == "CertOpenSystemStoreA" || call.api == "CertOpenSystemStoreW") {
            if (!readText(call.args[1], call.path, 128)) return;
        }
        if (call.api == "CertOpenStore" && (call.args[0] == 9 || call.args[0] == 10 || call.args[0] == 12 || call.args[0] == 13)) {
            if (!readText(call.args[4], call.path, 128)) return;
        }
        if (call.api == "CertAddEncodedCertificateToStore" || call.api == "CertAddCertificateContextToStore") {
            const bool context = call.api == "CertAddCertificateContextToStore";
            bool input = true;
            if (context) {
                input = call.args[1] && uint64_t(call.args[1]) + 20 <= (uint64_t(1) << 32)
                    && read32(call.args[1], call.certificateEncoding)
                    && read32(call.args[1] + 4, call.certificateDataAddress)
                    && read32(call.args[1] + 8, call.certificateDataBytes);
                for (uint32_t i = 0; input && i < 20; ++i) {
                    auto byte = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(call.args[1]) + i, klee::Expr::Int8));
                    if (!byte) { input = false; break; }
                    call.data += char(byte->getZExtValue());
                }
            } else {
                call.certificateEncoding = call.args[1];
                call.certificateDataAddress = call.args[2];
                call.certificateDataBytes = call.args[3];
            }
            call.bufferConcrete = input && call.certificateDataAddress && call.certificateDataBytes && call.certificateDataBytes <= 4096
                && uint64_t(call.certificateDataAddress) + call.certificateDataBytes <= (uint64_t(1) << 32);
            for (uint32_t i = 0; call.bufferConcrete && i < call.certificateDataBytes; ++i) {
                auto byte = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(call.certificateDataAddress) + i, klee::Expr::Int8));
                if (!byte) { call.bufferConcrete = false; break; }
                call.bufferPrefix += char(byte->getZExtValue());
            }
            if (!call.bufferConcrete) { call.bufferPrefix.clear(); call.data.clear(); }
        }

        if (call.api == "NtOpenFile" || call.api == "ZwOpenFile") {
            uint32_t length = 0, root = 0, objectName = 0, sizes = 0, buffer = 0;
            if (!call.args[2] || uint64_t(call.args[2]) + 24 > (uint64_t(1) << 32)
                || !read32(call.args[2], length) || length != 24
                || !read32(call.args[2] + 4, root) || root
                || !read32(call.args[2] + 8, objectName) || !objectName
                || uint64_t(objectName) + 8 > (uint64_t(1) << 32)
                || !read32(objectName, sizes) || !read32(objectName + 4, buffer)
                || !(sizes & 0xffff) || (sizes & 1) || (sizes & 0xffff) > (sizes >> 16)
                || (sizes & 0xffff) > 512 || uint64_t(buffer) + (sizes & 0xffff) > (uint64_t(1) << 32)
                || !readText(buffer, call.path, (sizes & 0xffff) / 2, true)
                || call.path.size() != (sizes & 0xffff) / 2) return;
        }
        if (call.api == "SendInput" || call.api == "SetSecurityInfo") {
            uint32_t address = call.api == "SendInput" ? call.args[1] : call.args[5], size = 0;
            if (call.api == "SendInput") {
                if (call.args[0] && call.args[0] <= 8 && call.args[2] == 28) size = 28 * call.args[0];
            } else {
                uint32_t header = 0;
                if (address && uint64_t(address) + 8 <= (uint64_t(1) << 32) && read32(address, header)
                    && ((header & 0xff) == 2 || (header & 0xff) == 4)
                    && (header >> 16) >= 8 && (header >> 16) <= 1024) size = header >> 16;
            }
            call.bufferConcrete = address && size && uint64_t(address) + size <= (uint64_t(1) << 32);
            for (uint32_t i = 0; call.bufferConcrete && i < size; ++i) {
                auto byte = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(address) + i, klee::Expr::Int8));
                if (!byte) { call.bufferConcrete = false; call.bufferPrefix.clear(); break; }
                call.bufferPrefix += char(byte->getZExtValue());
            }
        }

        if (adminNet) {
            call.serverConcrete = !call.args[0];
            if (call.args[0] && uint64_t(call.args[0]) + 256 <= (uint64_t(1) << 32)) {
                for (unsigned i = 0; i < 128; ++i) {
                    auto unit = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(call.args[0]) + 2 * i, klee::Expr::Int16));
                    if (!unit) break;
                    const uint16_t value = unit->getZExtValue();
                    call.data += char(value); call.data += char(value >> 8);
                    if (!value) { call.serverConcrete = true; break; }
                }
            }
            if (!call.serverConcrete) call.data.clear();
            if (call.api == "NetUserAdd" || call.api == "NetLocalGroupAddMembers") {
                const bool user = call.api == "NetUserAdd";
                const uint32_t address = call.args[user ? 2 : 3], size = user ? 28 : 4;
                call.bufferConcrete = address && uint64_t(address) + size <= (uint64_t(1) << 32);
                for (uint32_t i = 0; call.bufferConcrete && i < size; ++i) {
                    auto byte = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(address) + i, klee::Expr::Int8));
                    if (!byte) { call.bufferConcrete = false; break; }
                    call.bufferPrefix += char(byte->getZExtValue());
                }
                call.bufferConcrete = call.bufferConcrete && read32(address, call.requested)
                    && call.requested && uint64_t(call.requested) + 512 <= (uint64_t(1) << 32)
                    && readText(call.requested, call.value, 256);
                if (!user && !readText(call.args[1], call.path, 256)) call.bufferConcrete = false;
                if (!call.bufferConcrete) { call.bufferPrefix.clear(); call.value.clear(); call.requested = 0; }
            }
        }
        if (call.api == "NetUserGetInfo" || call.api == "NetUserDel") {
            if (!readText(call.args[1], call.path, 256)) return;
        }
        if (call.api == "SetFileAttributesA" || call.api == "SetFileAttributesW") {
            if (!readText(call.args[0], call.path, 512)) return;
        }
        if (call.api == "GetExtendedTcpTable") {
            if (!call.args[1] || !read32(call.args[1], call.requested)) return;
        }
        if (call.api == "SetupDiEnumDeviceInfo") {
            if (!call.args[2] || !read32(call.args[2], call.requested) || call.requested != 28) return;
        }
        if (call.api == "GetComputerNameA" || call.api == "GetComputerNameW") {
            if (!call.args[1] || uint64_t(call.args[1]) + 4 > (uint64_t(1) << 32)) return;
            auto capacity = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(call.args[1], klee::Expr::Int32));
            if (!capacity || capacity->getZExtValue() < 16 || capacity->getZExtValue() > 256) return;
            call.requested = capacity->getZExtValue();
        }
        if (call.api == "NetUserEnum" || call.api == "NetGroupEnum" || call.api == "NetLocalGroupEnum") {
            call.bufferConcrete = !call.args[0];
            if (call.args[0] && uint64_t(call.args[0]) + 256 <= (uint64_t(1) << 32)) {
                for (unsigned i = 0; i < 128; ++i) {
                    auto unit = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(call.args[0]) + 2 * i, klee::Expr::Int16));
                    if (!unit) break;
                    const uint16_t value = unit->getZExtValue();
                    call.data += char(value);
                    call.data += char(value >> 8);
                    if (!value) { call.bufferConcrete = true; break; }
                }
            }
            if (!call.bufferConcrete) call.data.clear();
        }
        if ((call.api.find("GetDriveType") == 0 || call.api.find("GetDiskFreeSpaceEx") == 0 ||
             call.api.find("GetVolumeInformation") == 0) && call.args[0] &&
            !readText(call.args[0], call.path)) return;
        call.category = true;
        call.argumentCount = count->second;
        call.callId = ++counted;
        call.module = dest->Name;
        if (!dest->ToRuntime(calleePc, call.calleePc)) return;
        call.entryTime = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        if (call.api == "DllRegisterServer") {
            call.calleeModuleBase = dest->LoadBase;
            if (!call.calleeModuleBase || call.calleePc < call.calleeModuleBase) return;
            call.bufferConcrete = call.calleePc && call.calleePc + 32 <= (uint64_t(1) << 32);
            for (unsigned i = 0; call.bufferConcrete && i < 32; ++i) {
                auto c = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(call.calleePc + i, klee::Expr::Int8));
                if (!c) { call.bufferConcrete = false; call.bufferPrefix.clear(); break; }
                call.bufferPrefix += char(c->getZExtValue());
            }
        }
        recordCategory(state, call, false, 0);
        // The observed msvcrt functions use cdecl; _open's optional mode argument
        // is not needed for data-write evidence and must not be guessed/read.
        returnSignal->stackCleanup = (call.api == "_open" || call.api == "_write" || call.api == "_close") ? 0 : 4 * count->second;
        returnSignal->connect(sigc::bind(sigc::mem_fun(*this, &FunctionCallLogger::onReturn), call));
        return;
    }
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
    if (call.api.find("CreateFile") == 0 || call.api.find("GetFileAttributes") == 0 ||
        call.api.find("FindFirstFile") == 0) {
        call.path.clear();
        if (!readText(call.args[0], call.path))
            return;
    } else if (call.api == "CredEnumerateA" || call.api == "CredEnumerateW") {
        call.path.clear();
        if (!call.args[2] || !call.args[3] || (call.args[0] && !readText(call.args[0], call.path))) return;
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
    } else if (call.api == "GetProcAddress") {
        call.path.clear();
        if (!readText(call.args[1], call.path, 128)) return;
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
    } else if (call.api == "RegDeleteValueA" || call.api == "RegDeleteValueW") {
        if (call.path.empty() || (call.args[1] && !readText(call.args[1], call.value))) return;
    } else if (call.api.find("RegSaveKey") == 0) {
        if (call.path.empty() || !readText(call.args[1], call.value)) return;
    } else if (call.api.find("RegSetValue") == 0) {
        if (call.path.empty() || (call.args[1] && !readText(call.args[1], call.value)))
            return;
        // Keep entry-bound typed bytes separate from the legacy ASCII string view.
        call.bufferConcrete = call.args[4] && call.args[5] && call.args[5] <= 2048 &&
            uint64_t(call.args[4]) + call.args[5] <= (uint64_t(1) << 32);
        for (uint32_t i = 0; call.bufferConcrete && i < call.args[5]; ++i) {
            auto byte = dyn_cast_or_null<klee::ConstantExpr>(state->mem()->read(uint64_t(call.args[4]) + i, klee::Expr::Int8));
            if (!byte) { call.bufferConcrete = false; call.bufferPrefix.clear(); break; }
            call.bufferPrefix += char(byte->getZExtValue());
        }
        if (call.args[3] == 1 || call.args[3] == 2) {
            unsigned width = wide ? 2 : 1;
            if (call.args[5] % width || call.args[5] / width > 512 ||
                !readText(call.args[4], call.data, call.args[5] / width, true))
                return;
        }
    }
    // Positive effects use direct non-DLL calls in the monitored process tree.
    // DLL RegCloseKey calls are negative-only evidence that invalidates stale handles.
    // File handles stay state/PID/lifetime local in the existing observer map.
    bool tracked = call.api.find("CredEnumerate") == 0 || call.api.find("Reg") == 0 || call.api == "ReadFile" || call.api == "WriteFile" || call.api == "GetProcAddress" || remoteProcess ||
                   call.api == "CloseHandle" || call.api == "CreateFileA" || call.api == "CreateFileW";
    auto &counted = m_lifecycleCalls[s2e()->getCurrentInstanceIndex()];
    if (tracked && (call.recordEffect || call.api == "RegCloseKey") && !call.diagnostic && counted < 8192) {
        call.lifecycle = true;
        call.callId = ++counted;
        call.module = dest->Name;
        if (!dest->ToRuntime(calleePc, call.calleePc)) return;
        call.entryTime = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        if (call.api == "WriteFile") call.requested = call.args[2];
        recordLifecycle(state, call, false, 0);
    }
    if (call.api == "WideCharToMultiByte") prepareAsciiConversion(state, call);
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
    if (call.category) {
        uint32_t categoryResult = 0;
        const bool voidResult = call.api == "GetSystemTime" || call.api == "GetLocalTime" ||
            call.api == "GetSystemTimeAsFileTime" || call.api == "GetSystemTimePreciseAsFileTime" ||
            call.api == "keybd_event" || call.api == "mouse_event" || call.api == "DeleteProcThreadAttributeList";
        if (!voidResult && !state->regs()->read(CPU_OFFSET(regs[R_EAX]), &categoryResult, 4, false)) return;
        if (!diagnostic) recordCategory(state, call, true, categoryResult);
        return;
    }
    uint32_t result;
    if (!state->regs()->read(CPU_OFFSET(regs[R_EAX]), &result, sizeof(result), false))
        return;
    if (!diagnostic) recordLifecycle(state, call, true, result);
    if (call.api == "CredEnumerateA" || call.api == "CredEnumerateW") return;
    if (call.api.find("RegSaveKey") == 0) return; // Successful export is not a registry write.
    if (call.api == "RegDeleteValueA" || call.api == "RegDeleteValueW") return; // Removal is lifecycle evidence, never a value-write effect.

    if (call.audio) {
        if (call.api == "waveInOpen" && result == 0 && call.args[0]) {
            auto expression = state->mem()->read(call.args[0], klee::Expr::Int32);
            auto constant = dyn_cast_or_null<klee::ConstantExpr>(expression);
            if (constant) call.socket = constant->getZExtValue();
        }
        recordAudioEvent(state, call, "return", result);
        return;
    }
    if (call.network) {
        if (call.redirected &&
            !state->mem()->write(call.args[1], call.originalSockaddr.data(), call.originalSockaddr.size())) {
            s2e()->getExecutor()->terminateState(*state, "Network redirect could not restore sockaddr");
            return;
        }
        if (diagnostic)
            return;
        auto read32 = [&](uint64_t address, uint32_t &value) {
            if (!address) return false;
            auto expression = state->mem()->read(address, klee::Expr::Int32);
            auto constant = dyn_cast_or_null<klee::ConstantExpr>(expression);
            if (!constant) return false;
            value = constant->getZExtValue();
            return true;
        };
        auto readBytes = [&](uint64_t address, uint32_t size, std::string &value) {
            if (!address || uint64_t(address) + size > (uint64_t(1) << 32)) return false;
            for (uint32_t i = 0; i < size; ++i) {
                auto byte = dyn_cast_or_null<klee::ConstantExpr>(
                    state->mem()->read(address + i, klee::Expr::Int8));
                if (!byte) return false;
                value += static_cast<char>(byte->getZExtValue());
            }
            return true;
        };
        if (call.api == "recv") {
            uint32_t extent = 0;
            if (input_observation::networkTransferExtent(result, call.requested, extent)) {
                call.bufferConcrete = readBytes(call.args[1], extent, call.bufferPrefix);
                if (!call.bufferConcrete) call.bufferPrefix.clear();
            }
        } else if (call.api == "accept" && result != UINT32_MAX) {
            call.acceptedSocket = result;
            uint32_t length = 0;
            if (call.args[1] && call.args[2] && read32(call.args[2], length) &&
                input_observation::networkAddressExtent(length) &&
                readBytes(call.args[1], length, call.peerSockaddr)) {
                call.addressLength = length;
            } else {
                call.peerSockaddr.clear();
                call.addressLength = 0;
            }
        }
        recordNetworkEvent(state, call, "return", result);
        if (call.api == "closesocket" && result == 0) {
            DECLARE_PLUGINSTATE(FunctionCallLoggerState, state);
            plgState->redirectedSockets.erase(std::make_tuple(call.pid, call.lifetime, call.socket));
        }
        return;
    }
    if (call.recordEffect && !call.diagnostic && !diagnostic && (depth ? m_discoverChildInputs : m_discoverRootInputs))
        observeAccess(state, call, result);
    if (call.api.find("GetFileAttributes") == 0 || call.api.find("FindFirstFile") == 0) return;
    if (call.api == "WideCharToMultiByte") { finishAsciiConversion(state, call, result); return; }
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
        unsigned index = (call.api == "RegOpenKeyA" || call.api == "RegOpenKeyW") ? 2 :
                         (call.api.find("RegOpenKey") == 0 ? 4 : 7);
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
        << ",\"depth\":" << depth << ",\"call_id\":" << call.callId << ",\"diagnostic_lineage\":" << (diagnostic ? "true" : "false") << ",\"api\":\""
        << call.api << "\",\"path_hex\":\"" << hex(call.path) << "\",\"value_hex\":\"" << hex(call.value)
        << "\",\"data_hex\":\"" << hex(call.data) << "\",\"bytes_written\":" << bytes
        << ",\"buffer_prefix_hex\":\"" << hex(bufferPrefix) << "\",\"buffer_prefix_bytes\":" << bufferPrefix.size()
        << ",\"registry_type\":" << (registry ? call.args[3] : 0) << ",\"return_value\":" << result;
    if (registry)
        out << ",\"registry_data_address\":" << call.args[4] << ",\"registry_data_bytes\":" << call.args[5]
            << ",\"registry_data_concrete\":" << (call.bufferConcrete ? "true" : "false")
            << ",\"registry_data_hex\":\"" << hex(call.bufferPrefix) << "\"";
    out << "}\n";
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
