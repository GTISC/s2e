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
    const bool observe = m_observeWindowsEffects || m_discoverRootInputs || m_discoverChildInputs ||
                         m_observeNetwork || m_observeAudio;
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
        call.originalSockaddr == m_connectRedirect.sockaddr) {
        std::string code;
        if (readBytes(call.callerPc, 6, code) && inputHex(code) == m_connectRedirect.code &&
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
        !(m_observeNetwork && networkModule) && !(m_observeAudio && audioModule))
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
        {"GetEnvironmentVariableA", 3}, {"GetEnvironmentVariableW", 3}, {"WideCharToMultiByte", 8},
        {"GetCommandLineA", 0}, {"GetCommandLineW", 0},
        {"GetFileAttributesA", 1}, {"GetFileAttributesW", 1}, {"FindFirstFileA", 2}, {"FindFirstFileW", 2},
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
    for (unsigned i = 0; i < count->second; ++i)
        if (!read32(state->regs()->getSp() + 4 * (i + 1), call.args[i]))
            return;
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
    if (call.api.find("CreateFile") == 0 || call.api.find("GetFileAttributes") == 0 ||
        call.api.find("FindFirstFile") == 0) {
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
    uint32_t result;
    if (!state->regs()->read(CPU_OFFSET(regs[R_EAX]), &result, sizeof(result), false))
        return;
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
