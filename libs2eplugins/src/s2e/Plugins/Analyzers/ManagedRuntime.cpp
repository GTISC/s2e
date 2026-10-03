#include "ManagedRuntime.h"
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <sstream>

namespace s2e {
namespace plugins {
S2E_DEFINE_PLUGIN(ManagedRuntime, "State-local original-IL observations", "", "OSMonitor", "ProcessExecutionDetector");
class ManagedRuntimeState : public PluginState {
public:
    ManagedBindings bindings;
    uint64_t pageDir = 0;
    ManagedRuntimeState *clone() const override {
        return new ManagedRuntimeState(*this);
    }
    static PluginState *factory(Plugin *, S2EExecutionState *) {
        return new ManagedRuntimeState();
    }
};
void ManagedRuntime::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_processes = s2e()->getPlugin<ProcessExecutionDetector>();
    auto cfg = s2e()->getConfig();
    auto key = getConfigKey();
    m_policy.session = cfg->getString(key + ".session");
    m_policy.mvid = cfg->getString(key + ".mvid");
    m_policy.plan = cfg->getString(key + ".plan");
    const auto maxForks = cfg->getInt(key + ".maxForks", 8);
    m_boundForks = cfg->getBool(key + ".boundForks", true);
    const auto sourceToken = cfg->getInt(key + ".booleanSourceToken", 0);
    const auto sourceSeed = cfg->getInt(key + ".booleanSourceSeed", 0);
    if (maxForks < 0 || maxForks > 16 || sourceSeed < 0 || sourceSeed > 1 ||
        (sourceToken && (sourceToken < 0x06000001 || sourceToken > 0x06ffffff))) {
        getWarningsStream() << "Invalid managed fork/source policy\n";
        exit(1);
    }
    m_maxForks = maxForks;
    m_policy.booleanSourceToken = sourceToken;
    m_policy.booleanSourceSeed = sourceSeed;
    for (auto name : cfg->getListKeys(key + ".methods")) {
        auto path = key + ".methods." + name;
        ManagedExpectedMethod method;
        method.original = cfg->getString(path + ".original");
        std::istringstream offsets(cfg->getString(path + ".probes"));
        uint32_t offset;
        while (offsets >> offset)
            method.probes.push_back(offset);
        if (!offsets.eof() || !ManagedBindings::hash(method.original) || method.probes.empty() ||
            method.probes.size() > 256 || !std::is_sorted(method.probes.begin(), method.probes.end()) ||
            std::adjacent_find(method.probes.begin(), method.probes.end()) != method.probes.end()) {
            getWarningsStream() << "Invalid managed method policy\n";
            exit(1);
        }
        const auto token = cfg->getInt(path + ".token", 0);
        if (token < 0x06000001 || token > 0x06ffffff || !m_policy.methods.emplace(token, method).second) {
            getWarningsStream() << "Invalid or duplicate managed MethodDef token\n";
            exit(1);
        }
    }
    if (m_policy.session.size() != 32 || m_policy.mvid.size() != 36 || !ManagedBindings::hash(m_policy.plan) ||
        m_policy.methods.empty() || m_policy.methods.size() > 64 || m_maxForks > 16 || m_policy.booleanSourceSeed > 1 ||
        (m_policy.booleanSourceToken && (!m_policy.methods.count(m_policy.booleanSourceToken) ||
                                         m_policy.methods.at(m_policy.booleanSourceToken).probes.front() != 0))) {
        getWarningsStream() << "Invalid managed policy\n";
        exit(1);
    }
    m_log.open(s2e()->getOutputFilename("managed-s2e.jsonl"));
    if (!m_log) {
        getWarningsStream() << "Cannot open managed journal\n";
        exit(1);
    }
    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &ManagedRuntime::onProcessUnload));
    m_monitor->onModuleUnload.connect(sigc::mem_fun(*this, &ManagedRuntime::onModuleUnload));
    s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &ManagedRuntime::onStateKill));
    s2e()->getCorePlugin()->onStateForkDecide.connect(sigc::mem_fun(*this, &ManagedRuntime::onForkDecide));
    s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &ManagedRuntime::onFork));
}
void ManagedRuntime::handleOpcodeInvocation(S2EExecutionState *state, uint64_t ptr, uint64_t size) {
    DECLARE_PLUGINSTATE(ManagedRuntimeState, state);
    ManagedCommand c = {};
    std::string error;
    if (size != sizeof(c) || !state->mem()->read(ptr, &c, sizeof(c)))
        error = "invalid_packet";
    else if (!m_processes->isTrackedPid(state, m_monitor->getPid(state)))
        error = "untracked_process";
    else if (plgState->bindings.active && plgState->pageDir != state->regs()->getPageDir())
        error = "address_space";
    else
        error = plgState->bindings.accept(c, m_monitor->getPid(state), m_policy);
    if (!error.empty()) {
        m_log << "{\"event\":\"rejected\",\"state\":" << state->getID() << ",\"reason\":\"" << error << "\"}\n";
        m_log.flush();
        s2e()->getExecutor()->terminateState(*state, "ManagedRuntime: " + error);
        return;
    }
    if (c.operation == ManagedStart)
        plgState->pageDir = state->regs()->getPageDir();
    if (c.operation == ManagedBooleanSource) {
        uint32_t seed;
        if (!state->mem()->read(c.start, &seed, sizeof(seed)) || seed != c.offset) {
            s2e()->getExecutor()->terminateState(*state, "ManagedRuntime: source_seed_mismatch");
            return;
        }
        // One bit, one invocation, one independently replayable Boolean recipe.
        auto value = state->createSymbolicValue("__symfile___managed_boolean___0_1_symfile__", klee::Expr::Int8,
                                                std::vector<uint8_t>{static_cast<uint8_t>(seed)});
        if (!state->addConstraint(klee::UleExpr::create(value, klee::ConstantExpr::create(1, klee::Expr::Int8)))) {
            s2e()->getExecutor()->terminateState(*state, "ManagedRuntime: source_constraint_failed");
            return;
        }
        if (!state->mem()->write(c.start, klee::ZExtExpr::create(value, klee::Expr::Int32))) {
            s2e()->getExecutor()->terminateState(*state, "ManagedRuntime: source_write_failed");
            return;
        }
    }
    m_log << "{\"event\":\"packet\",\"state\":" << state->getID() << ",\"pid\":" << c.pid
          << ",\"page_dir\":" << plgState->pageDir << ",\"sequence\":" << c.sequence << ",\"operation\":" << c.operation
          << ",\"function\":" << c.function << ",\"offset\":" << c.offset << ",\"pc\":" << state->regs()->getPc();
    if (c.operation == ManagedRegister)
        m_log << ",\"token\":" << c.token << ",\"start\":" << c.start << ",\"size\":" << c.size << ",\"original\":\""
              << c.original << "\",\"instrumented\":\"" << c.instrumented << "\"";
    if (c.operation == ManagedBooleanSource)
        m_log << ",\"token\":" << c.token << ",\"source\":\"managed_boolean\",\"seed\":" << c.offset;
    if (c.operation == ManagedEvent) {
        std::string event(c.event);
        if (!event.empty() && event.back() == '\n')
            event.pop_back();
        m_log << ",\"clr\":" << event;
    }
    m_log << "}\n";
    m_log.flush();
    if (!m_log)
        s2e()->getExecutor()->terminateState(*state, "ManagedRuntime: journal_write_failed");
}
void ManagedRuntime::onModuleUnload(S2EExecutionState *state, const ModuleDescriptor &module) {
    DECLARE_PLUGINSTATE(ManagedRuntimeState, state);
    auto &b = plgState->bindings;
    if (b.active && b.pid == module.Pid && m_processes->isTrackedModule(module.Name)) {
        for (auto &m : b.methods)
            b.retired.insert(m.first);
        b.methods.clear();
        m_log << "{\"event\":\"image_unload\",\"state\":" << state->getID() << "}\n";
        m_log.flush();
    }
}
void ManagedRuntime::onStateKill(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(ManagedRuntimeState, state);
    const auto &b = plgState->bindings;
    m_log << "{\"event\":\"state_end\",\"state\":" << state->getID() << ",\"active\":" << (b.active ? "true" : "false")
          << ",\"ended\":" << (b.ended ? "true" : "false") << "}\n";
    m_log.flush();
}
void ManagedRuntime::onProcessUnload(S2EExecutionState *state, uint64_t, uint64_t pid, uint64_t code) {
    DECLARE_PLUGINSTATE(ManagedRuntimeState, state);
    auto &b = plgState->bindings;
    if (b.pid != pid)
        return;
    m_log << "{\"event\":\"process_exit\",\"state\":" << state->getID() << ",\"pid\":" << pid << ",\"code\":" << code
          << ",\"ended\":" << (b.ended ? "true" : "false") << "}\n";
    m_log.flush();
    b.active = false;
    b.methods.clear();
    b.ended = true;
}
void ManagedRuntime::onForkDecide(S2EExecutionState *state, const klee::ref<klee::Expr> &, bool &allow) {
    if (!m_boundForks)
        return;
    DECLARE_PLUGINSTATE(ManagedRuntimeState, state);
    auto &b = plgState->bindings;
    // Veto only: never override another plugin's resource/safety decision.
    allow = allow && b.active && b.pid == m_monitor->getPid(state) &&
            plgState->pageDir == state->regs()->getPageDir() && b.contains(state->regs()->getPc()) &&
            b.forks < m_maxForks;
}
void ManagedRuntime::onFork(S2EExecutionState *parent, const std::vector<S2EExecutionState *> &children,
                            const std::vector<klee::ref<klee::Expr>> &) {
    DECLARE_PLUGINSTATE(ManagedRuntimeState, parent);
    if (!plgState->bindings.active)
        return;
    auto next = plgState->bindings.forks + 1;
    for (auto child : children) {
        auto cs = static_cast<ManagedRuntimeState *>(child->getPluginState(this, &ManagedRuntimeState::factory));
        cs->bindings.forks = next;
        m_log << "{\"event\":\"fork\",\"parent\":" << parent->getID() << ",\"state\":" << child->getID()
              << ",\"next_sequence\":" << cs->bindings.next << ",\"pc\":" << parent->regs()->getPc() << "}\n";
    }
    m_log.flush();
}
} // namespace plugins
} // namespace s2e
