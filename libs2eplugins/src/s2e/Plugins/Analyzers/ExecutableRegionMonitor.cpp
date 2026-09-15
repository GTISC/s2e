///
/// Monitor executable behavior originating in virtual allocations.
///

#include "ExecutableRegionMonitor.h"

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

#include <klee/Expr.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <vector>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ExecutableRegionMonitor, "Virtual-allocation execution monitor", "ExecutableRegionMonitor",
                  "OSMonitor", "ProcessExecutionDetector", "ModuleMap");

namespace {

static constexpr uint64_t EXECUTABLE_REGION_COMMAND_MAGIC = UINT64_C(0x4558524d); // EXRM
static constexpr uint64_t EXECUTABLE_REGION_COMMAND_VERSION = 1;
static constexpr uint64_t EXECUTABLE_REGION_COMMAND_READY = 1;

struct ExecutableRegionCommand {
    uint64_t magic;
    uint64_t version;
    uint64_t command;
    uint64_t pid;
    uint64_t tid;
};

struct ExecutableRegion {
    uint64_t allocationId = 0;
    uint64_t budgetBase = 0;
    uint64_t pid = 0;
    uint64_t sourcePid = 0;
    uint64_t start = 0;
    uint64_t end = 0; // Exclusive.
    uint64_t allocationType = 0;
    uint64_t protection = 0;
    bool everWritable = false;
    bool remote = false;
    bool executed = false;
    bool dumped = false;
};

struct DescendantProcess {
    uint64_t parentPid = 0;
    uint64_t depth = 0;
    std::string imageName;
};

class ExecutableRegionMonitorState : public PluginState {
public:
    BehaviorOracle oracle;
    std::vector<ExecutableRegion> regions;
    std::set<uint64_t> armedPids;
    std::set<uint64_t> readyPids;
    std::map<uint64_t, std::set<uint64_t>> trustedThreads;
    std::map<uint64_t, DescendantProcess> descendants;

    static PluginState *factory(Plugin *plugin, S2EExecutionState *state) {
        return new ExecutableRegionMonitorState();
    }

    ExecutableRegionMonitorState *clone() const override {
        return new ExecutableRegionMonitorState(*this);
    }
};

static bool ntSuccess(uint64_t status) {
    return (static_cast<uint32_t>(status) & 0x80000000U) == 0;
}

static bool isWritable(uint64_t protection) {
    switch (protection & 0xff) {
        case 0x04: // PAGE_READWRITE
        case 0x08: // PAGE_WRITECOPY
        case 0x40: // PAGE_EXECUTE_READWRITE
        case 0x80: // PAGE_EXECUTE_WRITECOPY
            return true;
        default:
            return false;
    }
}

static bool isExecutable(uint64_t protection) {
    switch (protection & 0xff) {
        case 0x10: // PAGE_EXECUTE
        case 0x20: // PAGE_EXECUTE_READ
        case 0x40: // PAGE_EXECUTE_READWRITE
        case 0x80: // PAGE_EXECUTE_WRITECOPY
            return true;
        default:
            return false;
    }
}

static uint64_t exclusiveEnd(uint64_t start, uint64_t size) {
    if (!size || size > std::numeric_limits<uint64_t>::max() - start) {
        return std::numeric_limits<uint64_t>::max();
    }
    return start + size;
}

static bool overlaps(const ExecutableRegion &region, uint64_t start, uint64_t end) {
    return start < region.end && region.start < end;
}

static std::string lowerCase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return value;
}

static bool isTrustedThread(const ExecutableRegionMonitorState *state, uint64_t pid, uint64_t tid) {
    auto process = state->trustedThreads.find(pid);
    return process != state->trustedThreads.end() && process->second.count(tid);
}

} // namespace

unsigned ExecutableRegionMonitor::behaviorStage(S2EExecutionState *state, BehaviorGoal goal) {
    DECLARE_PLUGINSTATE(ExecutableRegionMonitorState, state);
    return plgState->oracle.stage(goal);
}

bool ExecutableRegionMonitor::isTrackedDynamicCode(S2EExecutionState *state, uint64_t pc) {
    uint64_t pid, allocation, offset;
    return getDynamicCodeLocation(state, pc, pid, allocation, offset);
}

bool ExecutableRegionMonitor::getDynamicCodeLocation(S2EExecutionState *state, uint64_t pc, uint64_t &pid,
                                                     uint64_t &allocation, uint64_t &offset) {
    DECLARE_PLUGINSTATE(ExecutableRegionMonitorState, state);
    pid = m_windows->getCurrentProcessId(state);
    if (m_requireInstrumentationReady && !isTrustedThread(plgState, pid, m_windows->getCurrentThreadId(state))) {
        return false;
    }
    if (m_modules->getModule(state, pid, pc))
        return false;
    for (const auto &region : plgState->regions) {
        if (region.executed && region.pid == pid && region.start <= pc && pc < region.end) {
            allocation = region.allocationId;
            offset = pc - region.budgetBase;
            return true;
        }
    }
    return false;
}

void ExecutableRegionMonitor::initialize() {
    m_windows = dynamic_cast<WindowsMonitor *>(s2e()->getPlugin("OSMonitor"));
    if (!m_windows) {
        getWarningsStream() << "ExecutableRegionMonitor: requires WindowsMonitor\n";
        exit(-1);
    }
    m_process = s2e()->getPlugin<ProcessExecutionDetector>();
    m_modules = s2e()->getPlugin<ModuleMap>();

    ConfigFile *cfg = s2e()->getConfig();
    bool ok = false;
    m_moduleName = cfg->getString(getConfigKey() + ".moduleName", "", &ok);
    if (!ok || m_moduleName.empty()) {
        getWarningsStream() << "ExecutableRegionMonitor: moduleName is required\n";
        exit(-1);
    }
    m_dumpOnExecute = cfg->getBool(getConfigKey() + ".dumpOnExecute", true, &ok);
    if (!ok) {
        getWarningsStream() << "ExecutableRegionMonitor: dumpOnExecute must be a boolean\n";
        exit(-1);
    }
    m_trackChildProcesses = cfg->getBool(getConfigKey() + ".trackChildProcesses", true, &ok);
    if (!ok) {
        getWarningsStream() << "ExecutableRegionMonitor: trackChildProcesses must be a boolean\n";
        exit(-1);
    }
    m_requireInstrumentationReady = cfg->getBool(getConfigKey() + ".requireInstrumentationReady", false, &ok);
    if (!ok) {
        getWarningsStream() << "ExecutableRegionMonitor: requireInstrumentationReady must be a boolean\n";
        exit(-1);
    }

    int64_t maxDumpBytes = cfg->getInt(getConfigKey() + ".maxDumpBytes", 1024 * 1024, &ok);
    if (!ok || maxDumpBytes < 0 || maxDumpBytes > 16 * 1024 * 1024) {
        getWarningsStream() << "ExecutableRegionMonitor: maxDumpBytes must be between 0 and 16 MiB\n";
        exit(-1);
    }
    m_maxDumpBytes = maxDumpBytes;

    int64_t maxRegions = cfg->getInt(getConfigKey() + ".maxRegions", 1024, &ok);
    if (!ok || maxRegions <= 0 || maxRegions > 65536) {
        getWarningsStream() << "ExecutableRegionMonitor: maxRegions must be between 1 and 65536\n";
        exit(-1);
    }
    m_maxRegions = maxRegions;

    int64_t maxChildDepth = cfg->getInt(getConfigKey() + ".maxChildDepth", 4, &ok);
    if (!ok || maxChildDepth <= 0 || maxChildDepth > 64) {
        getWarningsStream() << "ExecutableRegionMonitor: maxChildDepth must be between 1 and 64\n";
        exit(-1);
    }
    m_maxChildDepth = maxChildDepth;

    int64_t maxChildren = cfg->getInt(getConfigKey() + ".maxChildren", 64, &ok);
    if (!ok || maxChildren <= 0 || maxChildren > 4096) {
        getWarningsStream() << "ExecutableRegionMonitor: maxChildren must be between 1 and 4096\n";
        exit(-1);
    }
    m_maxChildren = maxChildren;

    m_windows->onMonitorLoad.connect(sigc::mem_fun(*this, &ExecutableRegionMonitor::onMonitorLoad));
    m_windows->onNtAllocateVirtualMemory.connect(
        sigc::mem_fun(*this, &ExecutableRegionMonitor::onNtAllocateVirtualMemory));
    m_windows->onNtProtectVirtualMemory.connect(
        sigc::mem_fun(*this, &ExecutableRegionMonitor::onNtProtectVirtualMemory));
    m_windows->onNtFreeVirtualMemory.connect(sigc::mem_fun(*this, &ExecutableRegionMonitor::onNtFreeVirtualMemory));
    m_windows->onProcessLoad.connect(sigc::mem_fun(*this, &ExecutableRegionMonitor::onProcessLoad));
    m_windows->onProcessUnload.connect(sigc::mem_fun(*this, &ExecutableRegionMonitor::onProcessUnload));
    m_windows->onThreadCreate.connect(sigc::mem_fun(*this, &ExecutableRegionMonitor::onThreadCreate));
    m_windows->onThreadExit.connect(sigc::mem_fun(*this, &ExecutableRegionMonitor::onThreadExit));

    getInfoStream() << "ExecutableRegionMonitor: enabled moduleName=" << m_moduleName << " maxRegions=" << m_maxRegions
                    << " dumpOnExecute=" << m_dumpOnExecute << " maxDumpBytes=" << m_maxDumpBytes
                    << " trackChildProcesses=" << m_trackChildProcesses << " maxChildDepth=" << m_maxChildDepth
                    << " maxChildren=" << m_maxChildren
                    << " requireInstrumentationReady=" << m_requireInstrumentationReady << "\n";
}

void ExecutableRegionMonitor::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr,
                                                     uint64_t guestDataSize) {
    ExecutableRegionCommand request = {};
    if (guestDataSize != sizeof(request)) {
        getWarningsStream(state) << "ExecutableRegionMonitor: rejectedCommand=invalid-size size=" << guestDataSize
                                 << " expected=" << sizeof(request) << "\n";
        return;
    }
    if (!state->mem()->read(guestDataPtr, &request, sizeof(request))) {
        getWarningsStream(state) << "ExecutableRegionMonitor: rejectedCommand=unreadable\n";
        return;
    }
    if (request.magic != EXECUTABLE_REGION_COMMAND_MAGIC || request.version != EXECUTABLE_REGION_COMMAND_VERSION ||
        request.command != EXECUTABLE_REGION_COMMAND_READY || !request.pid || !request.tid) {
        getWarningsStream(state) << "ExecutableRegionMonitor: rejectedCommand=invalid-payload magic="
                                 << hexval(request.magic) << " version=" << request.version
                                 << " command=" << request.command << " pid=" << hexval(request.pid)
                                 << " tid=" << hexval(request.tid) << "\n";
        return;
    }

    DECLARE_PLUGINSTATE(ExecutableRegionMonitorState, state);
    // malware-inject sends this after every hook DLL finishes initialization
    // and immediately before it resumes the sample's main thread. Threads
    // that predate this boundary, including EasyHook's loader, stay untrusted.
    plgState->readyPids.insert(request.pid);
    plgState->trustedThreads[request.pid].insert(request.tid);
    getInfoStream(state) << "ExecutableRegionMonitor: instrumentationReady sourcePid="
                         << hexval(m_windows->getCurrentProcessId(state))
                         << " sourceTid=" << hexval(m_windows->getCurrentThreadId(state))
                         << " pid=" << hexval(request.pid) << " tid=" << hexval(request.tid) << "\n";
}

void ExecutableRegionMonitor::onMonitorLoad(S2EExecutionState *state) {
    if (m_translationEnabled) {
        return;
    }
    m_translationEnabled = true;
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &ExecutableRegionMonitor::onTranslateBlockStart));

    // Blocks translated before WindowsMonitor became ready have no callback.
    // Flush once so later execution inside a new allocation cannot be missed.
    se_tb_safe_flush();
}

void ExecutableRegionMonitor::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                    TranslationBlock *tb, uint64_t pc) {
    signal->connect(sigc::mem_fun(*this, &ExecutableRegionMonitor::onBlockExecute));
}

void ExecutableRegionMonitor::onNtAllocateVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_ALLOCATE_VM &data) {
    if (!ntSuccess(data.Status) || !data.BaseAddress || !data.Size) {
        return;
    }

    uint64_t sourcePid = m_windows->getCurrentProcessId(state);
    uint64_t targetPid = m_windows->getPidFromHandle(state, sourcePid, data.ProcessHandle);
    uint64_t pid = targetPid ? targetPid : sourcePid;
    bool remote = pid != sourcePid;
    DECLARE_PLUGINSTATE(ExecutableRegionMonitorState, state);
    bool sourceArmed = plgState->armedPids.count(sourcePid);
    bool targetArmed = plgState->armedPids.count(pid);
    // The injector allocates its loader inside the tracked process before the
    // sample starts. A genuine remote allocation must originate from an armed
    // analysis process; accepting an armed target alone turns our own tooling
    // into a malware behavior false positive.
    if ((!sourceArmed && !targetArmed) || (remote && !sourceArmed)) {
        return;
    }
    uint64_t sourceTid = m_windows->getCurrentThreadId(state);
    if (m_requireInstrumentationReady && !isTrustedThread(plgState, sourcePid, sourceTid)) {
        return;
    }

    uint64_t start = data.BaseAddress;
    uint64_t end = exclusiveEnd(start, data.Size);

    ExecutableRegion region;
    region.allocationId = m_nextAllocationId++;
    region.budgetBase = start;
    region.pid = pid;
    region.sourcePid = sourcePid;
    region.start = start;
    region.end = end;
    region.allocationType = data.AllocationType;
    region.protection = data.Protection;
    region.everWritable = isWritable(data.Protection);
    region.remote = remote;

    // Reserve/commit calls commonly describe the same range twice. Preserve
    // lifecycle flags while coalescing overlap instead of producing duplicate
    // execution evidence and duplicate dumps.
    for (auto it = plgState->regions.begin(); it != plgState->regions.end();) {
        if (it->pid != pid || !overlaps(*it, start, end)) {
            ++it;
            continue;
        }
        region.start = std::min(region.start, it->start);
        region.end = std::max(region.end, it->end);
        // Reserve/commit overlap is the same lifetime, not a fresh budget.
        // Keep the origin stable even when the tracked interval expands.
        if (it->allocationId < region.allocationId) {
            region.allocationId = it->allocationId;
            region.budgetBase = it->budgetBase;
        }
        region.everWritable = region.everWritable || it->everWritable;
        region.executed = region.executed || it->executed;
        region.dumped = region.dumped || it->dumped;
        it = plgState->regions.erase(it);
    }

    if (plgState->regions.size() >= m_maxRegions) {
        plgState->regions.erase(plgState->regions.begin());
        getWarningsStream(state) << "ExecutableRegionMonitor: evicted oldest region at maxRegions=" << m_maxRegions
                                 << "\n";
    }
    plgState->regions.push_back(region);
    plgState->oracle.allocated(sourcePid, pid, start, end, m_maxRegions);

    getInfoStream(state) << "ExecutableRegionMonitor: effect=" << (remote ? "VirtualAllocEx" : "VirtualAlloc")
                         << " native=NtAllocateVirtualMemory sourcePid=" << hexval(sourcePid) << " pid=" << hexval(pid)
                         << " base=" << hexval(start) << " size=" << hexval(data.Size)
                         << " allocationType=" << hexval(data.AllocationType)
                         << " protection=" << hexval(data.Protection) << " remote=" << remote << "\n";
}

void ExecutableRegionMonitor::onNtProtectVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_PROTECT_VM &data) {
    if (!ntSuccess(data.Status) || !data.BaseAddress || !data.Size) {
        return;
    }

    uint64_t sourcePid = m_windows->getCurrentProcessId(state);
    uint64_t targetPid = m_windows->getPidFromHandle(state, sourcePid, data.ProcessHandle);
    uint64_t pid = targetPid ? targetPid : sourcePid;
    bool remote = pid != sourcePid;
    DECLARE_PLUGINSTATE(ExecutableRegionMonitorState, state);
    bool sourceArmed = plgState->armedPids.count(sourcePid);
    bool targetArmed = plgState->armedPids.count(pid);
    if ((!sourceArmed && !targetArmed) || (remote && !sourceArmed)) {
        return;
    }
    uint64_t sourceTid = m_windows->getCurrentThreadId(state);
    if (m_requireInstrumentationReady && !isTrustedThread(plgState, sourcePid, sourceTid)) {
        return;
    }

    uint64_t end = exclusiveEnd(data.BaseAddress, data.Size);
    bool matchedRegion = false;
    for (auto &region : plgState->regions) {
        if (region.pid != pid || !overlaps(region, data.BaseAddress, end)) {
            continue;
        }
        matchedRegion = true;

        uint64_t oldProtection = region.protection ? region.protection : data.OldProtection;
        bool writableBefore = region.everWritable || isWritable(oldProtection);
        bool becameExecutable = !isExecutable(oldProtection) && isExecutable(data.NewProtection);
        region.everWritable = writableBefore || isWritable(data.NewProtection);
        region.protection = data.NewProtection;

        if (writableBefore && becameExecutable) {
            getInfoStream(state) << "ExecutableRegionMonitor: effect=WritableToExecutable sourcePid="
                                 << hexval(sourcePid) << " pid=" << hexval(pid) << " base=" << hexval(region.start)
                                 << " size=" << hexval(region.end - region.start)
                                 << " oldProtection=" << hexval(oldProtection)
                                 << " newProtection=" << hexval(data.NewProtection) << " remote=" << remote << "\n";
        }
    }

    // NtProtectVirtualMemory is heavily used by EasyHook and normal image
    // maintenance. It is behavior evidence only when it changes executable
    // permissions on a region whose allocation already has analysis
    // provenance. Lifecycle state above is still updated for every matched
    // protection so a later writable-to-executable transition remains exact.
    bool protectionChanged = (data.OldProtection & 0xff) != (data.NewProtection & 0xff);
    bool executableRelevant = isExecutable(data.OldProtection) || isExecutable(data.NewProtection);
    if (matchedRegion && protectionChanged && executableRelevant) {
        getInfoStream(state) << "ExecutableRegionMonitor: effect=" << (remote ? "VirtualProtectEx" : "VirtualProtect")
                             << " native=NtProtectVirtualMemory sourcePid=" << hexval(sourcePid)
                             << " pid=" << hexval(pid) << " base=" << hexval(data.BaseAddress)
                             << " size=" << hexval(data.Size) << " oldProtection=" << hexval(data.OldProtection)
                             << " newProtection=" << hexval(data.NewProtection) << " remote=" << remote << "\n";
    }
}

void ExecutableRegionMonitor::onNtFreeVirtualMemory(S2EExecutionState *state, const S2E_WINMON2_FREE_VM &data) {
    if (!ntSuccess(data.Status) || !data.BaseAddress) {
        return;
    }

    uint64_t sourcePid = m_windows->getCurrentProcessId(state);
    uint64_t targetPid = m_windows->getPidFromHandle(state, sourcePid, data.ProcessHandle);
    uint64_t pid = targetPid ? targetPid : sourcePid;
    uint64_t end = exclusiveEnd(data.BaseAddress, data.Size);

    DECLARE_PLUGINSTATE(ExecutableRegionMonitorState, state);
    if (m_requireInstrumentationReady && !isTrustedThread(plgState, sourcePid, m_windows->getCurrentThreadId(state))) {
        return;
    }
    plgState->oracle.freed(pid, data.BaseAddress, data.Size ? end : data.BaseAddress);
    plgState->regions.erase(std::remove_if(plgState->regions.begin(), plgState->regions.end(),
                                           [&](const ExecutableRegion &region) {
                                               if (region.pid != pid) {
                                                   return false;
                                               }
                                               // MEM_RELEASE commonly reports size zero, in which case the base
                                               // identifies the whole allocation.
                                               return data.Size ? overlaps(region, data.BaseAddress, end)
                                                                : region.start == data.BaseAddress ||
                                                                      (region.start < data.BaseAddress &&
                                                                       data.BaseAddress < region.end);
                                           }),
                            plgState->regions.end());
}

void ExecutableRegionMonitor::onBlockExecute(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(ExecutableRegionMonitorState, state);
    uint64_t pid = m_windows->getCurrentProcessId(state);

    if (!plgState->armedPids.count(pid)) {
        // This callback is attached globally so it can see code without a
        // ModuleDescriptor. Keep the overwhelmingly common untracked-process
        // path to one PID-set lookup and do not query ModuleMap for it.
        if (!m_process->isTrackedPid(state, pid)) {
            return;
        }
        auto descendant = plgState->descendants.find(pid);
        if (descendant != plgState->descendants.end()) {
            // Do not attribute ntdll/kernel32 loader allocations to the
            // malware-created process. Activate the child only when its main
            // image starts or when it jumps into a region allocated remotely
            // by an already armed ancestor (e.g., process hollowing).
            auto injected =
                std::find_if(plgState->regions.begin(), plgState->regions.end(), [&](const ExecutableRegion &region) {
                    return region.pid == pid && region.start <= pc && pc < region.end;
                });
            bool injectedExecution = injected != plgState->regions.end();
            if (!injectedExecution) {
                auto module = m_modules->getModule(state, pid, pc);
                if (!module || lowerCase(module->Name) != descendant->second.imageName) {
                    return;
                }
            }
            plgState->armedPids.insert(pid);
            plgState->trustedThreads[pid].insert(m_windows->getCurrentThreadId(state));
            getInfoStream(state) << "ExecutableRegionMonitor: childActivated parentPid="
                                 << hexval(descendant->second.parentPid) << " pid=" << hexval(pid)
                                 << " image=" << descendant->second.imageName << " depth=" << descendant->second.depth
                                 << " reason=" << (injectedExecution ? "injected-allocation" : "main-image")
                                 << " pc=" << hexval(pc) << "\n";
        } else {
            if (m_requireInstrumentationReady && !plgState->readyPids.count(pid)) {
                return;
            }
            auto module = m_modules->getModule(state, pid, pc);
            if (!module || module->Name != m_moduleName) {
                return;
            }
            plgState->armedPids.insert(pid);
            getInfoStream(state) << "ExecutableRegionMonitor: armed pid=" << hexval(pid) << " module=" << module->Name
                                 << " pc=" << hexval(pc) << "\n";
        }
    }

    uint64_t tid = m_windows->getCurrentThreadId(state);
    if (m_requireInstrumentationReady && !isTrustedThread(plgState, pid, tid)) {
        return;
    }

    if (plgState->regions.empty()) {
        return;
    }

    auto it = std::find_if(plgState->regions.begin(), plgState->regions.end(), [&](const ExecutableRegion &region) {
        return region.pid == pid && region.start <= pc && pc < region.end;
    });
    if (it == plgState->regions.end() || it->executed) {
        return;
    }

    it->executed = true;
    // Windows' loader also reserves image address space through the same
    // native API. ModuleMap gives us a measured distinction: registered image
    // execution is ordinary module activity, while an unregistered allocation
    // is the dynamic-code behavior this plugin is intended to surface.
    auto module = m_modules->getModule(state, pid, pc);
    if (module) {
        getInfoStream(state) << "ExecutableRegionMonitor: executionIgnored=module-backed pid=" << hexval(pid)
                             << " pc=" << hexval(pc) << " module=" << module->Name << "\n";
        return;
    }

    getInfoStream(state) << "ExecutableRegionMonitor: effect=ExecuteAllocatedMemory sourcePid=" << hexval(it->sourcePid)
                         << " pid=" << hexval(pid) << " pc=" << hexval(pc) << " base=" << hexval(it->start)
                         << " size=" << hexval(it->end - it->start) << " protection=" << hexval(it->protection)
                         << " remote=" << it->remote << "\n";

    const unsigned previousStages[] = {plgState->oracle.stage(BehaviorGoal::AllocatedCodeExecution),
                                       plgState->oracle.stage(BehaviorGoal::ChildRemoteExecution)};
    plgState->oracle.executed(it->sourcePid, pid, pc);
    unsigned goalIndex = 0;
    for (auto goal : {BehaviorGoal::AllocatedCodeExecution, BehaviorGoal::ChildRemoteExecution}) {
        if (previousStages[goalIndex++] != behaviorGoalStages(goal) &&
            plgState->oracle.stage(goal) == behaviorGoalStages(goal)) {
            getInfoStream(state) << "BehaviorOracle: completed=" << behaviorGoalName(goal)
                                 << " state=" << state->getID() << " sourcePid=" << hexval(it->sourcePid)
                                 << " pid=" << hexval(pid) << " base=" << hexval(it->start) << " pc=" << hexval(pc)
                                 << "\n";
            // A native-only journal is the acceptance authority. Guest log
            // messages can contain arbitrary strings, including fake oracle
            // lines, and must never certify a completion contract.
            std::ofstream witness(s2e()->getOutputFilename("behavior-witnesses.jsonl"), std::ios::app);
            witness << "{\"schema\":1,\"goal\":\"" << behaviorGoalName(goal)
                    << "\",\"instance\":" << s2e()->getCurrentInstanceIndex() << ",\"state\":" << state->getID()
                    << ",\"source_pid\":" << it->sourcePid << ",\"pid\":" << pid << ",\"base\":" << it->start
                    << ",\"end\":" << it->end << ",\"pc\":" << pc << "}\n";
            witness.flush();
            if (!witness) {
                getWarningsStream(state) << "BehaviorOracle: could not persist completion witness\n";
            }
        }
    }

    if (!m_dumpOnExecute || !m_maxDumpBytes || it->dumped) {
        return;
    }
    it->dumped = true;

    uint64_t regionSize = it->end - it->start;
    uint64_t dumpSize = std::min(regionSize, m_maxDumpBytes);
    if (!dumpSize) {
        return;
    }

    // Read expressions directly. The bulk memory API concretizes symbolic
    // bytes, which silently adds solver work and changes exploration simply
    // because evidence collection was enabled.
    auto readConcrete = [&](uint64_t start, uint64_t size, std::vector<uint8_t> &bytes) {
        bytes.clear();
        bytes.reserve(size);
        for (uint64_t offset = 0; offset < size; ++offset) {
            klee::ref<klee::Expr> byte = state->mem()->read(start + offset, klee::Expr::Int8);
            if (!byte) {
                return false;
            }
            klee::ref<klee::ConstantExpr> constant = dyn_cast<klee::ConstantExpr>(byte);
            if (!constant) {
                bytes.clear();
                return false;
            }
            bytes.push_back(constant->getZExtValue());
        }
        return true;
    };

    uint64_t dumpStart = it->start;
    std::vector<uint8_t> bytes;
    if (!readConcrete(dumpStart, dumpSize, bytes)) {
        // A reserved region may contain uncommitted holes before the executed
        // payload. Fall back to the concrete executing page rather than
        // concretizing those holes or losing all payload evidence.
        dumpStart = pc & ~UINT64_C(0xfff);
        dumpSize = std::min(it->end - dumpStart, std::min(m_maxDumpBytes, UINT64_C(0x10000)));
        if (!dumpSize || !readConcrete(dumpStart, dumpSize, bytes)) {
            getInfoStream(state) << "ExecutableRegionMonitor: dumpSkipped=symbolic-or-unreadable pid=" << hexval(pid)
                                 << " base=" << hexval(it->start) << " pc=" << hexval(pc) << "\n";
            return;
        }
    }

    std::stringstream filename;
    filename << "executable-region-state" << state->getID() << "-pid" << std::hex << pid << "-" << it->start << "-at"
             << dumpStart << ".bin";
    std::string path = s2e()->getOutputFilename(filename.str());
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        getWarningsStream(state) << "ExecutableRegionMonitor: could not create " << path << "\n";
        return;
    }
    output.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    output.close();
    getInfoStream(state) << "ExecutableRegionMonitor: dump=" << filename.str() << " bytes=" << dumpSize << "\n";
}

void ExecutableRegionMonitor::onProcessLoad(S2EExecutionState *state, uint64_t pageDir, uint64_t pid,
                                            const std::string &imageName) {
    if (!m_trackChildProcesses || !pid) {
        return;
    }

    DECLARE_PLUGINSTATE(ExecutableRegionMonitorState, state);
    uint64_t parentPid = m_windows->getProcessParent(state, pid);
    if (!plgState->armedPids.count(parentPid)) {
        return;
    }

    uint64_t depth = 1;
    auto parent = plgState->descendants.find(parentPid);
    if (parent != plgState->descendants.end()) {
        depth = parent->second.depth + 1;
    }
    if (depth > m_maxChildDepth) {
        getWarningsStream(state) << "ExecutableRegionMonitor: childSkipped=maxChildDepth parentPid="
                                 << hexval(parentPid) << " pid=" << hexval(pid) << " image=" << imageName
                                 << " depth=" << depth << "\n";
        return;
    }
    if (!plgState->descendants.count(pid) && plgState->descendants.size() >= m_maxChildren) {
        getWarningsStream(state) << "ExecutableRegionMonitor: childSkipped=maxChildren parentPid=" << hexval(parentPid)
                                 << " pid=" << hexval(pid) << " image=" << imageName << "\n";
        return;
    }

    DescendantProcess child;
    child.parentPid = parentPid;
    child.depth = depth;
    child.imageName = lowerCase(imageName);
    plgState->descendants[pid] = child;
    plgState->oracle.childCreated(parentPid, pid);
    plgState->armedPids.erase(pid);

    // Keeping the PID in ProcessExecutionDetector ensures the analysis does
    // not terminate merely because the original sample exits while a child or
    // hollowed payload is still running.
    m_process->trackPid(state, pid);
    getInfoStream(state) << "ExecutableRegionMonitor: effect=ChildProcess parentPid=" << hexval(parentPid)
                         << " pid=" << hexval(pid) << " image=" << child.imageName << " depth=" << depth << "\n";
}

void ExecutableRegionMonitor::onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid,
                                              uint64_t returnCode) {
    DECLARE_PLUGINSTATE(ExecutableRegionMonitorState, state);
    plgState->oracle.processExited(pid);
    plgState->regions.erase(std::remove_if(plgState->regions.begin(), plgState->regions.end(),
                                           [&](const ExecutableRegion &region) { return region.pid == pid; }),
                            plgState->regions.end());
    plgState->armedPids.erase(pid);
    plgState->readyPids.erase(pid);
    plgState->trustedThreads.erase(pid);
    plgState->descendants.erase(pid);
}

void ExecutableRegionMonitor::onThreadCreate(S2EExecutionState *state, const ThreadDescriptor &thread) {
    if (!m_requireInstrumentationReady || !thread.Pid || !thread.Tid) {
        return;
    }

    DECLARE_PLUGINSTATE(ExecutableRegionMonitorState, state);
    // Trust threads created after the explicit readiness boundary. EasyHook's
    // injection thread already exists at that point and is never admitted.
    if (!plgState->readyPids.count(thread.Pid) && !plgState->armedPids.count(thread.Pid)) {
        return;
    }
    plgState->trustedThreads[thread.Pid].insert(thread.Tid);
    getInfoStream(state) << "ExecutableRegionMonitor: trustedThreadCreated pid=" << hexval(thread.Pid)
                         << " tid=" << hexval(thread.Tid) << "\n";
}

void ExecutableRegionMonitor::onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread) {
    if (!m_requireInstrumentationReady || !thread.Pid || !thread.Tid) {
        return;
    }

    DECLARE_PLUGINSTATE(ExecutableRegionMonitorState, state);
    auto process = plgState->trustedThreads.find(thread.Pid);
    if (process == plgState->trustedThreads.end()) {
        return;
    }
    process->second.erase(thread.Tid);
    if (process->second.empty()) {
        plgState->trustedThreads.erase(process);
    }
}

} // namespace plugins
} // namespace s2e
