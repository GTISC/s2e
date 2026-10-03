// Value-owned state: a fork copies bindings, counters and invalidations.
#ifndef S2E_MANAGED_BINDINGS_H
#define S2E_MANAGED_BINDINGS_H
#include <algorithm>
#include <map>
#include <s2e/managed.h>
#include <set>
#include <string>
#include <vector>

namespace s2e {
namespace plugins {
struct ManagedExpectedMethod {
    std::string original;
    std::vector<uint32_t> probes;
};
struct ManagedPolicy {
    std::string session, mvid, plan;
    std::map<uint32_t, ManagedExpectedMethod> methods;
    uint32_t booleanSourceToken = 0, booleanSourceSeed = 0;
};
struct ManagedBinding {
    uint32_t module, token, start, size;
    std::string original, instrumented;
    std::set<uint32_t> probes;
};
struct ManagedBindings {
    bool active = false, ended = false;
    uint32_t pid = 0, next = 0;
    uint64_t processStart = 0;
    std::map<uint32_t, ManagedBinding> methods;
    std::set<uint32_t> retired;
    std::set<uint32_t> publishedTokens;
    std::map<uint32_t, std::set<uint32_t>> observed;
    unsigned forks = 0;
    bool sourceConsumed = false;

    template <size_t N> static bool terminated(const char (&s)[N]) {
        return std::find(s, s + N, '\0') != s + N;
    }
    static bool hash(const std::string &s) {
        return s.size() == 64 && s.find_first_not_of("0123456789abcdef") == std::string::npos;
    }
    bool contains(uint64_t pc) const {
        for (const auto &m : methods) {
            if (pc >= m.second.start && pc - m.second.start < m.second.size)
                return true;
        }
        return false;
    }
    // Any error poisons the run at the caller; never retry a rejected packet.
    std::string accept(const ManagedCommand &c, uint64_t callerPid, const ManagedPolicy &policy) {
        if (c.version != 1 || !c.pid || c.pid != callerPid || c.sequence != next || next == UINT32_MAX ||
            !terminated(c.session) || !terminated(c.mvid) || !terminated(c.plan) || !terminated(c.original) ||
            !terminated(c.instrumented) || !terminated(c.event))
            return "wire_identity_or_sequence";
        if (policy.session != c.session || policy.plan != c.plan)
            return "session_or_plan";
        if (c.operation == ManagedStart) {
            if (active || ended || next || !c.processStart)
                return "duplicate_or_invalid_start";
            active = true;
            pid = c.pid;
            processStart = c.processStart;
        } else {
            if (!active || c.pid != pid || c.processStart != processStart)
                return "inactive_process";
            if (c.operation == ManagedRegister) {
                auto expected = policy.methods.find(c.token);
                if (!c.module || !c.function || !c.start || !c.size ||
                    uint64_t(c.start) + c.size > (uint64_t(1) << 32) || policy.mvid != c.mvid ||
                    expected == policy.methods.end() || expected->second.original != c.original ||
                    !hash(c.instrumented) || c.probeCount != expected->second.probes.size() || c.probeCount > 256 ||
                    !std::equal(expected->second.probes.begin(), expected->second.probes.end(), c.probes) ||
                    methods.count(c.function) || retired.count(c.function) || publishedTokens.count(c.token))
                    return "invalid_binding";
                for (const auto &m : methods) {
                    if (m.second.token == c.token || (uint64_t(c.start) < uint64_t(m.second.start) + m.second.size &&
                                                      uint64_t(m.second.start) < uint64_t(c.start) + c.size))
                        return "overlapping_binding";
                }
                methods.emplace(c.function,
                                ManagedBinding{c.module, c.token, c.start, c.size, c.original, c.instrumented,
                                               std::set<uint32_t>(c.probes, c.probes + c.probeCount)});
                publishedTokens.insert(c.token);
            } else if (c.operation == ManagedProbe) {
                auto m = methods.find(c.function);
                if (m == methods.end() || !m->second.probes.count(c.offset))
                    return "unpublished_or_unplanned_probe";
                observed[c.function].insert(c.offset);
            } else if (c.operation == ManagedBooleanSource) {
                auto m = methods.find(c.function);
                if (!policy.booleanSourceToken || sourceConsumed || m == methods.end() ||
                    m->second.token != policy.booleanSourceToken || c.token != policy.booleanSourceToken ||
                    !observed[c.function].count(0) || c.offset != policy.booleanSourceSeed || c.offset > 1 ||
                    !c.start || c.size != 4 || uint64_t(c.start) + 4 > (uint64_t(1) << 32))
                    return "invalid_boolean_source";
                sourceConsumed = true;
            } else if (c.operation == ManagedInvalidateFunction) {
                methods.erase(c.function);
                retired.insert(c.function);
            } else if (c.operation == ManagedInvalidateModule) {
                for (auto m = methods.begin(); m != methods.end();) {
                    if (m->second.module == c.module) {
                        retired.insert(m->first);
                        m = methods.erase(m);
                    } else
                        ++m;
                }
            } else if (c.operation == ManagedEnd) {
                active = false;
                ended = true;
                methods.clear();
            } else if (c.operation != ManagedEvent)
                return "unknown_operation";
        }
        ++next;
        return "";
    }
};
} // namespace plugins
} // namespace s2e
#endif
