#ifndef S2E_DYNAMIC_FORK_BUDGET_H
#define S2E_DYNAMIC_FORK_BUDGET_H

#include <cstdint>
#include <map>
#include <tuple>

namespace s2e {
namespace plugins {

// Global exploration budget, shared across sibling states. Allocation IDs are
// inherited on fork and replaced on reallocation, avoiding PID/address reuse.
class DynamicForkBudget {
    using Site = std::tuple<uint64_t, uint64_t, uint64_t>;
    std::map<Site, unsigned> m_sites;
    unsigned m_total = 0, m_loops = 0;

public:
    bool grant(uint64_t pid, uint64_t allocation, uint64_t offset, bool backedge,
               unsigned totalLimit, unsigned siteLimit, unsigned loopLimit) {
        Site site(pid, allocation, offset);
        auto it = m_sites.find(site);
        if (m_total >= totalLimit || (it != m_sites.end() && it->second >= siteLimit) ||
            !siteLimit || (backedge && m_loops >= loopLimit)) {
            return false;
        }
        ++m_sites[site];
        ++m_total;
        m_loops += backedge;
        return true;
    }
    unsigned total() const { return m_total; }
};

} // namespace plugins
} // namespace s2e
#endif
