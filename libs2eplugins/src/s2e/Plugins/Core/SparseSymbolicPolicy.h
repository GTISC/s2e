// Explicit under-approximation of guest-requested symbolic buffers.
#ifndef S2E_SPARSE_SYMBOLIC_POLICY_H
#define S2E_SPARSE_SYMBOLIC_POLICY_H
#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace s2e {
namespace plugins {
class SparseSymbolicPolicy {
public:
    using Ranges = std::vector<std::pair<unsigned, unsigned>>; // [begin,end)
private:
    std::map<std::string, Ranges> m_rules;

public:
    bool add(const std::string &name, Ranges ranges) {
        if (name.empty() || name.size() > 128 || ranges.empty() || m_rules.count(name))
            return false;
        if (name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.") !=
            std::string::npos)
            return false;
        std::sort(ranges.begin(), ranges.end());
        unsigned end = 0;
        for (const auto &range : ranges) {
            if (range.first < end || range.first >= range.second || range.second > 4096)
                return false;
            end = range.second;
        }
        m_rules.emplace(name, std::move(ranges));
        return true;
    }
    const Ranges *match(const std::string &name) const {
        const Ranges *result = nullptr;
        size_t longest = 0;
        for (const auto &rule : m_rules) {
            const auto &prefix = rule.first;
            if (prefix.size() > longest &&
                (name == prefix || (name.size() > prefix.size() && name.compare(0, prefix.size(), prefix) == 0 &&
                                    name[prefix.size()] == '.'))) {
                result = &rule.second;
                longest = prefix.size();
            }
        }
        return result;
    }
    static Ranges clipped(const Ranges &ranges, unsigned size) {
        Ranges result;
        for (const auto &range : ranges) {
            if (range.first < size)
                result.emplace_back(range.first, std::min(size, range.second));
        }
        return result;
    }
};
} // namespace plugins
} // namespace s2e
#endif
