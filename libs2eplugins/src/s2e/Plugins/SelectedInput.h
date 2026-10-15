#ifndef S2E_SELECTED_INPUT_H
#define S2E_SELECTED_INPUT_H
#include <cstdint>
#include <string>
#include <vector>

namespace s2e { namespace plugins {
struct SelectedInput {
    std::string api, path, value, scope, seed;
    unsigned readIndex = 1;
    std::vector<unsigned> offsets;
    bool enabled = false;

    bool valid() const {
        if ((scope != "root" && scope != "child") || path.empty() || path.size() > 512 || value.size() > 512 ||
            seed.empty() || seed.size() > 256 || readIndex < 1 || readIndex > 8 || offsets.empty() || offsets.size() > 16)
            return false;
        if (api != "ReadFile" && api != "RegQueryValueExA" && api != "RegQueryValueExW" &&
            api != "GetEnvironmentVariableA" && api != "GetEnvironmentVariableW") return false;
        for (size_t i = 0; i < offsets.size(); ++i)
            if (offsets[i] >= seed.size() || (i && offsets[i-1] >= offsets[i])) return false;
        return true;
    }

    bool accepts(const std::string &observed, unsigned type) const {
        if (!valid() || observed != seed) return false;
        if (api == "ReadFile") return true;
        if (api.find("Reg") == 0 && type == 4) return seed.size() == 4;
        if (api.find("Reg") == 0 && type != 1 && type != 2) return false;
        const unsigned width = api.back() == 'W' ? 2 : 1;
        const bool registry = api.find("Reg") == 0;
        if (seed.size() % width || (registry && seed.size() <= width)) return false;
        const size_t end = seed.size() - (registry ? width : 0);
        for (size_t i = 0; i < seed.size(); ++i) {
            unsigned char c = seed[i];
            if ((width == 2 && i % 2) || i >= end) { if (c) return false; }
            else if (c < 32 || c > 126) return false;
        }
        for (unsigned offset : offsets)
            if (offset >= end || (width == 2 && offset % 2)) return false;
        return true;
    }
};
} }
#endif
