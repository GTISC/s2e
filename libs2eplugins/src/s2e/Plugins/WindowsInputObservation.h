#ifndef S2E_WINDOWS_INPUT_OBSERVATION_H
#define S2E_WINDOWS_INPUT_OBSERVATION_H

#include <cstdint>
#include <limits>
#include <string>

namespace s2e { namespace plugins { namespace input_observation {

// A Win32 sentinel alone does not identify ERROR_FILE_NOT_FOUND. Only the
// registry APIs return an error code directly; never read a stale last-error.
inline const char *accessOutcome(const std::string &api, uint32_t result, uint32_t capacity = 0) {
    if (api.find("RegOpenKeyEx") == 0 || api.find("RegQueryValueEx") == 0) {
        if (!result) return "success";
        if (result == 2 || result == 3) return "not_found";
        if (result == 5) return "access_denied";
        if (result == 234) return "buffer_too_small";
        return "failed";
    }
    if (api.find("CreateFile") == 0 || api.find("GetFileAttributes") == 0 || api.find("FindFirstFile") == 0)
        return result == UINT32_MAX ? "failed" : "success";
    if (api == "ReadFile") return result ? "success" : "failed";
    if (api.find("GetEnvironmentVariable") == 0) {
        if (!result) return "zero_return"; // empty and absent remain ambiguous
        return result >= capacity ? "buffer_too_small" : "success";
    }
    return nullptr;
}

// Read last-error only after APIs whose failure contract defines it. Registry
// LSTATUS is already authoritative and successful Win32 calls may leave it stale.
inline bool needsLastError(const std::string &api, uint32_t result) {
    if (api.find("CreateFile") == 0 || api.find("GetFileAttributes") == 0 || api.find("FindFirstFile") == 0)
        return result == UINT32_MAX;
    return (api == "ReadFile" || api.find("GetEnvironmentVariable") == 0) && result == 0;
}
inline const char *accessOutcome(const std::string &api, uint32_t result, uint32_t capacity,
                                 bool errorValid, uint32_t error) {
    const char *basic = accessOutcome(api, result, capacity);
    if (!errorValid || !needsLastError(api, result)) return basic;
    if (error == 2 || error == 3 || (api.find("GetEnvironmentVariable") == 0 && error == 203)) return "not_found";
    if (error == 5) return "access_denied";
    if (error == 32 || error == 33) return "sharing_violation";
    return basic;
}

// These are observations of completed calls, never models of pending I/O.
inline bool bufferExtent(uint32_t count, uint32_t requested, bool completed, bool overlapped = false) {
    return completed && !overlapped && count && count <= requested && count <= 4096;
}

// Summaries preserve large completed reads without turning a sampled prefix
// into an authoritative complete source or widening symbolic input budgets.
inline bool largeReadExtent(uint32_t count, uint32_t requested, bool completed, bool overlapped) {
    return completed && !overlapped && count > 4096 && count <= requested && count <= 64 * 1024 * 1024;
}

// Only the operand of a host-verified PE HIGHLOW relocation may differ.
// Preserve opcode and in-image IAT identity across both positive and negative
// load biases; never mask arbitrary instruction bytes to obtain a match.
inline bool relocatedIndirectCall(const std::string &actual, const std::string &original,
                                  uint64_t preferredBase, uint64_t loadBase, uint64_t imageSize) {
    if (actual.size() != 6 || original.size() != 6 ||
        static_cast<unsigned char>(original[0]) != 0xff ||
        (static_cast<unsigned char>(original[1]) != 0x15 && static_cast<unsigned char>(original[1]) != 0x25) ||
        actual[0] != original[0] || actual[1] != original[1] || !imageSize ||
        preferredBase + imageSize > (uint64_t(1) << 32) || loadBase + imageSize > (uint64_t(1) << 32)) return false;
    uint32_t wanted = 0, observed = 0;
    for (unsigned i = 0; i < 4; ++i) {
        wanted |= uint32_t(static_cast<unsigned char>(original[i + 2])) << (8 * i);
        observed |= uint32_t(static_cast<unsigned char>(actual[i + 2])) << (8 * i);
    }
    return wanted >= preferredBase && uint64_t(wanted) + 4 <= preferredBase + imageSize &&
           uint64_t(observed) == loadBase + (wanted - preferredBase);
}

inline bool environmentExtent(uint32_t returned, uint32_t capacity, unsigned width, uint32_t &bytes,
                              uint32_t &requested) {
    if ((width != 1 && width != 2) || !returned || returned >= capacity ||
        capacity > std::numeric_limits<uint32_t>::max() / width || returned > 256 / width) return false;
    bytes = returned * width;
    requested = capacity * width;
    return true;
}

// Winsock uses signed int returns, represented here as their raw 32-bit EAX
// value. Accept only completed positive transfers bounded by the caller's
// concrete request; SOCKET_ERROR (0xffffffff) and zero never carry bytes.
inline bool networkTransferExtent(uint32_t result, uint32_t requested, uint32_t &captured) {
    if (!result || result == UINT32_MAX || result > requested || requested > 65536) return false;
    captured = result > 512 ? 512 : result;
    return true;
}

inline bool networkAddressExtent(uint32_t length) {
    return length > 0 && length <= 128;
}

inline bool ipv4Sockaddr(const std::string &bytes) {
    return bytes.size() == 16 && static_cast<unsigned char>(bytes[0]) == 2 && bytes[1] == 0;
}

inline bool sameIpv4Endpoint(const std::string &left, const std::string &right) {
    return ipv4Sockaddr(left) && ipv4Sockaddr(right) && left.compare(0, 8, right, 0, 8) == 0;
}

} } }
#endif
