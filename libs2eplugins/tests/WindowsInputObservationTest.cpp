#include <s2e/Plugins/WindowsInputObservation.h>
#include <cassert>
#include <cstdint>
using namespace s2e::plugins::input_observation;

int main() {
    assert(needsLastError("CreateFileA", UINT32_MAX));
    assert(!needsLastError("CreateFileA", 42));
    assert(!needsLastError("RegQueryValueExW", 2));
    assert(std::string(accessOutcome("CreateFileW", UINT32_MAX, 0, true, 32)) == "sharing_violation");
    assert(std::string(accessOutcome("CreateFileW", UINT32_MAX, 0, true, 2)) == "not_found");
    assert(std::string(accessOutcome("CreateFileW", 42, 0, true, 32)) == "success");
    assert(std::string(accessOutcome("CreateFileW", UINT32_MAX, 0, false, 2)) == "failed");
    assert(std::string(accessOutcome("GetEnvironmentVariableA", 0, 16, true, 203)) == "not_found");
    assert(std::string(accessOutcome("RegOpenKeyExW", 2)) == "not_found");
    assert(std::string(accessOutcome("RegQueryValueExA", 3)) == "not_found");
    assert(std::string(accessOutcome("RegQueryValueExW", 5)) == "access_denied");
    assert(std::string(accessOutcome("RegQueryValueExW", 234)) == "buffer_too_small");
    assert(std::string(accessOutcome("RegOpenKeyExW", 0)) == "success");
    assert(std::string(accessOutcome("CreateFileW", UINT32_MAX)) == "failed");
    assert(std::string(accessOutcome("GetFileAttributesW", UINT32_MAX)) == "failed");
    assert(std::string(accessOutcome("FindFirstFileA", 42)) == "success");
    assert(std::string(accessOutcome("GetEnvironmentVariableW", 0, 4)) == "zero_return");
    assert(std::string(accessOutcome("GetEnvironmentVariableW", 4, 4)) == "buffer_too_small");
    assert(std::string(accessOutcome("GetEnvironmentVariableW", 3, 4)) == "success");
    assert(!accessOutcome("WriteFile", 0));
    assert(bufferExtent(4, 4, true));
    assert(!bufferExtent(0, 4, true));
    assert(!bufferExtent(5, 4, true));
    assert(!bufferExtent(4097, 8192, true));
    assert(!bufferExtent(4, 4, false));
    assert(!bufferExtent(4, 4, true, true));
    uint32_t bytes = 0, requested = 0;
    assert(environmentExtent(3, 4, 2, bytes, requested));
    assert(bytes == 6 && requested == 8);
    assert(!environmentExtent(0, 4, 1, bytes, requested));
    assert(!environmentExtent(4, 4, 1, bytes, requested));
    assert(!environmentExtent(5, 4, 1, bytes, requested));
    assert(!environmentExtent(129, 256, 2, bytes, requested));
    assert(!environmentExtent(1, UINT32_MAX, 2, bytes, requested));
    assert(!environmentExtent(1, 4, 0, bytes, requested));
    uint32_t captured = 0;
    assert(networkTransferExtent(4, 4, captured) && captured == 4);
    assert(networkTransferExtent(600, 1024, captured) && captured == 512);
    assert(!networkTransferExtent(0, 4, captured));
    assert(!networkTransferExtent(UINT32_MAX, 4, captured));
    assert(!networkTransferExtent(5, 4, captured));
    assert(!networkTransferExtent(1, 65537, captured));
    assert(networkAddressExtent(16));
    assert(!networkAddressExtent(0));
    assert(!networkAddressExtent(129));
    assert(ipv4Sockaddr(std::string("\x02\x00", 2) + std::string(14, '\0')));
    assert(!ipv4Sockaddr(std::string("\x17\x00", 2) + std::string(14, '\0')));
}
