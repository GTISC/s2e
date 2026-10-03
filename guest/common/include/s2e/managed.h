// Versioned synchronous CLR observation protocol. All addresses are guest x86.
#ifndef S2E_MANAGED_H
#define S2E_MANAGED_H
#include <stdint.h>
enum ManagedOperation {
    ManagedStart = 1,
    ManagedRegister,
    ManagedProbe,
    ManagedInvalidateFunction,
    ManagedInvalidateModule,
    ManagedEnd,
    ManagedEvent,
    ManagedBooleanSource
};
#pragma pack(push, 1)
struct ManagedCommand {
    uint32_t version, operation, sequence, pid;
    uint64_t processStart;
    uint32_t module, function, token, start, size, offset, probeCount;
    uint32_t probes[256];
    char session[33], mvid[37], plan[65], original[65], instrumented[65], event[512];
};
#pragma pack(pop)
#endif
