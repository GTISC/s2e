#include <s2e/managed.h>
#include <stddef.h>

/* The native x86 CLR bridge and the 64-bit host must agree on the wire ABI. */
_Static_assert(sizeof(struct ManagedCommand) == 1853, "managed packet size");
_Static_assert(offsetof(struct ManagedCommand, processStart) == 16, "process lifetime offset");
_Static_assert(offsetof(struct ManagedCommand, probes) == 52, "probe offsets");
_Static_assert(offsetof(struct ManagedCommand, session) == 1076, "session offset");
_Static_assert(ManagedStart == 1 && ManagedBooleanSource == 8, "operation numbers");

int main(void) {
    return 0;
}
