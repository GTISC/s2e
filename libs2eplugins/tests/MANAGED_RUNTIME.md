# Managed runtime bridge

`ManagedRuntime` connects an explicitly enabled x86 CLR profiler to S2E. It
registers planned original-IL locations against live JIT code, records probe
arrival, bounds forks to those code ranges, and optionally supplies one typed
Boolean input. It is disabled unless the project loads the plugin.

The producer, IL-plan builder, original-byte auditor and pristine concrete
replayer are in [MalwareLab](https://github.com/GTISC/MalwareLab), under
`tools/clr_profiler/`, `tools/dotnet_s2e_ci.py`, `tools/dotnet_source_ci.py` and
`tools/dotnet_pipeline_ci.py`. A CLR profiler and its original-IL plan are
required; loading this plugin alone does not instrument an assembly.

## Build and interface

The ordinary engine build compiles the plugin into `libs2e.so`. Guest-tool
installation includes `include/s2e/managed.h`, alongside `s2e.h` and `opcodes.h`,
so the profiler can build against installed headers. Protocol version 1 has a
packed 1,853-byte packet; guest addresses and IDs are x86 values even when the
S2E host or Windows guest is 64-bit.

Load `ManagedRuntime`, `WindowsMonitor`, `ProcessExecutionDetector`,
`BaseInstructions` and the normal tracing/testcase plugins. Configure
`ProcessExecutionDetector.moduleNames` for the target executable. The managed
configuration is generated from the original-byte plan:

```lua
pluginsConfig.ManagedRuntime = {
    session = "<32-character run identifier>",
    mvid = "<original module MVID>",
    plan = "<64-character lowercase SHA-256 of the instrumented plan>",
    maxForks = 8,
    boundForks = true,
    methods = {
        main = {
            token = 0x06000001,
            original = "<64-character original method-body SHA-256>",
            probes = "0 188 198 208"
        }
    }
}
```

These placeholders must be replaced with actual identities. MethodDef tokens
must be unique; offsets must be sorted, unique and nonempty (at most 256 per
method, 64 methods). `maxForks` is a per-path bound from 0 through 16. The fork
callback only vetoes and cannot override another plugin's resource decision.
Disabling `boundForks` removes this plugin's fork restriction, not other limits.

Packets bind session, plan, caller PID, process creation time and consecutive
sequence number. Registration additionally checks the original MVID/body,
instrumented hash, exact planned offsets and disjoint native ranges. A new
function ID cannot republish an already registered MethodDef token. Probe
arrival is accepted only after registration. Process address space is checked
on every packet; process/image/function unload invalidates bindings. State
forks copy bindings, sequence counters, observed offsets and source-use status
by value. Rejected packets terminate the state.

## Symbolic input and evidence

The file fixture uses S2E's existing symbolic-file mechanism. The optional
`booleanSourceToken` and `booleanSourceSeed` select a planned getter with a
probe at offset zero and a seed of 0 or 1. After that getter's entry, one source
packet may replace a concrete four-byte slot with a zero-extended symbolic
byte constrained to 0/1. Repeated source calls, unplanned getters, wrong seeds
and addresses outside the x86 space are rejected. `TestCaseGenerator` exports
the byte as the `managed_boolean` symbolic file. MalwareLab maps each value to
a concrete response recipe and replays pristine bytes without the profiler.
This is a typed input model; it is not symbolic parsing of arbitrary HTTP.

`managed-s2e.jsonl` records accepted/rejected packets, fork inheritance, image
unload, process exit and state termination. MalwareLab checks the journal
against original IL, the profiler stream, independently captured process
lifetime, solver inputs, receipts and fresh replay artifacts. Probe arrival
does not establish instruction completion or external effects. A prepared or
JIT-compiled method receives no execution credit without a probe.

Windows process exit status is read as a 32-bit NTSTATUS. An unreadable status
uses an out-of-DWORD sentinel; adjacent EPROCESS bytes must not contaminate a
successful exit or silently turn a read failure into success.

## Validation

Run the standalone native contracts without a VM or LLVM dependency:

```sh
cmake -S libs2eplugins/tests -B build-managed -DCMAKE_BUILD_TYPE=Release
cmake --build build-managed --parallel 2
ctest --test-dir build-managed --output-on-failure
```

The managed-runtime Actions workflow runs these contracts with GCC and Clang.
Assertions remain enabled in release builds. The full existing engine build
workflow also compiles the plugin. The tests cover ABI layout, mismatched
identities/lifetimes, invalid ranges/probes, token reuse, fork isolation,
invalidation and the single-use Boolean source. They do not execute the CLR.

For VM qualification, run MalwareLab's `tools/dotnet_pipeline_ci.py` with a
host manifest pinning the freshly built engine and these transport headers.
Use a new output directory and require both solver values and both fresh
profiler-free CAPE replay receipts. The previously qualified engine hash is
not evidence for a new build; preserve the new engine identity and qualification
results before updating any installed runner's pin.

Scope is an explicit x86 .NET Framework IL-only profile. CoreCLR, managed x64,
generic sharing, ReJIT, inlined selected methods, arbitrary repeated symbolic
sources, complete IL/branch coverage and persistent rewriting are not qualified.
The in-process profiler is not a tamper-resistant observer for hostile code.
Remote service/dispatcher delivery requires separate deployment qualification.
