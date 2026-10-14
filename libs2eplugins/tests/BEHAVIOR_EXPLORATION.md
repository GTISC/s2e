# Bounded dynamic exploration and testcase capture

The behavior-analysis runner uses these native settings:

```lua
pluginsConfig.LuaCoreEvents.maxDynamicForks = 8
pluginsConfig.LuaCoreEvents.maxDynamicForksPerSite = 1
pluginsConfig.LuaCoreEvents.maxDynamicLoopForks = 2
pluginsConfig.TestCaseGenerator.generateOnStateFork = true
pluginsConfig.TestCaseGenerator.generateOnStateKill = true
pluginsConfig.TestCaseGenerator.terminateAfterSeconds = 240
```

The dynamic allowance defaults to **off** (`maxDynamicForks = 0`). Enabling it
requires ExecutableRegionMonitor and permits forks only in trusted, executed
allocations outside known modules. Earlier plugin safety/resource vetoes are
preserved. The total and site budgets are per S2E worker, shared by sibling
states. Site identity includes process, allocation lifetime, and a stable
allocation-relative PC. Reserve/commit overlap preserves the lifetime identity;
free/reallocation gets a new one. Denials do not spend budget.

The backward-edge allowance defaults to two, and the site allowance to one.
A backward successor is a loop heuristic, not proof a branch is irrelevant.
These limits redistribute a bounded exploration budget; they do not establish
ATT&CK importance or guarantee deeper behavior coverage. They do not shorten
the concrete execution of a loop. Both limit settings are configurable in Lua.

`terminateAfterSeconds` defaults to zero (disabled), with range 0..86400.
It measures wall time from plugin initialization, including guest startup.
At expiry, the timer arms execution instrumentation and requests a safe TB
cache flush. Termination occurs in the next execution callback, not in QEMU's
timer dispatcher, which cannot catch `CpuExitException`. Inactive states are
terminated before the active one so all final testcases can be recorded.
There is no per-block deadline instrumentation before expiry. A stuck solver
or externally killed process can still require a host fallback and yield
incomplete evidence; consumers must check capture completeness.

Fork capture writes `TC_TRACE | TC_FILE`. Generic API-input arrays require
the trace record; file assembly alone handles only specially named symbolic
files. WindowsMonitor's generic PID/TID accessors support inactive states via
their saved state cache, without changing the active cache. Mal-S2E's batch
exporter retains the latest testcase for each state, including empty inputs.

## Verification

From the repository root:

```sh
c++ -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -I libs2eplugins/src libs2eplugins/tests/DynamicForkBudgetTest.cpp \
  -o /tmp/s2e-dynamic-budget-test
/tmp/s2e-dynamic-budget-test
```

Also run `BehaviorOracleTest.cpp` and `SparseSymbolicPolicyTest.cpp` with the
same flags. Build both supported engine targets. Live integration fixtures
are in GTISC/Mal-S2E: `dynamic_profile` checks both allocated-code outcomes;
`dynamic_deadline` keeps both states alive until native timeout. Run
`script/ci/verify_testcase_capture.py` on their resolved output directories.
The real-sample evaluation and limitations are documented in Mal-S2E's
`script/test_samples/hand_made/REAL_SAMPLE_FIXES.md`.
