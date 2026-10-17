#ifndef S2E_PLUGINS_EXECUTABLETHREADPOLICY_H
#define S2E_PLUGINS_EXECUTABLETHREADPOLICY_H

namespace s2e {
namespace plugins {

/// Admit a thread after the explicit instrumentation boundary when either its
/// lifecycle was observed or it is executing code owned by an armed sample.
/// The ownership fallback is required on guests whose thread notifications do
/// not reach WindowsMonitor; pre-boundary and foreign-module execution remain
/// excluded.
inline bool admitExecutionThread(bool requireReady, bool trusted, bool armed, bool ownedExecution) {
    return !requireReady || trusted || (armed && ownedExecution);
}

} // namespace plugins
} // namespace s2e

#endif
