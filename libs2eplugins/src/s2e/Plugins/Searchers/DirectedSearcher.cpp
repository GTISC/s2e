#include "DirectedSearcher.h"

#include <limits>

using namespace s2e;
using namespace s2e::plugins;

DirectedSearcher::DirectedSearcher(S2E *s2e)
    : Plugin(s2e), m_currentState(nullptr), m_randomEngine(std::random_device()()) {
}

void DirectedSearcher::initialize() {
    // Any necessary initialization code
}

void DirectedSearcher::loadCFG(const std::string &cfgPath) {
    // Load and parse the CFG from the file
    // This is a placeholder, actual implementation will depend on your CFG format
    // Example: m_cfg[node] = {successor1, successor2, ...};
    // Use any suitable file parsing library to load the CFG
    // This is a dummy example, replace with actual file reading logic
    m_cfg[0] = {1, 2};
    m_cfg[1] = {3};
    m_cfg[2] = {3};
    m_cfg[3] = {};
}

void DirectedSearcher::calculateBranchDistance(S2EExecutionState *state) {
    // Calculate branch distance for the given state
    // This is a placeholder, actual implementation will depend on your method
    m_branchDistances[state] = 0.0; // Replace with actual branch distance calculation
}

S2EExecutionState *DirectedSearcher::selectState() {
    // Select the state with the minimum branch distance
    S2EExecutionState *selectedState = nullptr;
    double minDistance = std::numeric_limits<double>::max();

    for (const auto &entry : m_branchDistances) {
        if (entry.second < minDistance) {
            minDistance = entry.second;
            selectedState = entry.first;
        }
    }

    m_currentState = selectedState;
    return selectedState;
}

void DirectedSearcher::update(klee::ExecutionState *current, const klee::StateSet &addedStates,
                              const klee::StateSet &removedStates) {
    // Update states and recalculate branch distances
    for (auto state : addedStates) {
        auto s2eState = dynamic_cast<S2EExecutionState *>(state);
        m_branchDistances[s2eState] = 0.0;
        calculateBranchDistance(s2eState);
    }

    for (auto state : removedStates) {
        auto s2eState = dynamic_cast<S2EExecutionState *>(state);
        m_branchDistances.erase(s2eState);
    }
}

bool DirectedSearcher::empty() const {
    return m_branchDistances.empty();
}

void DirectedSearcher::setActive(S2EExecutionState *state, bool active) {
    if (active) {
        m_branchDistances[state] = 0.0;
        calculateBranchDistance(state);
    } else {
        m_branchDistances.erase(state);
    }
}

void DirectedSearcher::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    // Implement custom opcode handling if needed
}