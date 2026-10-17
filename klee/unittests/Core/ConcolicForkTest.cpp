#include <klee/Common.h>
#include <klee/ConcolicSlice.h>
#include <klee/Executor.h>
#include <klee/Internal/Module/KModule.h>
#include <llvm/IR/IRBuilder.h>
#include "gtest/gtest.h"

using namespace klee;
namespace {
class SlicingState : public ExecutionState {
public:
    unsigned attempts = 0;
    bool sliced = false;
    bool fail = false;
    unsigned concretizations = 0;
    bool constrained = false;
    void onConcretization(const ref<Expr> &, const ref<ConstantExpr> &, const std::string &, bool added) override {
        ++concretizations; constrained = added;
    }
    SlicingState(KFunction *function) : ExecutionState(function) {}
    bool solveWithConditions(const ConstraintManager &mgr, const std::vector<ref<Expr>> &added,
                             Assignment &assignment) override {
        ++attempts;
        if (fail) return false;
        ConcolicSliceStats stats;
        std::vector<std::vector<unsigned char>> values;
        sliced = tryConcolicSlice(*solver(), mgr, added, symbolics, *concolics, values, stats);
        if (stats.unsat) return false;
        if (!sliced) return ExecutionState::solveWithConditions(mgr, added, assignment);
        assignment.clear();
        for (size_t i = 0; i < symbolics.size(); ++i) assignment.add(symbolics[i], values[i]);
        return true;
    }
};
class TestExecutor : public Executor {
    void notifyBranch(ExecutionState &) override {}
public:
    TestExecutor(llvm::LLVMContext &context) : Executor(context) {}
};
class ConcolicForkTest : public ::testing::Test {
protected:
    llvm::LLVMContext context;
    llvm::Module module{"fork-test", context};
    std::unique_ptr<KFunction> function;
    ArrayPtr input = Array::create("fork_input", 1), noise = Array::create("fork_noise", 1);
    ref<Expr> branch;
    std::unique_ptr<SlicingState> state;
    void SetUp() override {
        klee_message_stream = &llvm::errs();
        klee_warning_stream = &llvm::errs();
        auto type = llvm::FunctionType::get(llvm::Type::getVoidTy(context), false);
        auto fn = llvm::Function::Create(type, llvm::GlobalValue::ExternalLinkage, "entry", module);
        llvm::IRBuilder<> builder(llvm::BasicBlock::Create(context, "entry", fn));
        builder.CreateRetVoid();
        function.reset(new KFunction(fn, nullptr));
        state.reset(new SlicingState(function.get()));
        SolverPtr solver = Z3Solver::createResetSolver();
        state->setSolver(solver);
        state->symbolics = {input, noise};
        state->concolics->add(input, {0});
        state->concolics->add(noise, {37});
        auto read = ReadExpr::create(UpdateList::create(input, nullptr), ConstantExpr::create(0, Expr::Int32));
        branch = EqExpr::create(read, ConstantExpr::create(7, Expr::Int8));
    }
};
TEST_F(ConcolicForkTest, OrdinaryForkUsesAddedPredicateAndPreservesNoise) {
    TestExecutor executor(context);
    auto pair = executor.fork(*state, branch);
    ASSERT_NE(pair.first, nullptr);
    ASSERT_EQ(pair.second, state.get());
    EXPECT_EQ(state->attempts, 1u);
    EXPECT_TRUE(state->sliced);
    EXPECT_EQ(pair.first->concolics->bindings.at(input)[0], 7);
    EXPECT_EQ(pair.first->concolics->bindings.at(noise)[0], 37);
    EXPECT_EQ(state->concolics->bindings.at(input)[0], 0);
    EXPECT_EQ(pair.first->symbolicForkDepth, 1u);
    EXPECT_EQ(state->symbolicForkDepth, 1u);
    delete pair.first;
}
TEST_F(ConcolicForkTest, ForcedRecomputeUsesAliasSafeSlice) {
    ASSERT_TRUE(state->addConstraint(branch, true));
    EXPECT_EQ(state->attempts, 1u);
    EXPECT_TRUE(state->sliced);
    EXPECT_EQ(state->concolics->bindings.at(input)[0], 7);
    EXPECT_EQ(state->concolics->bindings.at(noise)[0], 37);
    EXPECT_TRUE(state->concolics->evaluate(branch)->isTrue());
}
TEST_F(ConcolicForkTest, KeepTrueRecomputesBothOutcomes) {
    TestExecutor executor(context);
    auto pair = executor.fork(*state, branch, true);
    ASSERT_EQ(pair.first, state.get());
    ASSERT_NE(pair.second, nullptr);
    EXPECT_EQ(state->attempts, 2u);
    EXPECT_TRUE(pair.first->concolics->evaluate(branch)->isTrue());
    EXPECT_TRUE(pair.second->concolics->evaluate(branch)->isFalse());
    EXPECT_EQ(pair.second->concolics->bindings.at(noise)[0], 37);
    delete pair.second;
}
TEST_F(ConcolicForkTest, FailedForkKeepsOriginalPathAndSeed) {
    state->fail = true;
    TestExecutor executor(context);
    auto pair = executor.fork(*state, branch);
    EXPECT_EQ(pair.first, nullptr);
    EXPECT_EQ(pair.second, state.get());
    EXPECT_EQ(state->attempts, 1u);
    EXPECT_EQ(state->constraints().size(), 0u);
    EXPECT_EQ(state->concolics->bindings.at(input)[0], 0);
}
TEST_F(ConcolicForkTest, FullyConnectedInputsFallBackToFullModel) {
    auto left = ReadExpr::create(UpdateList::create(input, nullptr), ConstantExpr::create(0, Expr::Int32));
    auto right = ReadExpr::create(UpdateList::create(noise, nullptr), ConstantExpr::create(0, Expr::Int32));
    auto linked = EqExpr::create(left, right);
    // The existing seed must satisfy the original path before forcing a branch.
    state->concolics->clear();
    state->concolics->add(input, {0});
    state->concolics->add(noise, {0});
    ASSERT_TRUE(state->addConstraint(linked));
    ASSERT_TRUE(state->addConstraint(branch, true));
    EXPECT_EQ(state->attempts, 1u);
    EXPECT_FALSE(state->sliced);
    EXPECT_EQ(state->concolics->bindings.at(input)[0], 7);
    EXPECT_EQ(state->concolics->bindings.at(noise)[0], 7);
}
TEST_F(ConcolicForkTest, FailedForcedRecomputeDoesNotChangeSeedOrPath) {
    state->fail = true;
    EXPECT_FALSE(state->addConstraint(branch, true));
    EXPECT_EQ(state->attempts, 1u);
    EXPECT_EQ(state->constraints().size(), 0u);
    EXPECT_EQ(state->concolics->bindings.at(input)[0], 0);
    EXPECT_EQ(state->concolics->bindings.at(noise)[0], 37);
}
TEST_F(ConcolicForkTest, DisabledForkAvoidsModelSolving) {
    state->forkDisabled = true;
    TestExecutor executor(context);
    auto pair = executor.fork(*state, branch);
    EXPECT_EQ(pair.first, nullptr);
    EXPECT_EQ(pair.second, state.get());
    EXPECT_EQ(state->attempts, 0u);
}
} // namespace

TEST_F(ConcolicForkTest, SilentConcretizationNotifiesWithoutAddingConstraints) {
    auto before = state->constraints().size();
    EXPECT_TRUE(state->toConstantSilent(branch)->isFalse());
    EXPECT_EQ(state->concretizations, 1u);
    EXPECT_FALSE(state->constrained);
    EXPECT_EQ(state->constraints().size(), before);
}
TEST_F(ConcolicForkTest, ConstrainingConcretizationNotifiesAfterAddingEquality) {
    EXPECT_TRUE(state->toConstant(branch, "audit test")->isFalse());
    EXPECT_EQ(state->concretizations, 1u);
    EXPECT_TRUE(state->constrained);
    bool impossible = false;
    ASSERT_TRUE(state->solver()->mustBeFalse(Query(state->constraints(), branch), impossible));
    EXPECT_TRUE(impossible);
}
TEST_F(ConcolicForkTest, ConcreteValuesDoNotNotifyConcretization) {
    state->toConstantSilent(ConstantExpr::create(9, Expr::Int8));
    state->toConstant(ConstantExpr::create(9, Expr::Int8), "already concrete");
    EXPECT_EQ(state->concretizations, 0u);
}
