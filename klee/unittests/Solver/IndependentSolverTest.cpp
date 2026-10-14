#include <klee/Constraints.h>
#include <klee/Expr.h>
#include <klee/Solver.h>
#include <klee/SolverImpl.h>
#include <llvm/Support/raw_ostream.h>
#include "gtest/gtest.h"

namespace klee {
llvm::raw_ostream *klee_message_stream = &llvm::errs();
}

using namespace klee;

TEST(IndependentSolverTest, KeepsTransitiveDependenciesAndDropsDisconnectedInput) {
    auto a = ReadExpr::createTempRead(Array::create("a", 1), Expr::Int8);
    auto b = ReadExpr::createTempRead(Array::create("b", 1), Expr::Int8);
    auto c = ReadExpr::createTempRead(Array::create("c", 1), Expr::Int8);
    auto noise = ReadExpr::createTempRead(Array::create("noise", 1), Expr::Int8);
    ConstraintManager constraints;
    constraints.addConstraint(EqExpr::create(a, b));
    constraints.addConstraint(EqExpr::create(b, c));
    constraints.addConstraint(UleExpr::create(c, ConstantExpr::create(10, Expr::Int8)));
    constraints.addConstraint(UleExpr::create(noise, ConstantExpr::create(30, Expr::Int8)));
    Query query(constraints, UleExpr::create(a, ConstantExpr::create(10, Expr::Int8)));
    std::vector<ref<Expr>> required;
    getIndependentConstraintsForQuery(query, required);
    EXPECT_EQ(required.size(), 3u);
    EXPECT_EQ(constraints.size(), 4u);
    auto full = Z3Solver::createResetSolver();
    SolverPtr backend = Z3Solver::createResetSolver();
    auto sliced = createIndependentSolver(backend);
    bool expected = false, actual = false;
    ASSERT_TRUE(full->mustBeTrue(query, expected));
    ASSERT_TRUE(sliced->mustBeTrue(query, actual));
    EXPECT_TRUE(expected);
    EXPECT_EQ(actual, expected);
}

TEST(IndependentSolverTest, FullConcolicModelsRetainDisconnectedConstraints) {
    auto a = Array::create("model_a", 1);
    auto b = Array::create("model_b", 1);
    auto ar = ReadExpr::createTempRead(a, Expr::Int8);
    auto br = ReadExpr::createTempRead(b, Expr::Int8);
    ConstraintManager constraints;
    constraints.addConstraint(EqExpr::create(ar, ConstantExpr::create(7, Expr::Int8)));
    constraints.addConstraint(EqExpr::create(br, ConstantExpr::create(23, Expr::Int8)));
    SolverPtr backend = Z3Solver::createResetSolver();
    auto sliced = createIndependentSolver(backend);
    std::vector<std::vector<unsigned char>> values;
    ASSERT_TRUE(sliced->getInitialValues(Query(constraints, ConstantExpr::create(0, Expr::Bool)), {a, b}, values));
    ASSERT_EQ(values.size(), 2u);
    EXPECT_EQ(values[0][0], 7u);
    EXPECT_EQ(values[1][0], 23u);
}

TEST(IndependentSolverTest, SymbolicIndexRetainsAllAliasedBytes) {
    auto array = Array::create("indexed", 4);
    auto index = ReadExpr::createTempRead(Array::create("index", 4), Expr::Int32);
    auto updates = UpdateList::create(array, nullptr);
    ConstraintManager constraints;
    for (unsigned i = 0; i < 4; ++i) {
        constraints.addConstraint(UleExpr::create(ReadExpr::create(updates, ConstantExpr::create(i, Expr::Int32)),
                                                  ConstantExpr::create(10, Expr::Int8)));
    }
    constraints.addConstraint(UltExpr::create(index, ConstantExpr::create(4, Expr::Int32)));
    Query query(constraints, UleExpr::create(ReadExpr::create(updates, index), ConstantExpr::create(10, Expr::Int8)));
    std::vector<ref<Expr>> required;
    getIndependentConstraintsForQuery(query, required);
    EXPECT_EQ(required.size(), 5u);
    SolverPtr backend = Z3Solver::createResetSolver();
    auto sliced = createIndependentSolver(backend);
    auto validated = createValidatingSolver(sliced, backend);
    bool actual = false;
    ASSERT_TRUE(validated->mustBeTrue(query, actual));
    EXPECT_TRUE(actual);
}

class WrongSolver : public SolverImpl {
public:
    bool computeTruth(const Query &, bool &result) override {
        result = false;
        return true;
    }
    bool computeValidity(const Query &, Validity &result) override {
        result = Validity::Unknown;
        return true;
    }
    bool computeValue(const Query &, ref<Expr> &) override {
        return false;
    }
    bool computeInitialValues(const Query &, const ArrayVec &, std::vector<std::vector<unsigned char>> &,
                              bool &) override {
        return false;
    }
};

TEST(ValidatingSolverDeathTest, DisagreementIsNeverResolvedByVoting) {
    auto input = ReadExpr::createTempRead(Array::create("validation", 1), Expr::Int8);
    auto condition = UleExpr::create(input, ConstantExpr::create(10, Expr::Int8));
    ConstraintManager constraints;
    constraints.addConstraint(condition);
    Query query(constraints, condition);
    SolverPtr wrong = Solver::create(std::make_shared<WrongSolver>());
    SolverPtr full = Z3Solver::createResetSolver();
    auto validated = createValidatingSolver(wrong, full);
    bool truth;
    Validity validity;
    EXPECT_DEATH(validated->impl->computeTruth(query, truth), "invalid solver result");
    EXPECT_DEATH(validated->impl->computeValidity(query, validity), "invalid solver result");
}
