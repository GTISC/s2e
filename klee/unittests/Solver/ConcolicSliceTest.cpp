#include <klee/ConcolicSlice.h>
#include <klee/SolverImpl.h>
#include "gtest/gtest.h"

using namespace klee;

namespace {
ref<Expr> byte(const ArrayPtr &array, unsigned offset = 0) {
    return ReadExpr::create(UpdateList::create(array, nullptr), ConstantExpr::create(offset, Expr::Int32));
}
ref<Expr> number(unsigned n) { return ConstantExpr::create(n, Expr::Int8); }
class RecordingSolver : public SolverImpl {
public:
    SolverPtr real = Z3Solver::createResetSolver();
    unsigned calls = 0, arrays = 0, constraints = 0;
    bool fail = false, corrupt = false;
    bool computeTruth(const Query &, bool &) override { return false; }
    bool computeValidity(const Query &, Validity &) override { return false; }
    bool computeValue(const Query &, ref<Expr> &) override { return false; }
    bool computeInitialValues(const Query &query, const ArrayVec &objects,
                              std::vector<std::vector<unsigned char>> &values, bool &hasSolution) override {
        ++calls; arrays = objects.size(); constraints = query.constraints.size();
        if (fail) return false;
        bool ok = real->impl->computeInitialValues(query, objects, values, hasSolution);
        if (ok && hasSolution && corrupt) values[0][0] ^= 0xff;
        return ok;
    }
};
}

TEST(ConcolicSliceTest, TransitiveModelKeepsDisconnectedSeedAndEveryConstraint) {
    auto a=Array::create("slice_a",1), b=Array::create("slice_b",1), c=Array::create("slice_c",1);
    auto noise=Array::create("slice_noise",1);
    ArrayVec objects={a,b,c,noise};
    auto seed=Assignment::create(true);
    seed->add(a,{0});seed->add(b,{0});seed->add(c,{1});seed->add(noise,{23});
    ConstraintManager constraints;
    constraints.addConstraint(EqExpr::create(byte(a),byte(b)));
    constraints.addConstraint(EqExpr::create(byte(b),byte(c)));
    constraints.addConstraint(UleExpr::create(number(20),byte(noise)));
    auto branch=EqExpr::create(byte(a),number(7));constraints.addConstraint(branch);
    auto backend=std::make_shared<RecordingSolver>();auto solver=Solver::create(backend);
    std::vector<std::vector<unsigned char>> values;ConcolicSliceStats stats;
    ASSERT_TRUE(tryConcolicSlice(*solver,constraints,{branch},objects,*seed,values,stats));
    ASSERT_EQ(values.size(),4u);EXPECT_EQ(values[0][0],7);EXPECT_EQ(values[1][0],7);
    EXPECT_EQ(values[2][0],7);EXPECT_EQ(values[3][0],23);
    EXPECT_EQ(backend->arrays,3u);EXPECT_EQ(stats.seedBytes,1u);
    EXPECT_EQ(seed->bindings.at(a)[0],0);EXPECT_EQ(constraints.size(),4u);
}

TEST(ConcolicSliceTest, ConnectedInputsAreNeverFrozenOrDropped) {
    auto a=Array::create("linked_a",1), b=Array::create("linked_b",1);
    ArrayVec objects={a,b};auto seed=Assignment::create(true);seed->add(a,{0});seed->add(b,{0});
    ConstraintManager constraints;constraints.addConstraint(EqExpr::create(byte(a),byte(b)));
    auto branch=EqExpr::create(byte(a),number(9));constraints.addConstraint(branch);
    auto backend=std::make_shared<RecordingSolver>();auto solver=Solver::create(backend);
    std::vector<std::vector<unsigned char>> values;ConcolicSliceStats stats;
    EXPECT_FALSE(tryConcolicSlice(*solver,constraints,{branch},objects,*seed,values,stats));
    EXPECT_STREQ(stats.reason,"fully_connected");EXPECT_EQ(backend->calls,0u);
}

TEST(ConcolicSliceTest, SymbolicIndicesKeepTheWholeArrayAndIndexDependencies) {
    auto data=Array::create("indexed_data",4), index=Array::create("dynamic_index",1), noise=Array::create("index_noise",1);
    ArrayVec objects={data,index,noise};auto seed=Assignment::create(true);
    seed->add(data,{0,0,0,0});seed->add(index,{0});seed->add(noise,{33});
    ConstraintManager constraints;
    constraints.addConstraint(UltExpr::create(byte(index),number(4)));
    for(unsigned i=0;i<4;++i) constraints.addConstraint(UleExpr::create(byte(data,i),number(10)));
    auto branch=EqExpr::create(ReadExpr::create(UpdateList::create(data,nullptr),
                                  ZExtExpr::create(byte(index),Expr::Int32)),number(9));
    constraints.addConstraint(branch);
    auto backend=std::make_shared<RecordingSolver>();auto solver=Solver::create(backend);
    std::vector<std::vector<unsigned char>> values;ConcolicSliceStats stats;
    ASSERT_TRUE(tryConcolicSlice(*solver,constraints,{branch},objects,*seed,values,stats));
    EXPECT_EQ(backend->arrays,2u);EXPECT_EQ(values[0][values[1][0]],9);EXPECT_EQ(values[2][0],33);
}

TEST(ConcolicSliceTest, InvalidOrMissingDisconnectedSeedsRequireFullSolve) {
    auto a=Array::create("check_a",1), noise=Array::create("check_noise",1);ArrayVec objects={a,noise};
    auto seed=Assignment::create(true);seed->add(a,{0});
    ConstraintManager constraints;constraints.addConstraint(UleExpr::create(number(20),byte(noise)));
    auto branch=EqExpr::create(byte(a),number(7));constraints.addConstraint(branch);
    auto backend=std::make_shared<RecordingSolver>();auto solver=Solver::create(backend);
    std::vector<std::vector<unsigned char>> values;ConcolicSliceStats stats;
    EXPECT_FALSE(tryConcolicSlice(*solver,constraints,{branch},objects,*seed,values,stats));
    EXPECT_STREQ(stats.reason,"incomplete_seed");seed->add(noise,{1});
    EXPECT_FALSE(tryConcolicSlice(*solver,constraints,{branch},objects,*seed,values,stats));
    EXPECT_STREQ(stats.reason,"full_constraint_validation_failed");EXPECT_TRUE(values.empty());
}

TEST(ConcolicSliceTest, SolverFailureOrBadModelCannotProduceATrigger) {
    auto a=Array::create("failure_a",1), noise=Array::create("failure_noise",1);ArrayVec objects={a,noise};
    auto seed=Assignment::create(true);seed->add(a,{0});seed->add(noise,{33});
    ConstraintManager constraints;auto branch=EqExpr::create(byte(a),number(7));constraints.addConstraint(branch);
    auto backend=std::make_shared<RecordingSolver>();auto solver=Solver::create(backend);
    std::vector<std::vector<unsigned char>> values;ConcolicSliceStats stats;backend->fail=true;
    EXPECT_FALSE(tryConcolicSlice(*solver,constraints,{branch},objects,*seed,values,stats));
    backend->fail=false;backend->corrupt=true;
    EXPECT_FALSE(tryConcolicSlice(*solver,constraints,{branch},objects,*seed,values,stats));EXPECT_TRUE(values.empty());
}
