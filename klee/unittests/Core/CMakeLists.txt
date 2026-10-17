add_klee_unit_test(CoreTest AddressSpaceTest.cpp)

target_link_libraries(CoreTest PRIVATE kleeCore kleaverExpr kleeSupport)

if(ENABLE_SOLVER_Z3)
  add_klee_unit_test(ConcolicForkTest ConcolicForkTest.cpp)
  llvm_map_components_to_libnames(FORK_LLVM_LIBS core support bitreader bitwriter irreader
    ipo scalaropts instcombine transformutils analysis target executionengine mcjit native)
  target_link_libraries(ConcolicForkTest PRIVATE kleeCore kleeModule kleaverSolver
    kleaverExpr kleeSupport kleeBasic ${FORK_LLVM_LIBS} gomp)
endif()
