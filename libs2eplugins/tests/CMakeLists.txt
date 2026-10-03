cmake_minimum_required(VERSION 3.13)
project(ManagedRuntimeTests LANGUAGES C CXX)

# Standalone protocol tests: no VM, LLVM build, or installed S2E is required.
enable_testing()
foreach(test ManagedBindings ManagedBooleanSource)
    add_executable(${test}Test ${test}Test.cpp)
    target_compile_features(${test}Test PRIVATE cxx_std_14)
    target_include_directories(${test}Test PRIVATE ../../guest/common/include)
    target_compile_options(${test}Test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME ${test} COMMAND ${test}Test)
endforeach()

add_executable(ManagedProtocolTest ManagedProtocolTest.c)
target_include_directories(ManagedProtocolTest PRIVATE ../../guest/common/include)
target_compile_options(ManagedProtocolTest PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME ManagedProtocol COMMAND ManagedProtocolTest)
