cmake_minimum_required(VERSION 3.10)
project(HopperLangCompiler)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# LLVM finden
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_executable(hplc compiler.cpp)

# LLVM Bibliotheken linken
llvm_map_components_to_libnames(llvm_libs support core irreader)
target_link_libraries(hplc ${llvm_libs})
