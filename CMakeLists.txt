cmake_minimum_required(VERSION 3.16)
project(universal_setup C CXX)

option(USK_BUILD_APPS "Build Universal Setup app frontends" ON)
option(USK_BUILD_TESTS "Build Universal Setup native tests" ON)

add_library(usk_headers INTERFACE)
target_include_directories(usk_headers INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_library(usk_verify_static STATIC runtime/setup/verify/usk_package_verify.cpp)
target_compile_features(usk_verify_static PUBLIC cxx_std_17)
target_include_directories(usk_verify_static PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/verify"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
set_target_properties(usk_verify_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(usk_static STATIC runtime/setup/kernel/usk_api.c)
target_include_directories(usk_static PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(usk_static PUBLIC usk_verify_static)

add_library(usk_shared SHARED runtime/setup/kernel/usk_api.c)
target_include_directories(usk_shared PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_definitions(usk_shared PRIVATE USK_BUILD_SHARED)
target_link_libraries(usk_shared PRIVATE usk_verify_static)
set_target_properties(usk_shared PROPERTIES OUTPUT_NAME usk WINDOWS_EXPORT_ALL_SYMBOLS ON)

add_library(usk ALIAS usk_static)

if(USK_BUILD_TESTS)
  enable_testing()
  add_executable(usk_command_graph_smoke tests/native/usk_command_graph_smoke.c)
  target_link_libraries(usk_command_graph_smoke PRIVATE usk_static)
  add_test(NAME usk_command_graph_smoke COMMAND usk_command_graph_smoke)

  add_executable(usk_package_verify_smoke tests/native/usk_package_verify_smoke.cpp)
  target_compile_features(usk_package_verify_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_package_verify_smoke PRIVATE usk_static usk_verify_static)
  add_test(NAME usk_package_verify_smoke COMMAND usk_package_verify_smoke)
endif()
