# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)
project(universal_setup C CXX)

option(USK_BUILD_APPS "Build Universal Setup app frontends" ON)
option(USK_BUILD_TESTS "Build Universal Setup native tests" ON)
option(USK_BUILD_FUZZERS "Build bounded libFuzzer targets" OFF)

add_library(usk_headers INTERFACE)
target_include_directories(usk_headers INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_library(usk_base_static STATIC
  runtime/base/usk_json.cpp
  runtime/base/usk_record_io.cpp
  runtime/base/usk_sha256.cpp
  runtime/base/usk_stable_file.cpp
)
target_compile_features(usk_base_static PUBLIC cxx_std_17)
target_include_directories(usk_base_static PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/runtime/base")
set_target_properties(usk_base_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(usk_verify_static STATIC runtime/setup/verify/usk_package_verify.cpp)
target_compile_features(usk_verify_static PUBLIC cxx_std_17)
target_include_directories(usk_verify_static PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/verify"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_link_libraries(usk_verify_static PUBLIC usk_base_static)
set_target_properties(usk_verify_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(usk_archive_static STATIC runtime/setup/package/usk_archive_inspect.cpp)
target_compile_features(usk_archive_static PUBLIC cxx_std_17)
target_include_directories(usk_archive_static PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/package"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_link_libraries(usk_archive_static PUBLIC usk_base_static)
set_target_properties(usk_archive_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(usk_policy_static STATIC
  runtime/setup/policy/usk_target_inspect.cpp
  runtime/setup/policy/usk_target_policy.cpp
)
target_compile_features(usk_policy_static PUBLIC cxx_std_17)
target_include_directories(usk_policy_static PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/policy"
)
target_link_libraries(usk_policy_static PUBLIC usk_base_static)
set_target_properties(usk_policy_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(usk_transaction_static STATIC
  runtime/setup/transaction/usk_transaction_session.cpp
)
target_compile_features(usk_transaction_static PUBLIC cxx_std_17)
target_include_directories(usk_transaction_static PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/transaction"
)
target_link_libraries(usk_transaction_static PUBLIC usk_base_static)
set_target_properties(usk_transaction_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(usk_state_static STATIC
  runtime/setup/audit/usk_audit_repository.cpp
  runtime/setup/evidence/usk_live_evidence.cpp
  runtime/setup/state/usk_state_repository.cpp
)
target_compile_features(usk_state_static PUBLIC cxx_std_17)
target_include_directories(usk_state_static PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/audit"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/evidence"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/state"
)
target_link_libraries(usk_state_static PUBLIC usk_base_static)
set_target_properties(usk_state_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(usk_lifecycle_static STATIC
  runtime/setup/lifecycle/usk_lifecycle.cpp
  runtime/setup/lifecycle/usk_public_lifecycle.cpp
)
target_compile_features(usk_lifecycle_static PUBLIC cxx_std_17)
target_include_directories(usk_lifecycle_static PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/lifecycle"
)
target_link_libraries(usk_lifecycle_static PUBLIC
  usk_archive_static
  usk_base_static
  usk_policy_static
  usk_state_static
  usk_transaction_static
)
set_target_properties(usk_lifecycle_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(usk_static STATIC runtime/setup/kernel/usk_api.c)
target_include_directories(usk_static PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(usk_static PUBLIC usk_verify_static usk_archive_static usk_lifecycle_static)

add_library(usk_shared SHARED runtime/setup/kernel/usk_api.c)
target_include_directories(usk_shared PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_definitions(usk_shared PRIVATE USK_BUILD_SHARED)
target_link_libraries(usk_shared PRIVATE usk_verify_static usk_archive_static usk_lifecycle_static)
set_target_properties(usk_shared PROPERTIES OUTPUT_NAME usk WINDOWS_EXPORT_ALL_SYMBOLS ON)

add_library(usk ALIAS usk_static)

if(USK_BUILD_TESTS)
  enable_testing()
  add_executable(usk_sha256_smoke tests/native/usk_sha256_smoke.cpp)
  target_compile_features(usk_sha256_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_sha256_smoke PRIVATE usk_base_static)
  add_test(NAME usk_sha256_smoke COMMAND usk_sha256_smoke)

  add_executable(usk_json_smoke tests/native/usk_json_smoke.cpp)
  target_compile_features(usk_json_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_json_smoke PRIVATE usk_base_static)
  add_test(NAME usk_json_smoke COMMAND usk_json_smoke)

  add_executable(usk_stable_file_smoke tests/native/usk_stable_file_smoke.cpp)
  target_compile_features(usk_stable_file_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_stable_file_smoke PRIVATE usk_base_static)
  add_test(NAME usk_stable_file_smoke COMMAND usk_stable_file_smoke)

  add_executable(usk_archive_inspect_smoke tests/native/usk_archive_inspect_smoke.cpp)
  target_compile_features(usk_archive_inspect_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_archive_inspect_smoke PRIVATE usk_static)
  add_test(NAME usk_archive_inspect_smoke COMMAND usk_archive_inspect_smoke)

  add_executable(usk_target_policy_smoke tests/native/usk_target_policy_smoke.cpp)
  target_compile_features(usk_target_policy_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_target_policy_smoke PRIVATE usk_policy_static)
  add_test(NAME usk_target_policy_smoke COMMAND usk_target_policy_smoke)

  add_executable(usk_target_inspect_smoke tests/native/usk_target_inspect_smoke.cpp)
  target_compile_features(usk_target_inspect_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_target_inspect_smoke PRIVATE usk_policy_static)
  add_test(NAME usk_target_inspect_smoke COMMAND usk_target_inspect_smoke)

  add_executable(usk_transaction_session_smoke tests/native/usk_transaction_session_smoke.cpp)
  target_compile_features(usk_transaction_session_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_transaction_session_smoke PRIVATE usk_transaction_static)
  add_test(NAME usk_transaction_session_smoke COMMAND usk_transaction_session_smoke)

  add_executable(usk_state_repository_smoke tests/native/usk_state_repository_smoke.cpp)
  target_compile_features(usk_state_repository_smoke PRIVATE cxx_std_17)
  target_compile_definitions(usk_state_repository_smoke PRIVATE
    USK_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
  )
  target_link_libraries(usk_state_repository_smoke PRIVATE usk_state_static)
  add_test(NAME usk_state_repository_smoke COMMAND usk_state_repository_smoke)

  add_executable(usk_live_evidence_smoke tests/native/usk_live_evidence_smoke.cpp)
  target_compile_features(usk_live_evidence_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_live_evidence_smoke PRIVATE usk_state_static usk_base_static)
  add_test(NAME usk_live_evidence_smoke COMMAND usk_live_evidence_smoke)

  add_executable(usk_lifecycle_smoke tests/native/usk_lifecycle_smoke.cpp)
  target_compile_features(usk_lifecycle_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_lifecycle_smoke PRIVATE usk_lifecycle_static)
  add_test(NAME usk_lifecycle_smoke COMMAND usk_lifecycle_smoke)

  add_executable(usk_public_lifecycle_smoke tests/native/usk_public_lifecycle_smoke.cpp)
  target_compile_features(usk_public_lifecycle_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_public_lifecycle_smoke PRIVATE usk_static usk_base_static)
  add_test(NAME usk_public_lifecycle_smoke COMMAND usk_public_lifecycle_smoke)

  add_executable(usk_adversarial_lifecycle_smoke tests/native/usk_adversarial_lifecycle_smoke.cpp)
  target_compile_features(usk_adversarial_lifecycle_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_adversarial_lifecycle_smoke PRIVATE usk_lifecycle_static)
  add_test(NAME usk_adversarial_lifecycle_smoke COMMAND usk_adversarial_lifecycle_smoke)

  add_executable(usk_command_graph_smoke tests/native/usk_command_graph_smoke.c)
  target_link_libraries(usk_command_graph_smoke PRIVATE usk_static)
  add_test(NAME usk_command_graph_smoke COMMAND usk_command_graph_smoke)

  add_executable(usk_package_verify_smoke tests/native/usk_package_verify_smoke.cpp)
  target_compile_features(usk_package_verify_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_package_verify_smoke PRIVATE usk_static usk_verify_static)
  add_test(NAME usk_package_verify_smoke COMMAND usk_package_verify_smoke)
endif()

if(USK_BUILD_FUZZERS)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "USK_BUILD_FUZZERS requires Clang libFuzzer support")
  endif()
  target_compile_options(usk_base_static PRIVATE -fsanitize=fuzzer-no-link,address,undefined)
  add_executable(usk_json_fuzz tests/fuzz/usk_json_fuzz.cpp)
  target_compile_features(usk_json_fuzz PRIVATE cxx_std_17)
  target_compile_options(usk_json_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_options(usk_json_fuzz PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_libraries(usk_json_fuzz PRIVATE usk_base_static)
endif()
