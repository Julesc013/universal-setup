# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.21)
project(universal_setup VERSION 1.0.0 LANGUAGES C CXX)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
find_package(Git QUIET)
find_package(Python3 COMPONENTS Interpreter REQUIRED)

option(USK_BUILD_APPS "Build Universal Setup app frontends" "${PROJECT_IS_TOP_LEVEL}")
option(USK_BUILD_TESTS "Build Universal Setup native tests" "${PROJECT_IS_TOP_LEVEL}")
option(USK_BUILD_FUZZERS "Build bounded libFuzzer targets" OFF)
option(USK_BUILD_STATIC "Build the Universal Setup static library" ON)
option(USK_BUILD_SHARED "Build the Universal Setup shared library" ON)

if(NOT USK_BUILD_STATIC AND NOT USK_BUILD_SHARED)
  message(FATAL_ERROR "At least one of USK_BUILD_STATIC or USK_BUILD_SHARED must be enabled")
endif()
if((USK_BUILD_APPS OR USK_BUILD_TESTS) AND NOT USK_BUILD_STATIC)
  message(FATAL_ERROR "USK_BUILD_APPS and USK_BUILD_TESTS require the static library")
endif()

function(usk_enable_strict_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endfunction()

add_library(usk_headers INTERFACE)
set_target_properties(usk_headers PROPERTIES EXPORT_NAME Headers)
target_include_directories(
  usk_headers
  INTERFACE
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)
add_library(UniversalSetup::Headers ALIAS usk_headers)

add_library(usk_base_static STATIC
  runtime/base/usk_json.cpp
  runtime/base/usk_record_io.cpp
  runtime/base/usk_sha256.cpp
  runtime/base/usk_stable_file.cpp
  runtime/base/usk_utf8_path.cpp
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

if(NOT USK_BUILD_APPS AND NOT USK_BUILD_TESTS AND NOT USK_BUILD_FUZZERS)
  foreach(USK_INTERNAL_TARGET IN ITEMS
      usk_base_static
      usk_verify_static
      usk_archive_static
      usk_policy_static
      usk_transaction_static
      usk_state_static
      usk_lifecycle_static)
    set_target_properties(${USK_INTERNAL_TARGET} PROPERTIES EXCLUDE_FROM_ALL ON)
  endforeach()
endif()

set(USK_CORE_SOURCES
  runtime/base/usk_json.cpp
  runtime/base/usk_record_io.cpp
  runtime/base/usk_sha256.cpp
  runtime/base/usk_stable_file.cpp
  runtime/base/usk_utf8_path.cpp
  runtime/setup/audit/usk_audit_repository.cpp
  runtime/setup/evidence/usk_live_evidence.cpp
  runtime/setup/kernel/usk_api.c
  runtime/setup/lifecycle/usk_lifecycle.cpp
  runtime/setup/lifecycle/usk_public_lifecycle.cpp
  runtime/setup/package/usk_archive_inspect.cpp
  runtime/setup/policy/usk_target_inspect.cpp
  runtime/setup/policy/usk_target_policy.cpp
  runtime/setup/state/usk_state_repository.cpp
  runtime/setup/transaction/usk_transaction_session.cpp
  runtime/setup/verify/usk_package_verify.cpp
)
set(USK_PRIVATE_INCLUDE_DIRS
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/base"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/audit"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/evidence"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/lifecycle"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/package"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/policy"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/state"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/transaction"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/verify"
)

set(USK_INSTALL_TARGETS usk_headers)

if(USK_BUILD_STATIC)
  add_library(usk_static STATIC ${USK_CORE_SOURCES})
  set_target_properties(usk_static PROPERTIES
    EXPORT_NAME CoreStatic
    POSITION_INDEPENDENT_CODE ON
  )
  target_compile_features(usk_static PRIVATE cxx_std_17)
  target_include_directories(usk_static PRIVATE ${USK_PRIVATE_INCLUDE_DIRS})
  target_link_libraries(usk_static PUBLIC usk_headers)
  usk_enable_strict_warnings(usk_static)
  add_library(UniversalSetup::CoreStatic ALIAS usk_static)
  add_library(usk ALIAS usk_static)
  list(APPEND USK_INSTALL_TARGETS usk_static)
endif()

if(USK_BUILD_SHARED)
  add_library(usk_shared SHARED ${USK_CORE_SOURCES})
  set_target_properties(usk_shared PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    EXPORT_NAME CoreShared
    OUTPUT_NAME usk
    VISIBILITY_INLINES_HIDDEN YES
  )
  target_compile_features(usk_shared PRIVATE cxx_std_17)
  target_include_directories(usk_shared PRIVATE ${USK_PRIVATE_INCLUDE_DIRS})
  target_link_libraries(usk_shared PUBLIC usk_headers)
  target_compile_definitions(usk_shared PRIVATE USK_BUILD_SHARED INTERFACE USK_USE_SHARED)
  usk_enable_strict_warnings(usk_shared)
  add_library(UniversalSetup::CoreShared ALIAS usk_shared)
  list(APPEND USK_INSTALL_TARGETS usk_shared)
endif()

set(USK_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/UniversalSetup")
set(USK_INSTALL_CONTRACTS_DIR "${CMAKE_INSTALL_DATADIR}/universal-setup/contracts/schema")
set(USK_INSTALL_ABI_MANIFEST "${CMAKE_INSTALL_DATADIR}/universal-setup/contracts/abi/usk_c_abi.v1.toml")
set(USK_INSTALL_PROVIDER_MANIFEST "${CMAKE_INSTALL_DATADIR}/universal-setup/provider-package-manifest.v1.json")
set(USK_SOURCE_REPOSITORY "Julesc013/universal-setup" CACHE STRING "Provider source repository identity")
set(USK_SOURCE_COMMIT "" CACHE STRING "Exact 40-hex source commit for package identity")
set(USK_SOURCE_TREE "" CACHE STRING "Exact 40-hex source tree for package identity")
set(USK_SOURCE_REF "" CACHE STRING "Source ref recorded in the provider package manifest")
option(
  USK_ALLOW_UNVERIFIABLE_ARCHIVE_SOURCE
  "Allow explicitly supplied source identity when the source tree has no Git metadata"
  OFF
)

if(Git_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
  if(NOT USK_SOURCE_COMMIT)
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" -C "${CMAKE_CURRENT_SOURCE_DIR}" rev-parse HEAD
      OUTPUT_VARIABLE USK_SOURCE_COMMIT
      OUTPUT_STRIP_TRAILING_WHITESPACE
      COMMAND_ERROR_IS_FATAL ANY
    )
  endif()
  if(NOT USK_SOURCE_TREE)
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" -C "${CMAKE_CURRENT_SOURCE_DIR}" rev-parse "HEAD^{tree}"
      OUTPUT_VARIABLE USK_SOURCE_TREE
      OUTPUT_STRIP_TRAILING_WHITESPACE
      COMMAND_ERROR_IS_FATAL ANY
    )
  endif()
  if(NOT USK_SOURCE_REF)
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" -C "${CMAKE_CURRENT_SOURCE_DIR}" symbolic-ref --quiet HEAD
      OUTPUT_VARIABLE USK_SOURCE_REF
      OUTPUT_STRIP_TRAILING_WHITESPACE
      RESULT_VARIABLE USK_SOURCE_REF_RESULT
    )
    if(NOT USK_SOURCE_REF_RESULT EQUAL 0)
      set(USK_SOURCE_REF "refs/detached/${USK_SOURCE_COMMIT}")
    endif()
  endif()
endif()

string(LENGTH "${USK_SOURCE_COMMIT}" USK_SOURCE_COMMIT_LENGTH)
if(NOT USK_SOURCE_COMMIT_LENGTH EQUAL 40 OR NOT USK_SOURCE_COMMIT MATCHES "^[0-9a-f]+$")
  message(FATAL_ERROR "USK_SOURCE_COMMIT must be an exact 40-hex source commit")
endif()
string(LENGTH "${USK_SOURCE_TREE}" USK_SOURCE_TREE_LENGTH)
if(NOT USK_SOURCE_TREE_LENGTH EQUAL 40 OR NOT USK_SOURCE_TREE MATCHES "^[0-9a-f]+$")
  message(FATAL_ERROR "USK_SOURCE_TREE must be an exact 40-hex source tree")
endif()
if(NOT USK_SOURCE_REF MATCHES "^refs/")
  message(FATAL_ERROR "USK_SOURCE_REF must be a complete refs/... identity")
endif()

if(USK_BUILD_STATIC AND USK_BUILD_SHARED)
  set(USK_PROVIDER_LINKAGE "combined")
elseif(USK_BUILD_STATIC)
  set(USK_PROVIDER_LINKAGE "static")
else()
  set(USK_PROVIDER_LINKAGE "shared")
endif()
if(CMAKE_GENERATOR_PLATFORM)
  set(USK_PROVIDER_ARCHITECTURE "${CMAKE_GENERATOR_PLATFORM}")
else()
  set(USK_PROVIDER_ARCHITECTURE "${CMAKE_SYSTEM_PROCESSOR}")
endif()

configure_package_config_file(
  cmake/UniversalSetupConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/cmake-package/UniversalSetupConfig.cmake"
  INSTALL_DESTINATION "${USK_INSTALL_CMAKEDIR}"
  PATH_VARS
    USK_INSTALL_CONTRACTS_DIR
    USK_INSTALL_ABI_MANIFEST
    USK_INSTALL_PROVIDER_MANIFEST
)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/cmake-package/UniversalSetupConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY ExactVersion
)

install(
  TARGETS ${USK_INSTALL_TARGETS}
  EXPORT UniversalSetupTargets
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
install(EXPORT UniversalSetupTargets
  FILE UniversalSetupTargets.cmake
  NAMESPACE UniversalSetup::
  DESTINATION "${USK_INSTALL_CMAKEDIR}"
)
install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/cmake-package/UniversalSetupConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake-package/UniversalSetupConfigVersion.cmake"
  DESTINATION "${USK_INSTALL_CMAKEDIR}"
)
install(DIRECTORY include/usk DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(
  DIRECTORY contracts/schema/
  DESTINATION "${USK_INSTALL_CONTRACTS_DIR}"
  FILES_MATCHING PATTERN "*.json"
)
install(
  FILES contracts/abi/usk_c_abi.v1.toml
  DESTINATION "${CMAKE_INSTALL_DATADIR}/universal-setup/contracts/abi"
)
install(
  FILES LICENSE release/license.v1.toml
  DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/universal-setup"
)
install(
  FILES cmake/README-SDK.md
  DESTINATION "${CMAKE_INSTALL_DATADIR}/universal-setup"
)
configure_file(
  cmake/GenerateProviderPackageManifest.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/cmake-package/GenerateProviderPackageManifest.cmake"
  @ONLY
)
install(SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/cmake-package/GenerateProviderPackageManifest.cmake")

if(USK_BUILD_APPS)
  add_executable(usk_live_acceptance apps/cli/usk_live_acceptance.cpp)
  target_compile_features(usk_live_acceptance PRIVATE cxx_std_17)
  target_include_directories(usk_live_acceptance PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/runtime/base"
    "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/evidence"
  )
  target_link_libraries(usk_live_acceptance PRIVATE usk_static usk_base_static usk_state_static)
endif()

if(USK_BUILD_TESTS)
  enable_testing()

  add_executable(usk_abi_layout_smoke tests/native/usk_abi_layout_smoke.c)
  target_link_libraries(usk_abi_layout_smoke PRIVATE usk_headers)
  usk_enable_strict_warnings(usk_abi_layout_smoke)
  add_test(NAME usk_abi_layout_smoke COMMAND usk_abi_layout_smoke)

  foreach(USK_SDK_PHASE IN ITEMS workspace static shared combined)
    set(USK_SDK_CONFORMANCE_COMMAND
      "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/tools/cmake_sdk_conformance.py"
      --work-dir "${CMAKE_CURRENT_BINARY_DIR}/sdk-conformance/${USK_SDK_PHASE}"
      --config "$<CONFIG>"
      --phase "${USK_SDK_PHASE}"
    )
    if(CMAKE_GENERATOR_PLATFORM)
      list(APPEND USK_SDK_CONFORMANCE_COMMAND --platform "${CMAKE_GENERATOR_PLATFORM}")
    endif()
    add_test(
      NAME "usk_cmake_sdk_${USK_SDK_PHASE}"
      COMMAND ${USK_SDK_CONFORMANCE_COMMAND}
    )
    set_tests_properties(
      "usk_cmake_sdk_${USK_SDK_PHASE}"
      PROPERTIES
        ENVIRONMENT "CMAKE_GENERATOR=${CMAKE_GENERATOR}"
        TIMEOUT 900
    )
  endforeach()

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
  target_include_directories(usk_archive_inspect_smoke PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/runtime/base"
    "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/package"
  )
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

  add_executable(usk_interruption_recovery_smoke tests/native/usk_interruption_recovery_smoke.cpp)
  target_compile_features(usk_interruption_recovery_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_interruption_recovery_smoke PRIVATE usk_lifecycle_static)
  add_test(NAME usk_interruption_recovery_smoke COMMAND usk_interruption_recovery_smoke)

  add_executable(usk_public_lifecycle_smoke tests/native/usk_public_lifecycle_smoke.cpp)
  target_compile_features(usk_public_lifecycle_smoke PRIVATE cxx_std_17)
  target_include_directories(usk_public_lifecycle_smoke PRIVATE ${USK_PRIVATE_INCLUDE_DIRS})
  target_link_libraries(usk_public_lifecycle_smoke PRIVATE usk_static usk_base_static)
  add_test(NAME usk_public_lifecycle_smoke COMMAND usk_public_lifecycle_smoke)

  if(USK_BUILD_APPS)
    add_test(NAME usk_live_acceptance_cli_smoke
      COMMAND "${CMAKE_COMMAND}"
        -DUSK_ACCEPTANCE_EXE=$<TARGET_FILE:usk_live_acceptance>
        -DUSK_TEMP_ROOT=${CMAKE_CURRENT_BINARY_DIR}
        -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/usk_live_acceptance_smoke.cmake"
    )
  endif()

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
