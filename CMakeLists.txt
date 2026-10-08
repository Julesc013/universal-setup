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

set(USK_ZLIB_INFLATE_SOURCES
  external/zlib/upstream/adler32.c
  external/zlib/upstream/crc32.c
  external/zlib/upstream/inffast.c
  external/zlib/upstream/inflate.c
  external/zlib/upstream/inftrees.c
  external/zlib/upstream/zutil.c
)
add_library(usk_zlib_inflate_objects OBJECT ${USK_ZLIB_INFLATE_SOURCES})
target_include_directories(usk_zlib_inflate_objects PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/external/zlib/upstream")
target_compile_definitions(usk_zlib_inflate_objects PRIVATE Z_PREFIX)
set_target_properties(usk_zlib_inflate_objects PROPERTIES
  C_VISIBILITY_PRESET hidden
  POSITION_INDEPENDENT_CODE ON
)

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

if(WIN32)
  add_library(usk_publisher_windows_static STATIC
    runtime/platform/windows/usk_publisher_anchor_create.cpp
    runtime/platform/windows/usk_publisher_staged_stream.cpp
    runtime/platform/windows/usk_publisher_bound_rename.cpp
    runtime/platform/windows/usk_publisher_maintenance_mutation.cpp
    runtime/platform/windows/usk_publisher_metadata.cpp
    runtime/platform/windows/usk_publisher_directory_entries.cpp
    runtime/platform/windows/usk_publisher_handle_observation.cpp
    runtime/platform/windows/usk_publisher_security_descriptor.cpp
    runtime/platform/windows/usk_publisher_consumer_access.cpp
    runtime/platform/windows/usk_publisher_tree_observation.cpp
    runtime/platform/windows/usk_publisher_token_observation.cpp
    runtime/platform/windows/usk_publisher_execution_observation.cpp
    runtime/platform/windows/usk_publisher_creation_observation.cpp
    runtime/platform/windows/usk_publisher_process_boundary.cpp
    runtime/platform/windows/usk_publisher_worker_security.cpp
    runtime/platform/windows/usk_publisher_service_access.cpp
    runtime/platform/windows/usk_publisher_request_channel.cpp
    runtime/platform/windows/usk_publisher_effect_worker_custody_internal.cpp
    runtime/platform/windows/usk_publisher_effect_broker_internal.cpp
    runtime/platform/windows/usk_publisher_effect_execution_internal.cpp
    runtime/platform/windows/usk_publisher_registration.cpp
    runtime/platform/windows/usk_publisher_data_partition.cpp
    runtime/platform/windows/usk_publisher_volume_stream_observation.cpp
    runtime/platform/windows/usk_publisher_device_acl.cpp
    runtime/platform/windows/usk_publisher_volume_operation_guard.cpp
    runtime/platform/windows/usk_publisher_installation_lease.cpp)
  target_compile_features(usk_publisher_windows_static PUBLIC cxx_std_17)
  # Bind the SDK selected by this generated VS build, rather than the installed
  # SDK inventory or a test-runner assertion. Unknown generators remain unable
  # to produce the restricted publisher's qualified-platform observations.
  target_compile_definitions(usk_publisher_windows_static PRIVATE
    USK_PUBLISHER_BUILD_SDK_VERSION="${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}")
  target_include_directories(usk_publisher_windows_static PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/runtime/platform/windows")
  target_link_libraries(usk_publisher_windows_static PUBLIC usk_base_static usk_transaction_static advapi32 bcrypt shell32 ole32)
  set_target_properties(usk_publisher_windows_static PROPERTIES EXCLUDE_FROM_ALL ON)
  usk_enable_strict_warnings(usk_publisher_windows_static)
endif()

add_library(usk_verify_static STATIC runtime/setup/verify/usk_package_verify.cpp)
target_compile_features(usk_verify_static PUBLIC cxx_std_17)
target_include_directories(usk_verify_static PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/verify"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_link_libraries(usk_verify_static PUBLIC usk_base_static)
set_target_properties(usk_verify_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(usk_archive_static STATIC
  runtime/setup/package/usk_archive_inspect.cpp
  $<TARGET_OBJECTS:usk_zlib_inflate_objects>)
target_compile_features(usk_archive_static PUBLIC cxx_std_17)
target_include_directories(usk_archive_static PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/package"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/external/zlib/upstream"
)
target_compile_definitions(usk_archive_static PRIVATE Z_PREFIX)
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
  runtime/setup/transaction/usk_native_maintenance_transaction_internal.cpp
  runtime/setup/transaction/usk_install_lease.cpp
  runtime/setup/transaction/usk_replacement_session.cpp
  runtime/setup/transaction/usk_commit_authority.cpp
  runtime/setup/transaction/usk_stream_entry_journal.cpp
  runtime/setup/transaction/usk_maintenance_effect_journal.cpp
)
target_compile_features(usk_transaction_static PUBLIC cxx_std_17)
target_include_directories(usk_transaction_static PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/transaction"
)
target_link_libraries(usk_transaction_static PUBLIC usk_base_static)
set_target_properties(usk_transaction_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(usk_streaming_static STATIC
  runtime/setup/streaming/usk_streaming_source_target.cpp
)
target_compile_features(usk_streaming_static PUBLIC cxx_std_17)
target_include_directories(usk_streaming_static PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/streaming"
)
target_link_libraries(usk_streaming_static PUBLIC
  usk_base_static
  usk_state_static
  usk_transaction_static
)
set_target_properties(usk_streaming_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

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
  runtime/setup/lifecycle/usk_install_restart.cpp
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
if(WIN32)
  target_sources(usk_lifecycle_static PRIVATE runtime/setup/lifecycle/usk_protected_install_publisher.cpp)
  target_sources(usk_lifecycle_static PRIVATE runtime/setup/lifecycle/usk_native_maintenance_context_internal.cpp)
  target_compile_definitions(usk_lifecycle_static PRIVATE
    USK_INTERNAL_PUBLISHER_FINALIZATION)
  target_link_libraries(usk_lifecycle_static PRIVATE usk_publisher_windows_static)
endif()
set_target_properties(usk_lifecycle_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(NOT USK_BUILD_APPS AND NOT USK_BUILD_TESTS AND NOT USK_BUILD_FUZZERS)
  foreach(USK_INTERNAL_TARGET IN ITEMS
      usk_base_static
      usk_verify_static
      usk_archive_static
      usk_policy_static
      usk_transaction_static
      usk_state_static
      usk_lifecycle_static
      usk_streaming_static)
    set_target_properties(${USK_INTERNAL_TARGET} PROPERTIES EXCLUDE_FROM_ALL ON)
  endforeach()
endif()

set(USK_CORE_SOURCES
  $<TARGET_OBJECTS:usk_zlib_inflate_objects>
  runtime/base/usk_json.cpp
  runtime/base/usk_record_io.cpp
  runtime/base/usk_sha256.cpp
  runtime/base/usk_stable_file.cpp
  runtime/base/usk_utf8_path.cpp
  runtime/setup/audit/usk_audit_repository.cpp
  runtime/setup/evidence/usk_live_evidence.cpp
  runtime/setup/kernel/usk_api.c
  runtime/setup/lifecycle/usk_lifecycle.cpp
  runtime/setup/lifecycle/usk_install_restart.cpp
  runtime/setup/lifecycle/usk_public_lifecycle.cpp
  runtime/setup/package/usk_archive_inspect.cpp
  runtime/setup/policy/usk_target_inspect.cpp
  runtime/setup/policy/usk_target_policy.cpp
  runtime/setup/state/usk_state_repository.cpp
  runtime/setup/streaming/usk_streaming_source_target.cpp
  runtime/setup/transaction/usk_transaction_session.cpp
  runtime/setup/transaction/usk_native_maintenance_transaction_internal.cpp
  runtime/setup/transaction/usk_install_lease.cpp
  runtime/setup/transaction/usk_replacement_session.cpp
  runtime/setup/transaction/usk_commit_authority.cpp
  runtime/setup/transaction/usk_stream_entry_journal.cpp
  runtime/setup/transaction/usk_maintenance_effect_journal.cpp
  runtime/setup/verify/usk_package_verify.cpp
)
set(USK_PRIVATE_INCLUDE_DIRS
  "${CMAKE_CURRENT_SOURCE_DIR}/external/zlib/upstream"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/base"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/audit"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/evidence"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/lifecycle"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/package"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/policy"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/state"
  "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/streaming"
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
  target_compile_definitions(usk_static PRIVATE Z_PREFIX)
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
  target_compile_definitions(usk_shared PRIVATE USK_BUILD_SHARED Z_PREFIX INTERFACE USK_USE_SHARED)
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
  FILES external/zlib/upstream/LICENSE
  DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/universal-setup"
  RENAME zlib-LICENSE
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

  add_executable(usk_machine
    apps/cli/usk_machine.cpp
    apps/cli/usk_product_info.cpp
    runtime/command/usk_one_shot.cpp)
  target_compile_features(usk_machine PRIVATE cxx_std_17)
  target_include_directories(usk_machine PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/runtime/command"
    "${CMAKE_CURRENT_SOURCE_DIR}/runtime/base"
    "${CMAKE_CURRENT_SOURCE_DIR}/runtime/setup/package"
    "${CMAKE_CURRENT_SOURCE_DIR}/include")
  target_link_libraries(usk_machine PRIVATE usk_static usk_base_static usk_archive_static)
  if(WIN32)
    target_link_libraries(usk_machine PRIVATE usk_publisher_windows_static shell32)
  endif()
  usk_enable_strict_warnings(usk_machine)

  if(WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_executable(usk_publisher_service
      apps/daemon/usk_publisher_lab_service.cpp)
    target_compile_features(usk_publisher_service PRIVATE cxx_std_17)
    target_compile_definitions(usk_publisher_service PRIVATE
      USK_PRODUCTION_PUBLISHER=1)
    target_link_libraries(usk_publisher_service PRIVATE
      usk_publisher_windows_static usk_archive_static usk_lifecycle_static)
    usk_enable_strict_warnings(usk_publisher_service)
    if(MSVC)
      # Keep the optimized production image and its full matching symbols.
      # /Z7 embeds debug information in objects without a compiler PDB.
      foreach(USK_PUBLISHER_SYMBOL_TARGET IN ITEMS
          usk_base_static usk_publisher_windows_static usk_archive_static
          usk_policy_static usk_state_static usk_transaction_static
          usk_lifecycle_static usk_zlib_inflate_objects usk_publisher_service)
        target_compile_options(${USK_PUBLISHER_SYMBOL_TARGET} PRIVATE
          "$<$<CONFIG:Release>:/Z7>")
      endforeach()
      # /DEBUG changes link optimization defaults; preserve Release behavior.
      target_link_options(usk_publisher_service PRIVATE
        "$<$<CONFIG:Release>:/DEBUG:FULL>"
        "$<$<CONFIG:Release>:/INCREMENTAL:NO>"
        "$<$<CONFIG:Release>:/OPT:REF>"
        "$<$<CONFIG:Release>:/OPT:ICF>")
    endif()

    add_executable(usk_publisher_lab_service
      apps/daemon/usk_publisher_lab_service.cpp)
    target_compile_features(usk_publisher_lab_service PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_lab_service PRIVATE
      usk_publisher_windows_static usk_archive_static usk_lifecycle_static)
    usk_enable_strict_warnings(usk_publisher_lab_service)

    add_executable(usk_publisher_client apps/daemon/usk_publisher_client.cpp)
    target_compile_features(usk_publisher_client PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_client PRIVATE usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_client)

    add_executable(usk_publisher_service_control
      apps/daemon/usk_publisher_service_control.cpp)
    target_compile_features(usk_publisher_service_control PRIVATE cxx_std_17)
    target_include_directories(usk_publisher_service_control PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}/runtime/base")
    target_link_libraries(usk_publisher_service_control PRIVATE
      usk_publisher_windows_static usk_base_static advapi32 shell32)
    usk_enable_strict_warnings(usk_publisher_service_control)
  endif()
endif()

if(USK_BUILD_TESTS)
  enable_testing()

  add_executable(usk_one_shot_smoke
    tests/native/usk_one_shot_smoke.cpp
    runtime/command/usk_one_shot.cpp)
  target_compile_features(usk_one_shot_smoke PRIVATE cxx_std_17)
  target_include_directories(usk_one_shot_smoke PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/runtime/command"
    "${CMAKE_CURRENT_SOURCE_DIR}/runtime/base"
    "${CMAKE_CURRENT_SOURCE_DIR}/include")
  target_link_libraries(usk_one_shot_smoke PRIVATE usk_static usk_base_static)
  usk_enable_strict_warnings(usk_one_shot_smoke)
  add_test(NAME usk_one_shot_smoke COMMAND usk_one_shot_smoke)
  if(USK_BUILD_APPS)
    add_test(NAME usk_machine_process_smoke
      COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/native/usk_machine_process_probe.py"
        "$<TARGET_FILE:usk_machine>")
    add_test(NAME usk_bundle_plan_process_smoke
      COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/native/usk_bundle_plan_process_probe.py"
        "$<TARGET_FILE:usk_machine>")
  endif()

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

  add_executable(usk_install_lease_smoke tests/native/usk_install_lease_smoke.cpp)
  target_compile_features(usk_install_lease_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_install_lease_smoke PRIVATE usk_transaction_static)
  usk_enable_strict_warnings(usk_install_lease_smoke)
  add_test(NAME usk_install_lease_smoke COMMAND usk_install_lease_smoke)
  set_tests_properties(usk_install_lease_smoke PROPERTIES TIMEOUT 30)

  add_executable(usk_replacement_session_smoke tests/native/usk_replacement_session_smoke.cpp)
  target_compile_features(usk_replacement_session_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_replacement_session_smoke PRIVATE usk_transaction_static)
  add_test(NAME usk_replacement_session_smoke COMMAND usk_replacement_session_smoke)

  add_executable(
    usk_streaming_source_target_smoke
    tests/native/usk_streaming_source_target_smoke.cpp)
  target_compile_features(usk_streaming_source_target_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_streaming_source_target_smoke PRIVATE usk_streaming_static)
  add_test(NAME usk_streaming_source_target_smoke COMMAND usk_streaming_source_target_smoke)

  add_executable(usk_commit_authority_smoke tests/native/usk_commit_authority_smoke.cpp)
  target_compile_features(usk_commit_authority_smoke PRIVATE cxx_std_17)
  target_link_libraries(usk_commit_authority_smoke PRIVATE usk_transaction_static)
  add_test(NAME usk_commit_authority_smoke COMMAND usk_commit_authority_smoke)
  set_tests_properties(usk_commit_authority_smoke PROPERTIES TIMEOUT 30)

  if(WIN32)
    add_executable(usk_publisher_candidate_context_smoke tests/native/usk_publisher_candidate_context_smoke.cpp)
    target_compile_features(usk_publisher_candidate_context_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_candidate_context_smoke PRIVATE usk_lifecycle_static usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_candidate_context_smoke)
    add_test(NAME usk_publisher_candidate_context_smoke COMMAND usk_publisher_candidate_context_smoke)
    set_tests_properties(usk_publisher_candidate_context_smoke PROPERTIES TIMEOUT 30)
    add_executable(usk_publisher_request_channel_smoke tests/native/usk_publisher_request_channel_smoke.cpp)
    add_executable(usk_publisher_registered_contention_probe
      tests/native/usk_publisher_registered_contention_probe.cpp runtime/command/usk_one_shot.cpp)
    target_compile_features(usk_publisher_registered_contention_probe PRIVATE cxx_std_17)
    target_include_directories(usk_publisher_registered_contention_probe PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/runtime/command")
    target_link_libraries(usk_publisher_registered_contention_probe PRIVATE usk_publisher_windows_static usk_static)
    usk_enable_strict_warnings(usk_publisher_registered_contention_probe)
    add_executable(usk_neutral_payload tests/fixtures/authoring/neutral_one_file/hello.c)
    target_compile_features(usk_publisher_request_channel_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_request_channel_smoke PRIVATE usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_request_channel_smoke)
    add_test(NAME usk_publisher_request_channel_smoke COMMAND usk_publisher_request_channel_smoke)
    # Its sub-second deadlines need a scheduled signalling thread. Run it
    # separately from CTest's concurrent compiler/package subprocesses.
    set_tests_properties(usk_publisher_request_channel_smoke PROPERTIES TIMEOUT 15 RUN_SERIAL TRUE)
    add_test(NAME usk_publisher_held_capture_context_smoke
      COMMAND powershell -NoProfile -ExecutionPolicy Bypass -File
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/windows_publisher_held_capture_context_smoke.ps1")
    set_tests_properties(usk_publisher_held_capture_context_smoke PROPERTIES TIMEOUT 15)
    add_test(NAME usk_publisher_standard_client_cleanup_smoke
      COMMAND powershell -NoProfile -ExecutionPolicy Bypass -File
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/windows_publisher_standard_client_cleanup_smoke.ps1")
    set_tests_properties(usk_publisher_standard_client_cleanup_smoke PROPERTIES TIMEOUT 15)
    add_test(NAME usk_publisher_standard_launcher_smoke
      COMMAND powershell -NoProfile -ExecutionPolicy Bypass -File
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/windows_publisher_standard_launcher_smoke.ps1")
    set_tests_properties(usk_publisher_standard_launcher_smoke PROPERTIES TIMEOUT 15)
    if(TARGET usk_machine)
      add_test(NAME usk_publisher_candidate_apply_process_smoke
        COMMAND "${Python3_EXECUTABLE}"
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/native/usk_bundle_plan_process_probe.py"
          "$<TARGET_FILE:usk_machine>" "$<TARGET_FILE:usk_publisher_candidate_context_smoke>")
      set_tests_properties(usk_publisher_candidate_apply_process_smoke PROPERTIES TIMEOUT 60)
    endif()
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
      if(TARGET usk_publisher_service_control)
        add_test(NAME usk_publisher_apply_control_preflight
          COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/native/usk_publisher_apply_control_probe.py"
            "$<TARGET_FILE:usk_publisher_service_control>")
        set_tests_properties(usk_publisher_apply_control_preflight PROPERTIES TIMEOUT 30)
      endif()
      if(TARGET usk_publisher_service)
        add_test(NAME usk_publisher_service_mode_smoke
          COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/native/usk_publisher_service_mode_probe.py"
            "$<TARGET_FILE:usk_publisher_service>")
        set_tests_properties(usk_publisher_service_mode_smoke PROPERTIES TIMEOUT 15)
      endif()

      add_executable(usk_publisher_lab_service_fault
        apps/daemon/usk_publisher_lab_service.cpp)
      target_compile_features(usk_publisher_lab_service_fault PRIVATE cxx_std_17)
      target_compile_definitions(usk_publisher_lab_service_fault PRIVATE
        USK_TEST_REGISTERED_FAULT_GATE=1)
      target_link_libraries(usk_publisher_lab_service_fault PRIVATE
        usk_publisher_windows_static usk_archive_static usk_lifecycle_static)
      usk_enable_strict_warnings(usk_publisher_lab_service_fault)

      # A private coordination-only hosted fixture; never registered as a service
      # and never executed by local CTest. The owned lab retains its process.
      add_executable(usk_publisher_install_guard_holder
        tests/native/usk_publisher_install_guard_holder.cpp)
      target_compile_features(usk_publisher_install_guard_holder PRIVATE cxx_std_17)
      target_link_libraries(usk_publisher_install_guard_holder PRIVATE usk_publisher_windows_static)
      usk_enable_strict_warnings(usk_publisher_install_guard_holder)

      add_executable(usk_publisher_lab_device_acl
        tests/native/usk_publisher_lab_device_acl.cpp)
      target_compile_features(usk_publisher_lab_device_acl PRIVATE cxx_std_17)
      target_link_libraries(usk_publisher_lab_device_acl PRIVATE advapi32 VirtDisk)
      usk_enable_strict_warnings(usk_publisher_lab_device_acl)
      # Keep the packaged machine-client and non-admin consumer journey in the
      # normal hosted gate, including actual payload execution and recovery.
      if(TARGET usk_machine AND DEFINED ENV{GITHUB_ACTIONS} AND
          "$ENV{RUNNER_ENVIRONMENT}" STREQUAL "github-hosted" AND
          "$ENV{USK_TRUSTED_HOSTED_LAB}" STREQUAL "true")
        add_test(NAME usk_machine_registered_candidate_hosted
          COMMAND pwsh -NoProfile -NonInteractive -File
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/windows_publisher_lab_probe.ps1"
            -OutputPath "$ENV{RUNNER_TEMP}/usk-wu006-packaged-machine-bridge.json"
            -ServiceBinary "$<TARGET_FILE:usk_publisher_service>"
            -ServiceControlBinary "$<TARGET_FILE:usk_publisher_service_control>"
            -DeviceAclBinary "$<TARGET_FILE:usk_publisher_lab_device_acl>"
            -MachineBinary "$<TARGET_FILE:usk_machine>"
            -PublicApplyBinary "$<TARGET_FILE:usk_publisher_candidate_context_smoke>"
            -ClientBinary "$<TARGET_FILE:usk_publisher_client>"
            -PayloadBinary "$<TARGET_FILE:usk_neutral_payload>"
            -ReviewedSource -RegisteredService -ConsumerAccess
            -MachineRequestClient -ReuseRegistration -ProductionConcurrentRights)
        set_tests_properties(usk_machine_registered_candidate_hosted
          PROPERTIES RUN_SERIAL TRUE TIMEOUT 420)
        add_test(NAME usk_controller_registered_apply_hosted
          COMMAND pwsh -NoProfile -NonInteractive -File
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/windows_publisher_lab_probe.ps1"
            -OutputPath "$ENV{RUNNER_TEMP}/usk-wu006-controller-apply-bridge.json"
            -ServiceBinary "$<TARGET_FILE:usk_publisher_service>"
            -ServiceControlBinary "$<TARGET_FILE:usk_publisher_service_control>"
            -DeviceAclBinary "$<TARGET_FILE:usk_publisher_lab_device_acl>"
            -MachineBinary "$<TARGET_FILE:usk_machine>"
            -PublicApplyBinary "$<TARGET_FILE:usk_publisher_candidate_context_smoke>"
            -ClientBinary "$<TARGET_FILE:usk_publisher_client>"
            -ReviewedSource -RegisteredService -ControllerApply)
        set_tests_properties(usk_controller_registered_apply_hosted
          PROPERTIES RUN_SERIAL TRUE TIMEOUT 420)
      endif()
    endif()

    add_executable(usk_publisher_handle_observation_smoke
      tests/native/usk_publisher_handle_observation_smoke.cpp)
    target_compile_features(usk_publisher_handle_observation_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_handle_observation_smoke PRIVATE
      usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_handle_observation_smoke)
    add_test(NAME usk_publisher_handle_observation_smoke
      COMMAND usk_publisher_handle_observation_smoke)
    set_tests_properties(usk_publisher_handle_observation_smoke PROPERTIES TIMEOUT 30)

    add_executable(usk_publisher_volume_operation_guard_smoke
      tests/native/usk_publisher_volume_operation_guard_smoke.cpp)
    target_compile_features(usk_publisher_volume_operation_guard_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_volume_operation_guard_smoke PRIVATE
      usk_publisher_windows_static ole32)
    usk_enable_strict_warnings(usk_publisher_volume_operation_guard_smoke)
    add_test(NAME usk_publisher_volume_operation_guard_smoke
      COMMAND usk_publisher_volume_operation_guard_smoke)
    # The release/cancellation deadlines exercise real threads. Keep competing
    # SDK builds and native tests from delaying the fixture's release signal.
    set_tests_properties(usk_publisher_volume_operation_guard_smoke PROPERTIES TIMEOUT 30 RUN_SERIAL TRUE)

    add_executable(usk_publisher_device_acl_smoke
      tests/native/usk_publisher_device_acl_smoke.cpp)
    target_compile_features(usk_publisher_device_acl_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_device_acl_smoke PRIVATE
      usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_device_acl_smoke)
    add_test(NAME usk_publisher_device_acl_smoke
      COMMAND usk_publisher_device_acl_smoke)
    set_tests_properties(usk_publisher_device_acl_smoke PROPERTIES TIMEOUT 30)

    add_executable(usk_publisher_volume_bound_setup_smoke
      tests/native/usk_publisher_volume_bound_setup_smoke.cpp)
    target_compile_features(usk_publisher_volume_bound_setup_smoke PRIVATE cxx_std_17)
    target_include_directories(usk_publisher_volume_bound_setup_smoke PRIVATE ${USK_PRIVATE_INCLUDE_DIRS})
    target_link_libraries(usk_publisher_volume_bound_setup_smoke PRIVATE
      usk_static usk_base_static)
    usk_enable_strict_warnings(usk_publisher_volume_bound_setup_smoke)
    add_test(NAME usk_publisher_volume_bound_setup_smoke
      COMMAND usk_publisher_volume_bound_setup_smoke)
    set_tests_properties(usk_publisher_volume_bound_setup_smoke PROPERTIES TIMEOUT 30)

    add_executable(usk_publisher_token_observation_smoke
      tests/native/usk_publisher_token_observation_smoke.cpp)
    target_compile_features(usk_publisher_token_observation_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_token_observation_smoke PRIVATE
      usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_token_observation_smoke)
    add_test(NAME usk_publisher_token_observation_smoke
      COMMAND usk_publisher_token_observation_smoke)
    set_tests_properties(usk_publisher_token_observation_smoke PROPERTIES TIMEOUT 30)

    add_executable(usk_publisher_data_partition_smoke
      tests/native/usk_publisher_data_partition_smoke.cpp)
    target_compile_features(usk_publisher_data_partition_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_data_partition_smoke PRIVATE
      usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_data_partition_smoke)
    add_test(NAME usk_publisher_data_partition_smoke
      COMMAND usk_publisher_data_partition_smoke)
    set_tests_properties(usk_publisher_data_partition_smoke PROPERTIES TIMEOUT 30)

    add_executable(usk_publisher_security_descriptor_smoke
      tests/native/usk_publisher_security_descriptor_smoke.cpp)
    target_compile_features(usk_publisher_security_descriptor_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_security_descriptor_smoke PRIVATE
      usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_security_descriptor_smoke)
    add_test(NAME usk_publisher_security_descriptor_smoke
      COMMAND usk_publisher_security_descriptor_smoke)
    set_tests_properties(usk_publisher_security_descriptor_smoke PROPERTIES TIMEOUT 30)

    add_executable(usk_publisher_anchor_create_smoke
      tests/native/usk_publisher_anchor_create_smoke.cpp)
    target_compile_features(usk_publisher_anchor_create_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_anchor_create_smoke PRIVATE
      usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_anchor_create_smoke)
    add_test(NAME usk_publisher_anchor_create_smoke
      COMMAND usk_publisher_anchor_create_smoke)
    set_tests_properties(usk_publisher_anchor_create_smoke PROPERTIES TIMEOUT 30)

    add_executable(usk_publisher_creation_observation_smoke
      tests/native/usk_publisher_creation_observation_smoke.cpp)
    target_compile_features(usk_publisher_creation_observation_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_creation_observation_smoke PRIVATE usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_creation_observation_smoke)
    add_test(NAME usk_publisher_creation_observation_smoke COMMAND usk_publisher_creation_observation_smoke)
    set_tests_properties(usk_publisher_creation_observation_smoke PROPERTIES TIMEOUT 30)

    add_executable(usk_publisher_process_boundary_smoke
      tests/native/usk_publisher_process_boundary_smoke.cpp)
    target_compile_features(usk_publisher_process_boundary_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_process_boundary_smoke PRIVATE usk_publisher_windows_static usk_lifecycle_static)
    usk_enable_strict_warnings(usk_publisher_process_boundary_smoke)
    add_test(NAME usk_publisher_process_boundary_smoke COMMAND usk_publisher_process_boundary_smoke)
    set_tests_properties(usk_publisher_process_boundary_smoke PROPERTIES TIMEOUT 30)

    add_executable(usk_publisher_effect_worker_custody_smoke
      tests/native/usk_publisher_effect_worker_custody_smoke.cpp)
    target_compile_features(usk_publisher_effect_worker_custody_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_effect_worker_custody_smoke PRIVATE usk_publisher_windows_static usk_lifecycle_static)
    usk_enable_strict_warnings(usk_publisher_effect_worker_custody_smoke)
    add_test(NAME usk_publisher_effect_worker_custody_smoke COMMAND usk_publisher_effect_worker_custody_smoke)
    set_tests_properties(usk_publisher_effect_worker_custody_smoke PROPERTIES TIMEOUT 60)
    add_executable(usk_publisher_broker_object_query_smoke tests/native/usk_publisher_broker_object_query_smoke.cpp)
    target_compile_features(usk_publisher_broker_object_query_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_broker_object_query_smoke PRIVATE usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_broker_object_query_smoke)
    add_test(NAME usk_publisher_broker_object_query_smoke COMMAND usk_publisher_broker_object_query_smoke)
    set_tests_properties(usk_publisher_broker_object_query_smoke PROPERTIES TIMEOUT 30)

    add_executable(usk_publisher_service_access_smoke
      tests/native/usk_publisher_service_access_smoke.cpp)
    target_compile_features(usk_publisher_service_access_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_service_access_smoke PRIVATE usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_service_access_smoke)
    add_test(NAME usk_publisher_service_access_smoke COMMAND usk_publisher_service_access_smoke)
    set_tests_properties(usk_publisher_service_access_smoke PROPERTIES TIMEOUT 15)

    add_executable(usk_publisher_volume_stream_observation_smoke
      tests/native/usk_publisher_volume_stream_observation_smoke.cpp)
    target_compile_features(usk_publisher_volume_stream_observation_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_volume_stream_observation_smoke PRIVATE
      usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_volume_stream_observation_smoke)
    add_test(NAME usk_publisher_volume_stream_observation_smoke
      COMMAND usk_publisher_volume_stream_observation_smoke)
    set_tests_properties(usk_publisher_volume_stream_observation_smoke PROPERTIES TIMEOUT 30)

    add_executable(usk_publisher_directory_entries_smoke
      tests/native/usk_publisher_directory_entries_smoke.cpp)
    target_compile_features(usk_publisher_directory_entries_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_directory_entries_smoke PRIVATE
      usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_directory_entries_smoke)
    add_test(NAME usk_publisher_directory_entries_smoke
      COMMAND usk_publisher_directory_entries_smoke)
    set_tests_properties(usk_publisher_directory_entries_smoke PROPERTIES TIMEOUT 30)

    add_executable(usk_publisher_tree_observation_smoke
      tests/native/usk_publisher_tree_observation_smoke.cpp)
    target_compile_features(usk_publisher_tree_observation_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_tree_observation_smoke PRIVATE
      usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_tree_observation_smoke)
    add_test(NAME usk_publisher_tree_observation_smoke
      COMMAND usk_publisher_tree_observation_smoke)
    set_tests_properties(usk_publisher_tree_observation_smoke PROPERTIES TIMEOUT 30)

    add_executable(usk_publisher_bound_rename_smoke
      tests/native/usk_publisher_bound_rename_smoke.cpp)
    target_compile_features(usk_publisher_bound_rename_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_bound_rename_smoke PRIVATE
      usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_bound_rename_smoke)
    add_test(NAME usk_publisher_bound_rename_smoke
      COMMAND usk_publisher_bound_rename_smoke)
    set_tests_properties(usk_publisher_bound_rename_smoke PROPERTIES TIMEOUT 30)

    add_executable(usk_publisher_maintenance_mutation_smoke
      tests/native/usk_publisher_maintenance_mutation_smoke.cpp)
    target_compile_features(usk_publisher_maintenance_mutation_smoke PRIVATE cxx_std_17)
    target_link_libraries(usk_publisher_maintenance_mutation_smoke PRIVATE usk_publisher_windows_static)
    usk_enable_strict_warnings(usk_publisher_maintenance_mutation_smoke)
    add_test(NAME usk_publisher_maintenance_mutation_smoke COMMAND usk_publisher_maintenance_mutation_smoke)
    set_tests_properties(usk_publisher_maintenance_mutation_smoke PROPERTIES TIMEOUT 30)
  endif()

  add_executable(usk_entry_restart_smoke tests/native/usk_entry_restart_smoke.cpp)
  target_compile_features(usk_entry_restart_smoke PRIVATE cxx_std_17)
  find_package(Threads REQUIRED)
  target_link_libraries(usk_entry_restart_smoke PRIVATE usk_streaming_static Threads::Threads)
  add_test(NAME usk_entry_restart_smoke COMMAND usk_entry_restart_smoke)
  set_tests_properties(usk_entry_restart_smoke PROPERTIES TIMEOUT 120)

  add_executable(usk_zip_restart_smoke tests/native/usk_zip_restart_smoke.cpp)
  target_compile_features(usk_zip_restart_smoke PRIVATE cxx_std_17)
  target_include_directories(usk_zip_restart_smoke PRIVATE ${USK_PRIVATE_INCLUDE_DIRS})
  target_link_libraries(usk_zip_restart_smoke PRIVATE usk_static Threads::Threads)
  add_test(NAME usk_zip_restart_smoke COMMAND usk_zip_restart_smoke)
  set_tests_properties(usk_zip_restart_smoke PROPERTIES TIMEOUT 120)

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

  add_executable(usk_public_lifecycle_smoke
    tests/native/usk_public_lifecycle_smoke.cpp
    runtime/command/usk_one_shot.cpp)
  target_compile_features(usk_public_lifecycle_smoke PRIVATE cxx_std_17)
  target_include_directories(usk_public_lifecycle_smoke PRIVATE ${USK_PRIVATE_INCLUDE_DIRS}
    "${CMAKE_CURRENT_SOURCE_DIR}/runtime/command")
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

  # Keep retained native/Python fixtures inside this disposable build tree.
  # Failed probes may retain diagnostics; they must not scatter payloads into
  # the user's system temporary directory across repeated local test runs.
  # The campaign task path already carries repository/task identity. Adding
  # build/run identifiers to native fixture paths can exceed the supported
  # Windows path envelope before the behavior under test is reached.
  if(DEFINED ENV{FACMAN_TASK_ROOT} AND NOT "$ENV{FACMAN_TASK_ROOT}" STREQUAL "")
    set(USK_TEST_TEMP_ROOT "$ENV{FACMAN_TASK_ROOT}/t")
  else()
    set(USK_TEST_TEMP_ROOT "${CMAKE_CURRENT_BINARY_DIR}/test-tmp")
  endif()
  file(MAKE_DIRECTORY "${USK_TEST_TEMP_ROOT}")
  get_property(USK_NATIVE_TESTS DIRECTORY PROPERTY TESTS)
  foreach(USK_NATIVE_TEST IN LISTS USK_NATIVE_TESTS)
    set_property(TEST "${USK_NATIVE_TEST}" APPEND PROPERTY ENVIRONMENT
      "TMP=${USK_TEST_TEMP_ROOT}"
      "TEMP=${USK_TEST_TEMP_ROOT}"
      "TMPDIR=${USK_TEST_TEMP_ROOT}")
  endforeach()
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
