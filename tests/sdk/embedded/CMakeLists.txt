# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.21)
project(usk_sdk_embedded_defaults LANGUAGES C CXX)

if(NOT DEFINED USK_SOURCE_DIR)
  message(FATAL_ERROR "USK_SOURCE_DIR is required")
endif()
add_subdirectory("${USK_SOURCE_DIR}" usk-provider)

if(USK_BUILD_APPS OR USK_BUILD_TESTS)
  message(FATAL_ERROR "embedded consumers must not build USK apps or tests by default")
endif()
if(TARGET usk_command_graph_smoke OR TARGET usk_live_acceptance)
  message(FATAL_ERROR "embedded default unexpectedly created provider tests or apps")
endif()
if(NOT TARGET UniversalSetup::Headers OR
   NOT TARGET UniversalSetup::CoreStatic OR
   NOT TARGET UniversalSetup::CoreShared)
  message(FATAL_ERROR "embedded provider targets are incomplete")
endif()
