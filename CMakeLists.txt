cmake_minimum_required(VERSION 3.16)
project(universal_setup C)

option(USK_BUILD_APPS "Build Universal Setup app frontends" ON)

add_library(usk_headers INTERFACE)
target_include_directories(usk_headers INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_library(usk_static STATIC runtime/setup/kernel/usk_api.c)
target_include_directories(usk_static PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_library(usk_shared SHARED runtime/setup/kernel/usk_api.c)
target_include_directories(usk_shared PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
set_target_properties(usk_shared PROPERTIES OUTPUT_NAME usk WINDOWS_EXPORT_ALL_SYMBOLS ON)

add_library(usk ALIAS usk_static)
