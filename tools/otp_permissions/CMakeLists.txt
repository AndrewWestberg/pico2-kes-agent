# Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
# SPDX-License-Identifier: BSD-3-Clause
cmake_minimum_required(VERSION 3.12)

if (NOT PICO_SDK_PATH AND DEFINED ENV{PICO_SDK_PATH})
    set(PICO_SDK_PATH "$ENV{PICO_SDK_PATH}")
endif()
if (NOT PICO_SDK_PATH)
    message(FATAL_ERROR "Set PICO_SDK_PATH to the pinned Pico SDK checkout")
endif()
find_package(Git REQUIRED)
execute_process(COMMAND "${GIT_EXECUTABLE}" -C "${PICO_SDK_PATH}" rev-parse HEAD
    RESULT_VARIABLE sdk_git_result OUTPUT_VARIABLE sdk_revision
    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
if (NOT sdk_git_result EQUAL 0 OR NOT sdk_revision STREQUAL "079c6f39023649b154152db30f1d781e884879bc")
    message(FATAL_ERROR "Pico SDK must be checkout 079c6f39023649b154152db30f1d781e884879bc")
endif()
set(PICO_PLATFORM rp2350-arm-s CACHE STRING "" FORCE)
set(PICO_NO_PICOTOOL 1)
include(${PICO_SDK_PATH}/external/pico_sdk_import.cmake)
project(pico2_otp_permissions C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
pico_sdk_init()
add_executable(pico2-otp-permissions set_perms.c)
target_link_libraries(pico2-otp-permissions pico_stdlib)
pico_set_binary_type(pico2-otp-permissions xip_ram)
