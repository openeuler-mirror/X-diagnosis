# Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# Description: cmake file of xdiagnosis
# Author: lanshen
# Create: 2023-02-15

cmake_minimum_required(VERSION 3.12.1)
project(xdiagnosis)

SET(CMAKE_VERBOSE_MAKEFILE OFF)

IF(COVERAGE_ENABLE)
    MESSAGE(STATUS "Enable coverage compile option")
    SET(COVERAGE_OPTION "${COVERAGE_OPTION} -fprofile-arcs -ftest-coverage")
ENDIF(COVERAGE_ENABLE)

IF(ASAN_ENABLE)
    MESSAGE(STATUS "Enable asan compile option")
    SET(ASAN_OPTIONS "${ASAN_OPTION} -fsanitize=address -fsanitize-recover=address")
ENDIF(ASAN_ENABLE)

IF(CMAKE_BUILD_TYPE STREQUAL Debug)
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${COVERAGE_OPTION} ${ASAN_OPTIONS}")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${COVERAGE_OPTION} ${ASAN_OPTIONS}")
ENDIF()

add_subdirectory(iostack)
#add_subdirectory(net)
#add_subdirectory(sched)

