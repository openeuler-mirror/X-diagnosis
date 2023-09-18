# Description: cmake file of xdiagnosis
# Author: EulerosWander
# Create: 2023-09-18

cmake_minimum_required(VERSION 3.12.1)
project(xdiagnosis)

SET(CMAKE_VERBOSE_MAKEFILE OFF)

IF(COVERAGE_ENABLE)
    MESSAGE(STATUS "Enable coverage compile option")
    SET(COVERAGE_OPTION "${COVERAGE_OPTION} -fprofile-arcs -ftest-coverage")
ENDIF(COVERAGE_ENABLE)

IF(CMAKE_BUILD_TYPE STREQUAL Debug)
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${COVERAGE_OPTION} ${ASAN_OPTIONS}")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${COVERAGE_OPTION} ${ASAN_OPTIONS}")
ENDIF()

add_subdirectory(sched)

