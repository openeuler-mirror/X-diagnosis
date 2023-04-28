# Clang target triple.
SET(triple bpf)

# Set clang as a compiler.
set(CMAKE_C_COMPILER clang)
#set(CMAKE_CXX_COMPILER_TARGET ${triple})

set(ARCH ${CMAKE_SYSTEM_PROCESSOR})
if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
set(ARCH "x86")
endif()

if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
set(ARCH "arm64")
endif()

set(DEFS "-DBPF_NO_PRESERVE_ACCESS_INDEX")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g -O2 -target bpf -D__TARGET_ARCH_${ARCH} ${DEFS}")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_ISYSTEM_DIRS} -fsanitize=address -ggdb -fno-omit-frame-pointer -fPIC " )

include_directories(${CMAKE_SOURCE_DIR}/common/bpf_common)
include_directories(${CMAKE_SOURCE_DIR}/common/include)

function(bpf prefix)
  add_library(${prefix}.bpf ${prefix}.bpf.c)
  add_custom_command(
    TARGET ${prefix}.bpf
    PRE_LINK
    COMMAND llvm-strip -g $<TARGET_OBJECTS:${prefix}.bpf>
    COMMAND /usr/sbin/bpftool gen skeleton $<TARGET_OBJECTS:${prefix}.bpf> > ${CMAKE_CURRENT_SOURCE_DIR}/../${prefix}.skel.h
  )
endfunction()
