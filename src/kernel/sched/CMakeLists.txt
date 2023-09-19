# Find kernel headers
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/common/mk")
find_package(KernelHeaders REQUIRED)
include_directories(${KERNELHEADERS_INCLUDE_DIRS})

set(DRIVER_FILE watchcfs.ko)
set(KBUILD_CMD $(MAKE) -C ${KERNELHEADERS_DIR} modules M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR})

# Generate the Kbuild file through cmake.
FILE(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "obj-m := watchcfs.o")

add_custom_command(OUTPUT ${DRIVER_FILE}
        COMMAND ${KBUILD_CMD}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS watchcfs.c VERBATIM)

add_custom_target(watchcfs ALL DEPENDS ${DRIVER_FILE})
