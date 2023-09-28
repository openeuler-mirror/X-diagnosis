# Find the kernel release
execute_process(
        COMMAND uname -r
        OUTPUT_VARIABLE KERNEL_RELEASE
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Set the kernel headers dir
set(KERNELHEADERS_DIR
        /lib/modules/${KERNEL_RELEASE}/build
        CACHE PATH "Kernel headers dir"
)

message(STATUS "Kernel release: ${KERNEL_RELEASE}")
message(STATUS "Kernel headers dir: ${KERNELHEADERS_DIR}")

if (KERNELHEADERS_DIR)
    set(KERNELHEADERS_INCLUDE_DIRS
	    ${KERNELHEADERS_DIR}
	    CACHE PATH "Kernel headers include dirs"
        )
    message(STATUS "Kernel headers include dirs: ${KERNELHEADERS_INCLUDE_DIRS}")
    set(KERNELHEADERS_FOUND 1 CACHE STRING "Set to 1 if kernel headers were found")
else (KERNELHEADERS_DIR)
    set(KERNELHEADERS_FOUND 0 CACHE STRING "Set to 0 if kernel headers were not found")
endif (KERNELHEADERS_DIR)

mark_as_advanced(KERNELHEADERS_FOUND)
