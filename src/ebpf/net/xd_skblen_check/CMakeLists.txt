include(${CMAKE_SOURCE_DIR}/common/mk/var.cmake)

add_executable(xd_skblen_check xd_skblen_check.c)
target_link_libraries(xd_skblen_check
  PRIVATE libbpf.a
  PRIVATE pthread
  PRIVATE elf
  PRIVATE z
)

add_dependencies(xd_skblen_check xd_skblen_check.bpf)

install(TARGETS xd_skblen_check
        RUNTIME DESTINATION ${XD_INSTALL_BINDIR})

add_subdirectory(bpf)

