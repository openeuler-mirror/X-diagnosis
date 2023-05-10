include(${CMAKE_SOURCE_DIR}/common/mk/var.cmake)

add_executable(xd_ntrace xd_ntrace.c)
target_link_libraries(xd_ntrace
  PRIVATE libbpf.a
  PRIVATE pthread
  PRIVATE elf
  PRIVATE z
)

add_dependencies(xd_ntrace xd_ntrace.bpf)

install(TARGETS xd_ntrace
        RUNTIME DESTINATION ${XD_INSTALL_BINDIR})

add_subdirectory(bpf)

