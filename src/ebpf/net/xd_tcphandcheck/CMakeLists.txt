include(${CMAKE_SOURCE_DIR}/common/mk/var.cmake)

add_executable(xd_tcphandcheck xd_tcphandcheck.c)
target_link_libraries(xd_tcphandcheck
  PRIVATE libbpf.a
  PRIVATE pthread
  PRIVATE elf
  PRIVATE z
)

add_dependencies(xd_tcphandcheck xd_tcphandcheck.bpf)

install(TARGETS xd_tcphandcheck
        RUNTIME DESTINATION ${XD_INSTALL_BINDIR})

add_subdirectory(bpf)

