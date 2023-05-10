include(${CMAKE_SOURCE_DIR}/common/mk/var.cmake)

add_executable(xd_tcpskinfo xd_tcpskinfo.c)
target_link_libraries(xd_tcpskinfo
  PRIVATE libbpf.a
  PRIVATE pthread
  PRIVATE elf
  PRIVATE z
)

add_dependencies(xd_tcpskinfo xd_tcpskinfo.bpf)

install(TARGETS xd_tcpskinfo
        RUNTIME DESTINATION ${XD_INSTALL_BINDIR})

add_subdirectory(bpf)

