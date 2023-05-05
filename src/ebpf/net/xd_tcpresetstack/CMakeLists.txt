include(${CMAKE_SOURCE_DIR}/common/mk/var.cmake)

add_executable(xd_tcpresetstack xd_tcpresetstack.c)
target_link_libraries(xd_tcpresetstack
  PRIVATE libbpf.a
  PRIVATE pthread
  PRIVATE elf
  PRIVATE z
)

add_dependencies(xd_tcpresetstack xd_tcpresetstack.bpf)

install(TARGETS xd_tcpresetstack
        RUNTIME DESTINATION ${XD_INSTALL_BINDIR})

add_subdirectory(bpf)

