include(${CMAKE_SOURCE_DIR}/common/mk/var.cmake)

add_executable(xd_iolatency xd_iolatency.c)
target_link_libraries(xd_iolatency
  PRIVATE libbpf.a
  PRIVATE pthread
  PRIVATE elf
  PRIVATE z
)

add_dependencies(xd_iolatency xd_iolatency.bpf)

install(TARGETS xd_iolatency
        RUNTIME DESTINATION ${XD_INSTALL_BINDIR})

add_subdirectory(bpf)

