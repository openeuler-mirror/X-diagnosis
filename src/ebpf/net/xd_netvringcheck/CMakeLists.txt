include(${CMAKE_SOURCE_DIR}/common/mk/var.cmake)

add_executable(xd_netvringcheck xd_netvringcheck.c)
target_link_libraries(xd_netvringcheck
  PRIVATE libbpf.a
  PRIVATE pthread
  PRIVATE elf
  PRIVATE z
)

add_dependencies(xd_netvringcheck xd_netvringcheck.bpf)

install(TARGETS xd_netvringcheck
        RUNTIME DESTINATION ${XD_INSTALL_BINDIR})

add_subdirectory(bpf)

