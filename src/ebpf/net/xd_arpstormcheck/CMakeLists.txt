include(${CMAKE_SOURCE_DIR}/common/mk/var.cmake)

add_executable(xd_arpstormcheck xd_arpstormcheck.c)
target_link_libraries(xd_arpstormcheck
  PRIVATE libbpf.a
  PRIVATE pthread
  PRIVATE elf
  PRIVATE z
)

add_dependencies(xd_arpstormcheck xd_arpstormcheck.bpf)

install(TARGETS xd_arpstormcheck
        RUNTIME DESTINATION ${XD_INSTALL_BINDIR})

add_subdirectory(bpf)

