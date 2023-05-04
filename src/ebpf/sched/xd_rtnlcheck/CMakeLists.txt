include(${CMAKE_SOURCE_DIR}/common/mk/var.cmake)

add_executable(xd_rtnlcheck xd_rtnlcheck.c)
target_link_libraries(xd_rtnlcheck
  PRIVATE libbpf.a
  PRIVATE pthread
  PRIVATE elf
  PRIVATE z
)

add_dependencies(xd_rtnlcheck xd_rtnlcheck.bpf)

install(TARGETS xd_rtnlcheck
        RUNTIME DESTINATION ${XD_INSTALL_BINDIR})

add_subdirectory(bpf)

