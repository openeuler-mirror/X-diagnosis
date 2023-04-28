include(${CMAKE_SOURCE_DIR}/common/mk/var.cmake)

add_executable(xd_ext4fsstat xd_ext4fsstat.c)
target_link_libraries(xd_ext4fsstat
  PRIVATE libbpf.a
  PRIVATE pthread
  PRIVATE elf
  PRIVATE z
)

add_dependencies(xd_ext4fsstat xd_ext4fsstat.bpf)

install(TARGETS xd_ext4fsstat 
        RUNTIME DESTINATION ${XD_INSTALL_BINDIR})

add_subdirectory(bpf)

