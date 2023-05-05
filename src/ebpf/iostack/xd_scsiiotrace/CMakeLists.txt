include(${CMAKE_SOURCE_DIR}/common/mk/var.cmake)

add_executable(xd_scsiiotrace xd_scsiiotrace.c)
target_link_libraries(xd_scsiiotrace
  PRIVATE libbpf.a
  PRIVATE pthread
  PRIVATE elf
  PRIVATE z
)

add_dependencies(xd_scsiiotrace xd_scsiiotrace.bpf)

install(TARGETS xd_scsiiotrace
        RUNTIME DESTINATION ${XD_INSTALL_BINDIR})

add_subdirectory(bpf)

