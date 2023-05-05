include(${CMAKE_SOURCE_DIR}/common/mk/var.cmake)

add_executable(xd_scsiiocount xd_scsiiocount.c)
target_link_libraries(xd_scsiiocount
  PRIVATE libbpf.a
  PRIVATE pthread
  PRIVATE elf
  PRIVATE z
)

add_dependencies(xd_scsiiocount xd_scsiiocount.bpf)

install(TARGETS xd_scsiiocount
        RUNTIME DESTINATION ${XD_INSTALL_BINDIR})

add_subdirectory(bpf)

