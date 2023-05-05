include(${CMAKE_SOURCE_DIR}/common/mk/var.cmake)

add_executable(xd_schedmonitor xd_schedmonitor.c)
target_link_libraries(xd_schedmonitor
  PRIVATE libbpf.a
  PRIVATE pthread
  PRIVATE elf
  PRIVATE z
)

add_dependencies(xd_schedmonitor xd_schedmonitor.bpf)

install(TARGETS xd_schedmonitor
        RUNTIME DESTINATION ${XD_INSTALL_BINDIR})

add_subdirectory(bpf)

