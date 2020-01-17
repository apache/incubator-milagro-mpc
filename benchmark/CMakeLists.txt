link_directories(${CMAKE_CURRENT_BINARY_DIR}
                 /usr/local/lib)

include_directories (${PROJECT_SOURCE_DIR}/include
                     ${PROJECT_BINARY_DIR}/include
                     /usr/local/include)

# List of benchmarks to configure
file(GLOB_RECURSE SRCS *.c.in)

foreach(bench ${SRCS})
  # Extract the filename without an extension
  get_filename_component(target ${bench} NAME_WE)

  configure_file (
    "${bench}"
    "${CMAKE_CURRENT_BINARY_DIR}/${target}.c"
  )

  add_executable(${target} ${CMAKE_CURRENT_BINARY_DIR}/${target}.c)

  target_link_libraries(${target} mpc)
endforeach(bench)
