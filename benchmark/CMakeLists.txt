link_directories(${CMAKE_CURRENT_BINARY_DIR}
                 /usr/local/lib)

include_directories (${PROJECT_SOURCE_DIR}/include
                     ${PROJECT_BINARY_DIR}/include
                     /usr/local/include)

# MPC benchmark
configure_file (
  "${CMAKE_CURRENT_SOURCE_DIR}/bench_mpc.c.in"
  "${CMAKE_CURRENT_BINARY_DIR}/bench_mpc.c"
)

add_executable(bench_mpc ${CMAKE_CURRENT_BINARY_DIR}/bench_mpc.c)

target_link_libraries(bench_mpc mpc)

# NM Commitment benchmark
configure_file (
  "${CMAKE_CURRENT_SOURCE_DIR}/bench_nm_commit.c.in"
  "${CMAKE_CURRENT_BINARY_DIR}/bench_nm_commit.c"
)

add_executable(bench_nm_commit ${CMAKE_CURRENT_BINARY_DIR}/bench_nm_commit.c)

target_link_libraries(bench_nm_commit mpc)
