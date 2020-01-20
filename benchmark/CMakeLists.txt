# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

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

target_link_libraries(bench_mpc amcl_mpc)

# NM Commitment benchmark
configure_file (
  "${CMAKE_CURRENT_SOURCE_DIR}/bench_nm_commit.c.in"
  "${CMAKE_CURRENT_BINARY_DIR}/bench_nm_commit.c"
)

add_executable(bench_nm_commit ${CMAKE_CURRENT_BINARY_DIR}/bench_nm_commit.c)

target_link_libraries(bench_nm_commit amcl_mpc)
