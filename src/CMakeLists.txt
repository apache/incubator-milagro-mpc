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

file(GLOB_RECURSE SOURCES *.c)

set(target "amcl_mpc")

link_directories(${CMAKE_CURRENT_BINARY_DIR}
                 /usr/local/lib)

include_directories (${PROJECT_SOURCE_DIR}/include
                     /usr/local/include)

add_library(${target} ${LIB_TYPE} ${SOURCES})

target_link_libraries (${target}  amcl_paillier amcl_bls_BLS381 amcl_pairing_BLS381 amcl_curve_BLS381 amcl_curve_SECP256K1 amcl_core)

set_target_properties(${target}
  PROPERTIES VERSION
  ${BUILD_VERSION}
  SOVERSION
  ${VERSION_MAJOR})

install(TARGETS ${target} DESTINATION lib PERMISSIONS
  OWNER_WRITE OWNER_READ OWNER_EXECUTE
  GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE)

if(BUILD_PYTHON)
  message(STATUS "Copy ${target} library to python directory for testing")
  add_custom_command(TARGET ${target} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/lib*" "${PROJECT_BINARY_DIR}/python/test")
  add_custom_command(TARGET ${target} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/lib*" "${PROJECT_BINARY_DIR}/python/benchmark")
  add_custom_command(TARGET ${target} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/lib*" "${PROJECT_BINARY_DIR}/python/examples")  
endif(BUILD_PYTHON)
