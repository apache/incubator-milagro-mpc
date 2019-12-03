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

# Add the binary tree directory to the search path for linking and include files
link_directories (${PROJECT_BINARY_DIR}/src
                  /usr/local/lib)

include_directories (${PROJECT_SOURCE_DIR}/include
                     /usr/local/include)

function(amcl_test name source dependencies expected_response)
  add_executable(${name} "${source}")

  target_link_libraries(${name} PRIVATE ${dependencies})

  add_test(NAME ${name}
    COMMAND ${TARGET_SYSTEM_EMULATOR} $<TARGET_FILE:${name}> ${ARGN}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/testVectors
  )

  set_tests_properties(${name} PROPERTIES
    PASS_REGULAR_EXPRESSION "${expected_response}"
  )
endfunction()

amcl_test(test_mta test_mta.c mpc "SUCCESS" "mpc/MTA.txt")


