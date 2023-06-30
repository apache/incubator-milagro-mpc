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

include_directories (${PROJECT_SOURCE_DIR}/src
                     ${PROJECT_SOURCE_DIR}/include
                     ${PROJECT_SOURCE_DIR}/test
        /usr/local/include)

function(amcl_test name source dependencies expected_response)
  add_executable(${name} "${source}" $<TARGET_OBJECTS:mpc_test_utils>)

  target_link_libraries(${name} PRIVATE ${dependencies})

  add_test(NAME ${name}
    COMMAND ${TARGET_SYSTEM_EMULATOR} $<TARGET_FILE:${name}> ${ARGN}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/testVectors
  )

  set_tests_properties(${name} PROPERTIES
    PASS_REGULAR_EXPRESSION "${expected_response}"
  )
endfunction()


 # Classic Schnorr tests
 amcl_test(test_schnorr_commit    test_schnorr_commit.c    amcl_mpc "SUCCESS" "schnorr/commit.txt")
 amcl_test(test_schnorr_challenge test_schnorr_challenge.c amcl_mpc "SUCCESS" "schnorr/challenge.txt")
 amcl_test(test_schnorr_prove     test_schnorr_prove.c     amcl_mpc "SUCCESS" "schnorr/prove.txt")
 amcl_test(test_schnorr_verify    test_schnorr_verify.c    amcl_mpc "SUCCESS" "schnorr/verify.txt")

 # Double Schnorr tests
 amcl_test(test_d_schnorr_commit    test_d_schnorr_commit.c    amcl_mpc "SUCCESS" "schnorr/dcommit.txt")
 amcl_test(test_d_schnorr_challenge test_d_schnorr_challenge.c amcl_mpc "SUCCESS" "schnorr/dchallenge.txt")
 amcl_test(test_d_schnorr_prove     test_d_schnorr_prove.c     amcl_mpc "SUCCESS" "schnorr/dprove.txt")
 amcl_test(test_d_schnorr_verify    test_d_schnorr_verify.c    amcl_mpc "SUCCESS" "schnorr/dverify.txt")

 # Hidden DLOG tests
 amcl_test(test_hidden_dlog_commit    test_hidden_dlog_commit.c    amcl_mpc "SUCCESS" "hidden_dlog/commit.txt")
 amcl_test(test_hidden_dlog_challenge test_hidden_dlog_challenge.c amcl_mpc "SUCCESS" "hidden_dlog/challenge.txt")
 amcl_test(test_hidden_dlog_prove     test_hidden_dlog_prove.c     amcl_mpc "SUCCESS" "hidden_dlog/prove.txt")
 amcl_test(test_hidden_dlog_verify    test_hidden_dlog_verify.c    amcl_mpc "SUCCESS" "hidden_dlog/verify.txt")

 # Shamir Secret Sharing
 amcl_test(test_shamir             test_shamir.c             amcl_mpc "SUCCESS" "shamir/SSS.txt")
 amcl_test(test_shamir_to_additive test_shamir_to_additive.c amcl_mpc "SUCCESS" "shamir/STA.txt")
 amcl_test(test_vss                test_vss.c                amcl_mpc "SUCCESS" "shamir/VSS.txt")
