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

# MPC tests
amcl_test(test_mta           test_mta.c           amcl_mpc "SUCCESS" "mpc/MTA.txt")
amcl_test(test_r             test_r.c             amcl_mpc "SUCCESS" "mpc/R.txt")
amcl_test(test_s             test_s.c             amcl_mpc "SUCCESS" "mpc/S.txt")

# NM Commitment tests
amcl_test(test_nm_commit test_nm_commit.c amcl_mpc "SUCCESS" "nm_commitment/commit.txt")

# GMR ZKP of Square Freeness
amcl_test(test_gmr_prove  test_gmr_prove.c  amcl_mpc "SUCCESS" "gmr/prove.txt")
amcl_test(test_gmr_verify test_gmr_verify.c amcl_mpc "SUCCESS" "gmr/verify.txt")
amcl_test(test_gmr_octets test_gmr_octets.c amcl_mpc "SUCCESS" "gmr/verify.txt")

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

# BC Commitment tests
amcl_test(test_bit_commitment_setup           test_bit_commitment_setup.c           amcl_mpc "SUCCESS" "bit_commitment/setup.txt")
amcl_test(test_bit_commitment_setup_internals test_bit_commitment_setup_internals.c amcl_mpc "SUCCESS")

amcl_test(test_bit_commitment_ecp_commit test_bit_commitment_ecp_commit.c amcl_mpc "SUCCESS" "bit_commitment/ecp_commit.txt")
amcl_test(test_bit_commitment_ecp_verify test_bit_commitment_ecp_verify.c amcl_mpc "SUCCESS" "bit_commitment/ecp_verify.txt")

amcl_test(test_bit_commitment_commit test_bit_commitment_commit.c amcl_mpc "SUCCESS" "bit_commitment/plain_commit.txt")
amcl_test(test_bit_commitment_prove  test_bit_commitment_prove.c  amcl_mpc "SUCCESS" "bit_commitment/plain_prove.txt")
amcl_test(test_bit_commitment_verify test_bit_commitment_verify.c amcl_mpc "SUCCESS" "bit_commitment/plain_verify.txt")
amcl_test(test_bit_commitment_octets test_bit_commitment_octets.c amcl_mpc "SUCCESS" "bit_commitment/plain_octets.txt")

amcl_test(test_bit_commitment_muladd_commit test_bit_commitment_muladd_commit.c amcl_mpc "SUCCESS" "bit_commitment/muladd_commit.txt")
amcl_test(test_bit_commitment_muladd_prove  test_bit_commitment_muladd_prove.c  amcl_mpc "SUCCESS" "bit_commitment/muladd_prove.txt")
amcl_test(test_bit_commitment_muladd_verify test_bit_commitment_muladd_verify.c amcl_mpc "SUCCESS" "bit_commitment/muladd_verify.txt")
amcl_test(test_bit_commitment_muladd_octets test_bit_commitment_muladd_octets.c amcl_mpc "SUCCESS" "bit_commitment/muladd_octets.txt")

# Hidden DLOG tests
amcl_test(test_hidden_dlog_commit    test_hidden_dlog_commit.c    amcl_mpc "SUCCESS" "hidden_dlog/commit.txt")
amcl_test(test_hidden_dlog_challenge test_hidden_dlog_challenge.c amcl_mpc "SUCCESS" "hidden_dlog/challenge.txt")
amcl_test(test_hidden_dlog_prove     test_hidden_dlog_prove.c     amcl_mpc "SUCCESS" "hidden_dlog/prove.txt")
amcl_test(test_hidden_dlog_verify    test_hidden_dlog_verify.c    amcl_mpc "SUCCESS" "hidden_dlog/verify.txt")

# MTA ZKPs tests
amcl_test(test_mta_rp   test_mta_rp.c   amcl_mpc "SUCCESS" "mta_zkp/rp_challenge.txt")
amcl_test(test_mta_zk   test_mta_zk.c   amcl_mpc "SUCCESS" "mta_zkp/mta_challenge.txt")
amcl_test(test_mta_zkwc test_mta_zkwc.c amcl_mpc "SUCCESS" "mta_zkp/mtawc_challenge.txt")

# GGN tests
amcl_test(test_ggn test_ggn.c amcl_mpc "SUCCESS" "ggn/challenge.txt")

# GG20 ZKPs tests
amcl_test(test_gg20_zkp_generator test_gg20_zkp_generator.c amcl_mpc "SUCCESS")

amcl_test(test_gg20_zkp_octets test_gg20_zkp_octets.c amcl_mpc "SUCCESS" "gg20_zkp/octets.txt")

amcl_test(test_gg20_zkp_phase3_commit    test_gg20_zkp_phase3_commit.c    amcl_mpc "SUCCESS" "gg20_zkp/phase3_commit.txt")
amcl_test(test_gg20_zkp_phase3_challenge test_gg20_zkp_phase3_challenge.c amcl_mpc "SUCCESS" "gg20_zkp/phase3_challenge.txt")
amcl_test(test_gg20_zkp_phase3_prove     test_gg20_zkp_phase3_prove.c     amcl_mpc "SUCCESS" "gg20_zkp/phase3_prove.txt")
amcl_test(test_gg20_zkp_phase3_verify    test_gg20_zkp_phase3_verify.c    amcl_mpc "SUCCESS" "gg20_zkp/phase3_verify.txt")

amcl_test(test_gg20_zkp_phase6_commit    test_gg20_zkp_phase6_commit.c    amcl_mpc "SUCCESS" "gg20_zkp/phase6_commit.txt")
amcl_test(test_gg20_zkp_phase6_challenge test_gg20_zkp_phase6_challenge.c amcl_mpc "SUCCESS" "gg20_zkp/phase6_challenge.txt")
amcl_test(test_gg20_zkp_phase6_prove     test_gg20_zkp_phase6_prove.c     amcl_mpc "SUCCESS" "gg20_zkp/phase6_prove.txt")
amcl_test(test_gg20_zkp_phase6_verify    test_gg20_zkp_phase6_verify.c    amcl_mpc "SUCCESS" "gg20_zkp/phase6_verify.txt")

# Shamir Secret Sharing
amcl_test(test_shamir             test_shamir.c             amcl_mpc "SUCCESS" "shamir/SSS.txt")
amcl_test(test_shamir_to_additive test_shamir_to_additive.c amcl_mpc "SUCCESS" "shamir/STA.txt")
amcl_test(test_vss                test_vss.c                amcl_mpc "SUCCESS" "shamir/VSS.txt")
