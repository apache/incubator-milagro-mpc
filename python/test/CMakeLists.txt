# Licensed to the Apache Software Foundation (ASF) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  The ASF licenses this
# file to you under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

# Set the LD_LIBRARY_PATH or equivalent to the libraries can be loaded when
# running the test.
if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  set(ld_library_path_var "DYLD_LIBRARY_PATH")
elseif(CMAKE_SYSTEM_NAME MATCHES "Linux")
  set(ld_library_path_var "LD_LIBRARY_PATH")
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
  set(ld_library_path_var "PATH")
endif()

# Prepend the env dynamic library path with the mpc path
set(dynamic_library_path ${PROJECT_BINARY_DIR}/src:$ENV{${ld_library_path_var}})

function(add_python_test name source)
  add_test(${name} python3 ${source})

  set_tests_properties(${name} PROPERTIES ENVIRONMENT "${ld_library_path_var}=${dynamic_library_path}")
endfunction()

# Tests
file(GLOB TESTS *.py)
file(COPY ${TESTS} DESTINATION "${PROJECT_BINARY_DIR}/python/test")

# MPC test vectors
file(GLOB MPC_TV "${PROJECT_SOURCE_DIR}/testVectors/mpc/*.json")
file(COPY ${MPC_TV} DESTINATION "${PROJECT_BINARY_DIR}/python/test/mpc/")

# Schnorr test vectors
file(GLOB SCHNORR_TV "${PROJECT_SOURCE_DIR}/testVectors/schnorr/*.json")
file(COPY ${SCHNORR_TV} DESTINATION "${PROJECT_BINARY_DIR}/python/test/schnorr/")

# NM Commitment test vector
file(
  COPY ${PROJECT_SOURCE_DIR}/testVectors/commitments/nm_commit.json
  DESTINATION "${PROJECT_BINARY_DIR}/python/test/commitments/")

# ZK Factoring test vectors
file(GLOB SCHNORR_TV "${PROJECT_SOURCE_DIR}/testVectors/factoring_zk/*.json")
file(COPY ${SCHNORR_TV} DESTINATION "${PROJECT_BINARY_DIR}/python/test/factoring_zk/")

# GCM test vectors
file(GLOB GCM_TV "${PROJECT_SOURCE_DIR}/testVectors/gcm/*.json")
file(COPY ${GCM_TV} DESTINATION "${PROJECT_BINARY_DIR}/python/test/gcm/")

if(NOT CMAKE_BUILD_TYPE STREQUAL "ASan")
  add_python_test(test_python_aes              test_aes.py)
  add_python_test(test_python_mpc_mta          test_mta.py)
  add_python_test(test_python_mpc_r            test_r.py)
  add_python_test(test_python_mpc_s            test_s.py)
  add_python_test(test_python_mpc_ecdsa        test_ecdsa.py)
  add_python_test(test_python_mpc_schnorr      test_schnorr.py)
  add_python_test(test_python_mpc_nm_commit    test_nm_commit.py)
  add_python_test(test_python_mpc_zk_factoring test_zk_factoring.py)
endif(NOT CMAKE_BUILD_TYPE STREQUAL "ASan")

foreach(level ${PYTHON_RSA_LEVELS})
  load_rsa_fields(${level})
  configure_rsa_file("test_rsa.py.in" "${PROJECT_BINARY_DIR}/python/test/test_rsa_${TFF}.py")

  add_python_test(test_python_rsa_${TFF} test_rsa_${TFF}.py)
endforeach()
