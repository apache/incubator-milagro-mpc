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

cmake_minimum_required(VERSION 3.1 FATAL_ERROR)

include(PythonSiteDirs)

install(FILES amcl_mpc.py DESTINATION ${PYTHON_SITE_PACKAGES})

file(COPY amcl_mpc.py DESTINATION "${PROJECT_BINARY_DIR}/python/")
file(COPY test_mta.py DESTINATION "${PROJECT_BINARY_DIR}/python/")
file(COPY test_r.py DESTINATION "${PROJECT_BINARY_DIR}/python/")
file(COPY test_s.py DESTINATION "${PROJECT_BINARY_DIR}/python/")
file(COPY test_ecdsa.py DESTINATION "${PROJECT_BINARY_DIR}/python/")

file(COPY "${PROJECT_SOURCE_DIR}/testVectors/mpc/MTA.json" DESTINATION "${PROJECT_BINARY_DIR}/python/")
file(COPY "${PROJECT_SOURCE_DIR}/testVectors/mpc/R.json" DESTINATION "${PROJECT_BINARY_DIR}/python/")
file(COPY "${PROJECT_SOURCE_DIR}/testVectors/mpc/S.json" DESTINATION "${PROJECT_BINARY_DIR}/python/")

if(NOT CMAKE_BUILD_TYPE STREQUAL "ASan")
  add_test(test_python_mpc_mta python3 test_mta.py)
  add_test(test_python_mpc_r python3 test_r.py)
  add_test(test_python_mpc_s python3 test_s.py)
  add_test(test_python_mpc_ecdsa python3 test_ecdsa.py)
endif(NOT CMAKE_BUILD_TYPE STREQUAL "ASan")

# Set the LD_LIBRARY_PATH or equivalent to the libraries can be loaded when
# running the test.
#if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
#  set(ld_library_path_var "DYLD_LIBRARY_PATH")
#elseif(CMAKE_SYSTEM_NAME MATCHES "Linux")
#  set(ld_library_path_var "LD_LIBRARY_PATH")
#elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
#  set(ld_library_path_var "PATH")
#endif()
#set_tests_properties(test_python_mpc_mta PROPERTIES ENVIRONMENT
#             "${ld_library_path_var}=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")

