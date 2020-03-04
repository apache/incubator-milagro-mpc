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

set(PYTHON_RSA_FIELDS TB   TFF  BASE ML HML)
set(PYTHON_RSA_2048   1024 2048 58   2  1  )
set(PYTHON_RSA_4096   512  4096 60   8  4  )

# Load RSA parameter in parent scope
function(load_rsa_fields level)
  if (NOT PYTHON_RSA_${level})
    message(FATAL_ERROR "Invalid RSA level: ${level}")
  endif()
  
  foreach(field ${PYTHON_RSA_FIELDS})
    list(FIND PYTHON_RSA_FIELDS "${field}" index)
    list(GET  PYTHON_RSA_${level} ${index} ${field})
    set("${field}" "${${field}}" PARENT_SCOPE)
  endforeach()

  set(BD "${TB}_${BASE}" PARENT_SCOPE)
endfunction()

# Configure file
macro(configure_rsa_file source target)
  configure_file("${source}" "${target}" @ONLY)
  file(READ "${target}" temp)
  string(REPLACE WWW "${TFF}" temp "${temp}")
  string(REPLACE XXX "${BD}"  temp "${temp}")

  file(WRITE "${target}" "${temp}")
endmacro()