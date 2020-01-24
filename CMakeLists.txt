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

cmake_minimum_required (VERSION 3.1 FATAL_ERROR)
project (libmpc)

# Helper Macros
macro(log var)
  message(STATUS "${var}: ${${var}}")
endmacro()

add_definitions(-D CMAKE)

# Includes
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(CMakeDependentOption)
include(CTest)
include(GNUInstallDirs)

# Extract version from the VERSION file
file(STRINGS VERSION VERSION_FILE_CONTENT)
string(REPLACE "." ";" VERSION_FILE_PARTS ${VERSION_FILE_CONTENT})
list(GET VERSION_FILE_PARTS 0 VERSION_MAJOR)
list(GET VERSION_FILE_PARTS 1 VERSION_MINOR)
list(GET VERSION_FILE_PARTS 2 VERSION_PATCH)
set(BUILD_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
log(BUILD_VERSION)
log(CMAKE_GENERATOR)

# Add options for build
option(BUILD_DOXYGEN "Build Doxygen" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_TESTS "Build tests" ON)
option(BUILD_EXAMPLES "Build examples" ON)
option(BUILD_BENCHMARK "Build benchmark" ON)
cmake_dependent_option(BUILD_PYTHON "Build Python" ON "BUILD_SHARED_LIBS" ON)
log(BUILD_DOXYGEN)
log(BUILD_SHARED_LIBS)
log(BUILD_TESTS)
log(BUILD_EXAMPLES)
log(BUILD_BENCHMARK)
log(BUILD_PYTHON)

# Allow the developer to select if Dynamic or Static libraries are built
# Set the default LIB_TYPE variable to STATIC
SET (LIB_TYPE STATIC)
IF (BUILD_SHARED_LIBS)
  # User wants to build Dynamic Libraries, so change the LIB_TYPE variable to CMake keyword 'SHARED'
  SET (LIB_TYPE SHARED)
ENDIF (BUILD_SHARED_LIBS)

# Configure build
set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
    CACHE STRING "Choose the type of build: Debug Release Coverage ASan"
    FORCE)

# Set a default build type if none was specified
if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to 'Release' as none was specified.")
  set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)
log(CMAKE_BUILD_TYPE)

if(CMAKE_COMPILER_IS_GNUCC)
    execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion
                    OUTPUT_VARIABLE GCC_VERSION)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -Wextra -Wno-strict-prototypes -Wunused-value -Wcast-align -Wunused-variable -Wundef -Wformat-security -Wno-pointer-sign -Wno-unknown-pragmas")

    if (GCC_VERSION VERSION_GREATER 4.8 OR GCC_VERSION VERSION_EQUAL 4.8)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow")
        set(CMAKE_C_FLAGS_ASAN    "-O0 -g3 -fsanitize=address")
    else (GCC_VERSION VERSION_GREATER 4.8 OR GCC_VERSION VERSION_EQUAL 4.8)
        message(STATUS "GCC 4.8 required to run address sanitizer - please upgrade your installation")
    endif(GCC_VERSION VERSION_GREATER 4.8 OR GCC_VERSION VERSION_EQUAL 4.8)

    IF (BUILD_SHARED_LIBS)
        set(CMAKE_C_FLAGS_RELEASE     "-O2")
        set(CMAKE_C_FLAGS_DEBUG       "-O0 -g3 -D DEBUG")
        set(CMAKE_C_FLAGS_COVERAGE    "-O0 -g3 --coverage")
    else(BUILD_SHARED_LIBS)
        set(CMAKE_C_FLAGS_RELEASE     "-static -O2")
        set(CMAKE_C_FLAGS_DEBUG       "-static -O0 -g3 -D DEBUG")
        set(CMAKE_C_FLAGS_COVERAGE    "-static -O0 -g3 --coverage")
    endif(BUILD_SHARED_LIBS)

endif(CMAKE_COMPILER_IS_GNUCC)

if(CMAKE_BUILD_TYPE STREQUAL "Coverage")
    set(CMAKE_SHARED_LINKER_FLAGS "--coverage")
endif(CMAKE_BUILD_TYPE STREQUAL "Coverage")

log(CMAKE_INSTALL_PREFIX)

# /include subdir
set(INSTALL_INCLUDESUBDIR "${CMAKE_INSTALL_INCLUDEDIR}/amcl")
log(CMAKE_INSTALL_INCLUDEDIR)
log(INSTALL_INCLUDESUBDIR)

# Add subdirectories
add_subdirectory(include)
add_subdirectory(src)

if(BUILD_EXAMPLES)
  message(STATUS "Build examples")
  add_subdirectory(examples)
endif()

if(BUILD_TESTS)
  message(STATUS "Build tests")
  add_subdirectory(test)
endif()

if(BUILD_BENCHMARK)
  message(STATUS "Build benchmark")
  add_subdirectory(benchmark)
endif()

if(BUILD_PYTHON)
  message(STATUS "Build Python wrappers")
  add_subdirectory(python)
endif()

# Build Documentation
if (BUILD_DOXYGEN)
  find_package(Doxygen QUIET)
  if(DOXYGEN_FOUND)
    add_subdirectory (doxygen)
  else(DOXYGEN_FOUND)
    message(STATUS "Doxygen not found. Documentation will not be built.")
  endif(DOXYGEN_FOUND)
endif (BUILD_DOXYGEN)

# uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

include(CPackConfig.cmake)

