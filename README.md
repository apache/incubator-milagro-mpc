<!--
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
-->

# *Apache Milagro Multi-Party Computation Library*

[![Master Branch](https://img.shields.io/badge/-master:-gray.svg)](https://github.com/apache/incubator-milagro-MPC/tree/master)
[![Master Build Status](https://travis-ci.org/apache/incubator-milagro-MPC.svg?branch=master)](https://travis-ci.org/apache/incubator-milagro-MPC)
[![Master Coverage Status](https://coveralls.io/repos/github/apache/incubator-milagro-MPC/badge.svg?branch=master)](https://coveralls.io/github/apache/incubator-milagro-MPC?branch=master)

[![Develop Branch](https://img.shields.io/badge/-develop:-gray.svg)](https://github.com/apache/incubator-milagro-MPC/tree/develop)
[![Develop Build Status](https://travis-ci.org/apache/incubator-milagro-MPC.svg?branch=develop)](https://travis-ci.org/apache/incubator-milagro-MPC)
[![Develop Coverage Status](https://coveralls.io/repos/github/apache/incubator-milagro-MPC/badge.svg?branch=develop)](https://coveralls.io/github/apache/incubator-milagro-MPC?branch=develop)

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=apache_incubator-milagro-MPC&metric=alert_status)](https://sonarcloud.io/dashboard?id=apache_incubator-milagro-MPC)

* **category**:    Library
* **copyright**:   2020 The Apache Software Foundation
* **license**:     ASL 2.0 ([Apache License Version 2.0, January 2004](http://www.apache.org/licenses/LICENSE-2.0))
* **link**:        https://github.com/apache/incubator-milagro-MPC

## Description

*AMCL - Apache Milagro Crypto Multi-Party Computation*

This library implements Multi-Party Computation (MPC) using the milargo crypto library.

## Dependencies

In order to build this library, the following packages are required:

* [CMake](https://cmake.org/) is required to build the source code.
* [CFFI](https://cffi.readthedocs.org/en/release-0.8/), the C Foreign Function Interface for the Python wrapper
* [Doxygen](http://doxygen.org) is required to build the source code documentation.
* [Python](https://www.python.org/) language is required to build the Python language wrapper.

On Ubuntu 18.04 these packages are installed with the following commands;

```
sudo apt-get update
sudo apt-get install -y build-essential cmake doxygen lcov python3-dev python3-pip wget git
pip3 install cffi
```

### AMCL

[AMCL](https://github.com/apache/incubator-milagro-crypto-c) is required

Build and install the AMCL library

```sh
./scripts/buildAMCL.sh
```

## Compiling

Build and test code.

```sh
./scripts/build.sh
./scripts/test.sh
```

## Documentation

The documentation is generated using doxygen and can accessed (post build)
via the file

```
./build/doxygen/html/index.html
```

## Docker

Build and run tests using docker

```sh
docker build --no-cache -t libmpc .
docker run --cap-add SYS_PTRACE --rm libmpc
```

Generate coverage figures

```sh
docker run --rm libmpc ./scripts/coverage.sh
```

or copy to host

```sh
CONTAINER_ID=$(docker run --cap-add SYS_PTRACE -d libmpc ./scripts/coverage.sh)
docker logs $CONTAINER_ID
docker cp ${CONTAINER_ID}:"/root/target/Coverage/coverage" ./
docker rm -f ${CONTAINER_ID} || true
```

## Python

There is a Python wrapper in ./python.
You can to specify the RSA levels to build in the wrappers using
the cmake flag `PYTHON_RSA_LEVELS`. Supported levels are 2048 and 4096.
E.g.

```
cmake -DPYTHON_RSA_LEVELS="2048,4096" ..
```

In order for the RSA wrappers to work, the appropriate dynamic
libraries need to be generated and installed for AMCL. For instance, to
install the dynamic libraries for RSA 2048 and 4069, modify the AMCL cmake
build as follows.

```
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_SHARED_LIBS=ON -D AMCL_CHUNK=64 -D AMCL_CURVE="BLS381,SECP256K1" -D AMCL_RSA="2048,4096" -D BUILD_PAILLIER=ON -D BUILD_PYTHON=ON -D BUILD_BLS=ON -D BUILD_WCC=OFF -D BUILD_MPIN=ON -D BUILD_X509=OFF -D CMAKE_INSTALL_PREFIX=/usr/local ..
```

## Virtual machine

In "./vagrant" there are configuration files to run the software on a VM