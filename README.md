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

### AMCL

[AMCL](https://github.com/apache/incubator-milagro-crypto-c) is required

Build and install the AMCL library

```sh
./scripts/build_amcl.sh
```

## Compiling

Build and run tests on all builds

```sh
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./
./scripts/build.sh
./scripts/test.sh
```

Install

```sh
cd target/Release
sudo make install
```

## Docker

Build and run tests using docker

```sh
docker build --no-cache -t libmpc .
```

Generate coverage figures

```sh
docker run --rm libmpc ./scripts/coverage.sh
```