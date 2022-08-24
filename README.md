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

AMCL-MPC - Apache Milagro Crypto Multi-Party Computation Library

This library implements Multi-Party Computation (MPC) using the Apache Milagro crypto library (AMCL).

# Building and running libmpc with Docker (preferred)


The preferred way to get libmpc built and tested is through the use of docker.

Once your docker installation is correctly set-up, simply run:
```
 git clone https://github.com/apache/incubator-milagro-MPC.git && cd incubator-milagro-MPC
```
```
 docker build -t libmpc .
```

If you want to run tests and ensure all routines perform as expected, run:
```
docker run --cap-add SYS_PTRACE --rm libmpc
```

This procedure has been tested on all major platforms (Linux, Mac OS, Windows) on arm64 and x86_64 platforms. If your build or execution fails, please open a bug.

Note that all of the above commands will by default generate an image native to your platform. In case you wish to build and run code for a different platform, use the `--platform linux/amd64` or `--platform linux/arm64` switches (paying a performance hit). For example:
```
docker build --platform linux/amd64 -t libmpc_x86 .
```

In case you run into problems, make sure your docker installation runs fine:
```
docker run hello-world
```
in case you run in permission errors, on some Linux platforms you might need to add your user to the docker group:
```
sudo gpasswd -a <youruser> docker
```

Once this works, you can use this Dockerfile as a base to build your own recipes. We will eventually publish an official OCI image on a registry, if there is sufficient demand (please open an issue).


## Documentation

To build and extract the documentation:
```sh
  docker build -t libmpc_doc --build-arg build_doc=true .
  docker run --rm libmpc_doc /usr/bin/tar c -C /root/build doxygen > doxygen.tar
```

## Testing and generating coverage figures with Docker

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

There is a Python wrapper in `./python`.
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


# Building natively

Sometimes, you will need to build and run libmpc natively. Here's how you do that:

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
git clone https://github.com/apache/incubator-milagro-crypto-c.git 
cd incubator-milagro-crypto-c
mkdir build
cd build
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_SHARED_LIBS=ON -D AMCL_CHUNK=64 -D AMCL_CURVE="BLS381,SECP256K1" -D AMCL_RSA="" -D BUILD_PAILLIER=ON -D BUILD_PYTHON=ON -D BUILD_BLS=ON -D BUILD_WCC=OFF -D BUILD_MPIN=ON -D BUILD_X509=OFF -D CMAKE_INSTALL_PREFIX=/usr/local ..
make
make test
sudo make install
```

## Compiling

Build and test code. 

```sh
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./
mkdir build
cd build
cmake ..
make
make doc
make test
sudo make install
```

or build and run test on all builds

```sh
./scripts/build.sh
./scripts/test.sh
```
