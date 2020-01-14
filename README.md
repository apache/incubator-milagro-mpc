# libmpc - MPC Crypto library

[![Build Status](https://travis-ci.com/qredo/libmpc.svg?token=7HZyp2nWewcVHbgDxjjg&branch=master)](https://travis-ci.com/qredo/libmpc)

This is a library that implements the MPC

## Dependencies

To correctly build the C library you need to install the following.

```
sudo apt-get update
sudo apt-get install -y gcc g++ git cmake doxygen autoconf automake libtool curl make unzip wget libssl-dev xsltproc lcov emacs
```

### AMCL

[AMCL](https://github.com/apache/incubator-milagro-crypto-c) is required

Build and install the AMCL library

```sh
git clone https://github.com/apache/incubator-milagro-crypto-c.git 
cd incubator-milagro-crypto-c
mkdir build
cd build
cmake -D CMAKE_BUILD_TYPE=Debug -D BUILD_SHARED_LIBS=ON -D AMCL_CHUNK=64 -D AMCL_CURVE="BLS381,SECP256K1" -D AMCL_RSA="" -D BUILD_PAILLIER=ON -D BUILD_PYTHON=ON -D BUILD_BLS=ON -D BUILD_WCC=OFF -D BUILD_MPIN=ON -D BUILD_X509=OFF -D CMAKE_INSTALL_PREFIX=/usr/local ..
make
make test
sudo make install
```

### golang

There is a golang wrapper in the ./go directory

```
wget https://dl.google.com/go/go1.13.linux-amd64.tar.gz
tar -xzf go1.13.linux-amd64.tar.gz
sudo cp -r go /usr/local
export GOROOT=/usr/local/go
export PATH=$PATH:$GOROOT/bin
echo 'GOROOT=/usr/local/go' >> ${HOME}/.bashrc
echo 'export PATH=$PATH:$GOROOT/bin' >> ${HOME}/.bashrc
```

#### configure GO

```
mkdir -p ${HOME}/go/bin 
mkdir -p ${HOME}/go/pkg 
mkdir -p ${HOME}/go/src 
echo 'export GOPATH=${HOME}/go' >> ${HOME}/.bashrc 
echo 'export PATH=$GOPATH/bin:$PATH' >> ${HOME}/.bashrc
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

## Documentation

The documentation is generated using doxygen and can accessed (post build)
via the file

```
./build/doxygen/html/index.html
```

## Docker

Build and run tests using docker

```
docker build --no-cache -t libmpc .
docker run --cap-add SYS_PTRACE --rm libmpc
```

Generate coverage figures

```
docker run --rm libmpc ./scripts/coverage.sh
```

or copy to host

```
CONTAINER_ID=$(docker run --cap-add SYS_PTRACE -d libmpc ./scripts/coverage.sh)
docker logs $CONTAINER_ID
docker cp ${CONTAINER_ID}:"/root/target/Coverage/coverage" ./
docker rm -f ${CONTAINER_ID} || true
```

## Model

There is a model written in Python in ./model

## Virtual machine

In "./vagrant" there are configuration files to run the software on a VM