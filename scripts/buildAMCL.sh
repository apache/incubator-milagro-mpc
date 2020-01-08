#!/bin/bash
#
# buildAMCL.sh
#
# Build AMCL
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES:

CURRENTDIR=${PWD}

git clone https://github.com/apache/incubator-milagro-crypto-c.git
cd incubator-milagro-crypto-c
git checkout 6b56b35f65469932debc755abc682caa7a3d029b
mkdir build
cd build
cmake -D CMAKE_BUILD_TYPE=Debug -D BUILD_SHARED_LIBS=ON -D AMCL_CHUNK=64 -D AMCL_CURVE="BLS381,SECP256K1" -D AMCL_RSA="" -D BUILD_PAILLIER=ON -D BUILD_PYTHON=OFF -D BUILD_BLS=ON -D BUILD_WCC=OFF -D BUILD_MPIN=OFF -D BUILD_X509=OFF -D CMAKE_INSTALL_PREFIX=/usr/local ..
make
make test
sudo make install
cd $CURRENTDIR
