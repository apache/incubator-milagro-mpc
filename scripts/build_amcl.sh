#!/bin/bash
#
# build_amcl.sh
#
# Build AMCL
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES:

set -Cue -o pipefail

PROJECT_HOME="$(cd "$(dirname "${0}")/.." && pwd)"
cd "$PROJECT_HOME"

git clone https://github.com/apache/incubator-milagro-crypto-c.git

(
    cd incubator-milagro-crypto-c
    mkdir build
    cd build

    cmake -D CMAKE_BUILD_TYPE=Release \
	  -D BUILD_SHARED_LIBS=ON \
          -D DEBUG_NORM=OFF \
          -D AMCL_CHUNK=64 \
          -D AMCL_CURVE="BLS381,SECP256K1" \
          -D BUILD_PAILLIER=ON \
          -D BUILD_PYTHON=OFF \
          -D BUILD_BLS=ON \
          -D BUILD_WCC=OFF \
          -D BUILD_MPIN=OFF \
          -D BUILD_X509=OFF \
          -D CMAKE_INSTALL_PREFIX=/usr/local ..

    make
    make test ARGS=-j8
    sudo make install
)
