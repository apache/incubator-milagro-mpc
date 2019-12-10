# Dockerfile
#
# Ubuntu 18.04 (Bionic) 
#
# @author  Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# NOTES:
#
# Create the image:
#     docker build --no-cache -t libmpc .
#
# Run tests:
#     docker run --cap-add SYS_PTRACE --rm libmpc
#
# Generate coverage figures:
#     CONTAINER_ID=$(docker run --cap-add SYS_PTRACE -d libmpc ./scripts/coverage.sh)
#     docker logs $CONTAINER_ID
#     docker cp ${CONTAINER_ID}:"/root/target/Coverage/coverage" ./
#     docker rm -f ${CONTAINER_ID} || true
#
# To login to container:
#     docker run -it --rm libmpc bash
# ------------------------------------------------------------------------------

FROM ubuntu:bionic

MAINTAINER kealanmccusker@gmail.com

WORKDIR /root

ENV LD_LIBRARY_PATH=/usr/local/lib:./

## install packages
RUN apt-get update && \
    apt-get install -y gcc g++ git cmake doxygen autoconf automake libtool curl make unzip wget libssl-dev xsltproc lcov emacs && \
    apt-get clean

# install AMCL
RUN git clone https://github.com/apache/incubator-milagro-crypto-c.git -b issue51 && \
    cd incubator-milagro-crypto-c && \
    git checkout 6b56b35f65469932debc755abc682caa7a3d029b && \
    mkdir build && \
    cd build && \
    cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_SHARED_LIBS=ON -D AMCL_CHUNK=64 -D AMCL_CURVE="" -D AMCL_RSA="2048,4096,8192" -D BUILD_PYTHON=OFF -D BUILD_BLS=OFF -D BUILD_WCC=OFF -D BUILD_MPIN=OFF -D BUILD_X509=OFF -D CMAKE_INSTALL_PREFIX=/usr/local .. && \
    make && \
    make test && \
    make install 

ADD . /root

RUN ./scripts/build.sh

RUN cd ./target/Release && \
    make install

CMD ./scripts/test.sh


