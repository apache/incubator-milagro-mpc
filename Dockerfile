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

FROM ubuntu:latest

LABEL maintainer="kealanmccusker@gmail.com"

WORKDIR /root

ENV LD_LIBRARY_PATH=/usr/local/lib:./

## install packages
RUN apt-get update && \
    apt-get install -y build-essential cmake doxygen lcov python3-dev python3-pip wget git && \
    apt-get clean

RUN pip3 install cffi

# install AMCL
RUN git clone https://github.com/apache/incubator-milagro-crypto-c.git && \
    cd incubator-milagro-crypto-c && \
    mkdir build && \
    cd build && \
    cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_SHARED_LIBS=ON -D AMCL_CHUNK=64 -D AMCL_CURVE="BLS381,SECP256K1" -D AMCL_RSA="" -D BUILD_PAILLIER=ON -D BUILD_PYTHON=OFF -D BUILD_BLS=ON -D BUILD_WCC=OFF -D BUILD_MPIN=OFF -D BUILD_X509=OFF -D CMAKE_INSTALL_PREFIX=/usr/local .. && \
    make && \
    make test ARGS=-j8 && \
    make install/fast

ADD . /root

RUN ./scripts/build.sh

RUN cd ./target/Release && \
    make -j8 install

CMD ./scripts/test.sh


