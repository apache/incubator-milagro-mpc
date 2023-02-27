# Dockerfile
#
# This is based on the latest Ubuntu LTS
#
# @author  Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------
FROM ubuntu:latest as build

# ------------------------------------------------------------------------------
# NOTES:
#
# Create the image:
#     docker build -t libmpc .
#
#     (or, alternatively, for non-release builds...)
#     docker build --build-arg build_type=Debug -t libmpc-debug .
#     docker build --build-arg build_type=Coverage -t libmpc-coverage .
#
# Run tests:
#     docker run --cap-add SYS_PTRACE --rm libmpc
# 
# Generate coverage figures:
#     docker build --build-arg build_type=Coverage -t libmpc-coverage .
#     docker run --rm libmpc-coverage genhtml coverage/libmpc.info;
#  or...
#     docker run --rm libmpc-coverage /usr/bin/tar c -C /root/build coverage > coverage.tar
#
# To login to container:
#     docker run -it --rm libmpc bash
#
# To build and extract the documentation
#     docker build -t libmpc_doc --build-arg build_doc=true .
#     docker run --rm libmpc_doc /usr/bin/tar c -C /root/build doxygen > doxygen.tar
# ------------------------------------------------------------------------------

# build_type can be one of:
# "Release" "Debug" "Coverage" "ASan"
ARG build_type=Release
# To build doc, pass --build-arg build_doc=true
ARG build_doc=false
# Parallel jobs to run when compiling (make -j)
ARG concurrency=8

LABEL maintainer="kealanmccusker@gmail.com"

WORKDIR /root

ENV build_type=${build_type}
ENV concurrency=${concurrency}

## install packages
RUN apt-get update && \
    apt-get install -y build-essential cmake doxygen lcov python3-dev python3-pip wget git libffi-dev && \
    apt-get clean

RUN pip3 install cffi

# build and install Milagro AMCL
RUN git clone https://github.com/apache/incubator-milagro-crypto-c.git
RUN cd incubator-milagro-crypto-c && \
    mkdir build && \
    cd build && \
    cmake -D CMAKE_BUILD_TYPE=${build_type} \
          -D BUILD_SHARED_LIBS=ON \
          -D AMCL_CHUNK=64 \
          -D AMCL_CURVE="BLS381,SECP256K1" \
          -D AMCL_RSA="" \
          -D BUILD_PAILLIER=ON\
          -D BUILD_PYTHON=ON \
          -D BUILD_BLS=ON \
          -D BUILD_WCC=OFF \
          -D BUILD_MPIN=OFF \
          -D BUILD_X509=OFF \
          -D CMAKE_INSTALL_PREFIX=/usr \
          .. && \
    make -j${concurrency} install

ADD . /root

RUN mkdir build

# Build and install the code
RUN cd build &&\
    cmake -D CMAKE_BUILD_TYPE=$build_type .. &&\
    make -j${concurrency} install

# Generate coverage figures, if needed
RUN if [ "${build_type}" = "Coverage" ]; then \
    cd build; \
    make -j${concurrency} test && \
    mkdir coverage && \
    lcov --capture --initial --directory ./src --output-file coverage/libmpc.info && \
    lcov --no-checksum --directory ./src --capture --output-file coverage/libmpc.info && \
    genhtml -o coverage -t "LIBPAILLIER Test Coverage" coverage/libmpc.info; \
fi

FROM build as documentation

# Build documentation, if requested
RUN if [ ${build_doc} ]; then \
    cd build && \
    make -j${concurrency} doc; \
    fi

WORKDIR /root/build

# Run tests by default
CMD make -j${concurrency} test


