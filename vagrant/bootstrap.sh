#!/usr/bin/env bash

echo "install packages"
sudo apt-get update
sudo apt-get install -y gcc g++ git cmake doxygen autoconf automake libtool curl make unzip wget libssl-dev xsltproc lcov emacs
sudo apt-get clean

echo "install docker"
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update && sudo apt-get install apt-transport-https ca-certificates curl software-properties-common docker-ce -y
sudo apt-get update && sudo apt-get install docker-ce -y
sudo curl -L https://github.com/docker/compose/releases/download/1.17.0/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
sudo usermod -aG docker vagrant

# install AMCL
git clone https://github.com/apache/incubator-milagro-crypto-c.git
cd incubator-milagro-crypto-c
mkdir build
cd build
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_SHARED_LIBS=ON -D AMCL_CHUNK=64 -D AMCL_CURVE="" -D AMCL_RSA="2048,4096,8192" -D BUILD_PYTHON=OFF -D BUILD_BLS=OFF -D BUILD_WCC=OFF -D BUILD_MPIN=OFF -D BUILD_X509=OFF -D CMAKE_INSTALL_PREFIX=/usr/local .. 
make
make test
sudo make install

