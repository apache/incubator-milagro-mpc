#!/usr/bin/env bash

echo "install packages"
sudo apt-get update
sudo apt-get install -y build-essential cmake doxygen lcov python3-dev python3-pip wget git emacs
sudo apt-get clean

## docker
sudo groupadd docker
sudo usermod -aG docker $USER
groups $USER
sudo snap install docker
# You will also need to re-enter the session for the group update to take place
# su - $USER
# Above command will not work as do not know password. Instead do these commands.
# vagrant halt
# vagrant up

#docker info

# install AMCL
git clone https://github.com/apache/incubator-milagro-crypto-c.git
cd incubator-milagro-crypto-c
mkdir build
cd build
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_SHARED_LIBS=ON -D AMCL_CHUNK=64 -D AMCL_CURVE="SECP256K1" -D AMCL_RSA="" -D BUILD_PAILLIER=ON -D BUILD_PYTHON=ON -D BUILD_BLS=ON -D BUILD_WCC=OFF -D BUILD_MPIN=OFF -D BUILD_X509=OFF -D CMAKE_INSTALL_PREFIX=/usr/local ..
make
make test
sudo make install

# intall libmpc
git clone https://github.com/apache/incubator-milagro-MPC.git
cd incubator-milagro-MPC
mkdir build
cd build
cmake -D CMAKE_INSTALL_PREFIX=/usr/local ..
make
make test
sudo make install
