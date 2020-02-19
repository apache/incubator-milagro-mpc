#!/bin/bash
#
# build.sh
#
# Build all the library configurations
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES:

CURRENTDIR=${PWD}

declare -a arr=("Release" "Debug" "Coverage" "ASan")

for i in "${arr[@]}"
do
  echo "$i"
  cd $CURRENTDIR
  rm -rf target/$i
  mkdir -p target/$i
  cd target/$i
  cmake -D CMAKE_BUILD_TYPE=$i ../..
  make
  if [ $i = Coverage ]
  then
      make test ARGS=-j8
  fi
done
