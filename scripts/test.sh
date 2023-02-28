#!/bin/bash
#
# testAll.sh
#
# Test all the library build configurations
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES:

set -e

CURRENTDIR=${PWD}

declare -a arr=("Release" "Debug" "Coverage" "ASan")

for i in "${arr[@]}"
do
  echo "$i"
  cd $CURRENTDIR
  cd target/$i
  make test ARGS=-j8
done
