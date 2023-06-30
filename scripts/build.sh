#!/bin/bash
#
# build.sh
#
# Build all the library configurations
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES:

set -Cue -o pipefail

PROJECT_HOME="$(cd "$(dirname "${0}")/.." && pwd)"
cd "$PROJECT_HOME"

declare -a arr=("Release" "Debug" "Coverage" "ASan")

for i in "${arr[@]}"
do
    (
	echo "$i"
	rm -rf target/$i
	mkdir -p target/$i
	cd target/$i
	cmake -D CMAKE_BUILD_TYPE=$i ../..
	make
    )
done
