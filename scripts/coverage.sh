#!/bin/bash
#
# coverage.sh
#
# Generate coverage figures
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES:

CURRENTDIR=${PWD}

function coverage()
{
  echo "coverage"
  cd $CURRENTDIR/target/Coverage
  mkdir coverage
  lcov --capture --initial --directory ./src --output-file coverage/libmpc.info
  lcov --no-checksum --directory ./src --capture --output-file coverage/libmpc.info
  genhtml -o coverage -t "LIBPAILLIER Test Coverage" coverage/libmpc.info
}

coverage
