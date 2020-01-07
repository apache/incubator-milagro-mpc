#!/bin/bash
#
# build.sh
#
# Build api documentation using Sphinx
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES: 
# 

# EXAMPLE USAGE:
# ./build.sh

virtualenv -p python3  --no-site-packages venv
source venv/bin/activate
pip3 install sphinx sphinx-autobuild

cd doc
make html

cp -r build/html/ ..
deactivate
