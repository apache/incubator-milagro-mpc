#!/bin/bash
#
# docker.sh
#
# Build library and deploy to docker repository
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES:

function deploy()
{
  echo "Build and deploy docker image"
  echo "872736314692.dkr.ecr.eu-west-1.amazonaws.com/libmpc"
  export VERSION=$(cat VERSION)
  docker build -t libmpc:builder .
  docker tag libmpc:builder 872736314692.dkr.ecr.eu-west-1.amazonaws.com/libmpc:builder
  docker tag libmpc:builder 872736314692.dkr.ecr.eu-west-1.amazonaws.com/libmpc:latest  
  docker tag libmpc:builder 872736314692.dkr.ecr.eu-west-1.amazonaws.com/libmpc:$VERSION  
  echo "Deploy to registry"  
  $(aws ecr get-login --no-include-email --region eu-west-1)
  docker push 872736314692.dkr.ecr.eu-west-1.amazonaws.com/libmpc:builder
  docker push 872736314692.dkr.ecr.eu-west-1.amazonaws.com/libmpc:latest  
  docker push 872736314692.dkr.ecr.eu-west-1.amazonaws.com/libmpc:$VERSION
}

deploy
