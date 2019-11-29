#!/bin/bash
#
# kill.sh
#
# Stop service
#
# @author Kealan McCusker <kealanmccusker@gmail.com>
# ------------------------------------------------------------------------------

# NOTES:

CONTAINER_ID=`docker ps -a | grep libmpc | cut -c1-12`
if [ "${CONTAINER_ID}" ];
then
    echo "docker stop $CONTAINER_ID"
    docker stop $CONTAINER_ID
    docker rm  $CONTAINER_ID
fi


