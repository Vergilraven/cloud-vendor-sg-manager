#!/bin/bash

IMAGE_NAME=""
TAG="v1.0.0"
CONTAINER_NAME="sg_manager"

docker build -f Dockerfile -t ${IMAGE_NAME}:${TAG} .

mkdir -p logs
touch ip-addresses.txt

if [ "$(docker ps -aq -f name=${CONTAINER_NAME})" ]; then
    docker stop ${CONTAINER_NAME}
    docker rm ${CONTAINER_NAME}
fi

docker run -d \
    --name ${CONTAINER_NAME} \
    --restart always \
    -v $(pwd)/configurations:/app/configurations \
    -v $(pwd)/logs:/app/logs \
    -v $(pwd)/ip-addresses.txt:/app/ip-addresses.txt \
    ${IMAGE_NAME}:${TAG}
