#!/bin/bash

IMAGE_NAME=""
TAG="1.0.1"
CONTAINER_NAME="sg_manager"

docker rmi ${IMAGE_NAME}:${TAG}
docker pull ${IMAGE_NAME}:${TAG}

docker run -d \
    --name ${CONTAINER_NAME} \
    --restart always \
    -v $(pwd)/configurations:/app/configurations \
    -v $(pwd)/logs:/app/logs \
    ${IMAGE_NAME}:${TAG}