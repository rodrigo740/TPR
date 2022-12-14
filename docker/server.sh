#!/bin/bash

# build image
docker build -t server:image .

# run container in background
docker run -d --name server server:image

# to access container:
# docker exec -it server bash