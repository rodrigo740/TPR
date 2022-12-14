#!/bin/bash

# build image
docker build -t client:image .

# run image
docker run -d --name client client:image

# to access container:
# docker exec -it client bash