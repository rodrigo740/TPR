#!/bin/bash

# build image
docker build -t client:infected .

# run image
docker run -d --name client client:infected
