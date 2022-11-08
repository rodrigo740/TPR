#!/bin/bash

# build image
docker build -t client:infected .

# run image
docker run -d -p 2222:6697 --name client client:infected
