#!/bin/bash

# build image
docker build -t server:attacker .

# run image
docker run -d --name server server:attacker
