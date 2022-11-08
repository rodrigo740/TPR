#!/bin/bash

# build image
docker build -t server:attacker .

# run image
docker run -d -p 2223:6697 --name server server:attacker
