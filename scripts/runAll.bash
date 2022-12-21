#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
    echo "Usage: $ ./runAll.bash test.pcap"
    exit
fi

now=$(date +"%r")
echo "1. Run Packet Sampling at $now"
python3 tlsPktSampling.py -i $1 -o out.dat -f 3 -d 0.1 -c 192.168.1.0/24 -s 0.0.0.0/0

now=$(date +"%r")
echo "2. Run Observation Windows from Packet Sampling at $now"
python3 tlsObsWindows.py -i out.dat -m 2 -w 10 -s 1

now=$(date +"%r")
echo "3. Run Feature Extraction from Observations at $now"
python3 tlsExtractFeatures.py -i out_obs_s1_m2/ -w 10

now=$(date +"%r")
echo "4. Run Extract Features Silence at $now"
python3 tlsExtractFeaturesSilence.py -i out_obs_s1_m2/ -w 10
