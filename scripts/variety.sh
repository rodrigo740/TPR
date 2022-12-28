#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
    echo "Usage: $ ./runAll.bash test.pcap"
    exit
fi

INPUT=params.csv
OLDIFS=$IFS
IFS=','

[ ! -f $INPUT ] && { echo "$INPUT file not found"; exit 99; }
while read sampling width sliding
do
    now=$(date +"%r")
    echo "1. Run Packet Sampling at $now"
    python3 tlsPktSampling.py -i $1 -o out.dat -f 3 -d $sampling -c 0.0.0.0/0 -s 0.0.0.0/0

    now=$(date +"%r")
    echo "2. Run Observation Windows from Packet Sampling at $now"
    python3 tlsObsWindows.py -i out.dat -m 2 -w $width -s $sliding

    now=$(date +"%r")
    echo "3. Run Feature Extraction from Observations at $now"
    python3 tlsExtractFeatures.py -i "out_obs_s"$sliding"_m2/" -w $width

    now=$(date +"%r")
    echo "4. Run Extract Features Silence at $now"
    python3 tlsExtractFeaturesSilence.py -i "out_obs_s"$sliding"_m2/" -w $width

    #################################################################################

    rm -r "out_obs_s"$sliding"_m2/"

    #################################################################################

    now=$(date +"%r")
    echo "1. Run Packet Sampling at $now"
    python3 tlsPktSampling.py -i attack.pcap -o out.dat -f 3 -d $sampling -c 0.0.0.0/0 -s 0.0.0.0/0

    now=$(date +"%r")
    echo "2. Run Observation Windows from Packet Sampling at $now"
    python3 tlsObsWindows.py -i out.dat -m 2 -w $width -s $sliding

    now=$(date +"%r")
    echo "3. Run Feature Extraction from Observations at $now"
    python3 tlsExtractFeatures.py -i "out_obs_s"$sliding"_m2/" -w $width

    now=$(date +"%r")
    echo "4. Run Extract Features Silence at $now"
    python3 tlsExtractFeaturesSilence.py -i "out_obs_s"$sliding"_m2/" -w $width

    python3 tlsProfile.py

     rm -r "out_obs_s"$sliding"_m2/"
done < $INPUT
IFS=$OLDIFS
