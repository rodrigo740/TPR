## 1. Run Packet Sampling

```bash
python3 tlsPktSampling.py -i test.pcap -o out.dat -f 3 -d 0.1 -c 192.168.1.0/24 -s 0.0.0.0/0
```

## 2. Run Observation Windows from Packet Sampling

```bash
python3 tlsObsWindows.py -i out.dat -m 2 -w 10 -s 1
```

## 3. Run Feature Extraction from Observations
```bash
python3 tlsExtractFeatures.py -i out_obs_s1_m2/ -w 10
```
