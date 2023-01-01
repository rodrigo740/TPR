import sys
import argparse
import datetime
from netaddr import IPNetwork, IPAddress, IPSet
import pyshark

class FlowIndex:  # to check which tcp flow a packet belongs to
    def __init__(self, srcPort, dstport):
        self.srcPort = srcPort
        self.dstport = dstport

    def __hash__(self):
        return hash(self.srcPort) + hash(self.dstport)
    
    def __eq__(self, other):
        return (self.srcPort == other.srcPort and self.dstport == other.dstport) or (self.srcPort == other.dstport and self.dstport == other.srcPort)

# flow metadata format:
#   - stream index
#   - srcPort
#   - dstPort
#   - initial flow timestamp
#   - number of inbound bytes
#   - number of outbound bytes
#   - number of inbound packets
#   - number of outbound packets
#   - flow duration
#   - number of supported client tls cipher suites
#   - number of supported client tls extensions
#   - number of supported client tls elliptic curve groups
#   - number of supported client tls elliptic curve point formats
#   - number of supported server tls extensions
flows = {}

def pktHandler(pkt,sampDelta,outfile):
    global scnets
    global ssnets
    global npkts
    global T0
    global outc
    global last_ks

    timestamp,srcIP,dstIP,lengthIP = pkt.sniff_timestamp,pkt.ip.src,pkt.ip.dst,pkt.ip.len

    srcPort = pkt.tcp.srcPort
    dstport = pkt.tcp.dstport
    stream = pkt.tcp.stream

    flowIndex = FlowIndex(srcPort, dstport)
    
    if (IPAddress(srcIP) in scnets and IPAddress(dstIP) in ssnets) or (IPAddress(srcIP) in ssnets and IPAddress(dstIP) in scnets):

        if flowIndex not in flows:
            flows[flowIndex] = [stream, srcPort, dstport, float(timestamp), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        flow = flows[flowIndex]

        if npkts==0:
            T0=float(timestamp)
            last_ks=0
            
        ks=int((float(timestamp)-T0)/sampDelta)
        
        if ks>last_ks:
            outfile.write('{} {} {} {} {} {} {} {} {} {} {} {} {} {} {}\n'.format(last_ks,*flow))
            flow[7] = 0
            flow[5] = 0
            flow[6] = 0
            flow[4] = 0
            
        if ks>last_ks+1:
            for j in range(last_ks+1,ks):
                outfile.write('{} {} {} {} {} {} {} {} {} {} {} {} {} {} {}\n'.format(j,*flow))
            flow[7] = 0
            flow[5] = 0
            flow[6] = 0
            flow[4] = 0
        
        if IPAddress(srcIP) in scnets: #Upload (outbound)
            flow[7] = flow[7] + 1                   # outbound packets
            flow[5] = flow[5] + int(lengthIP)       # outbound bytes

        if IPAddress(dstIP) in scnets: #Download (inbound)
            flow[6] = flow[6] + 1                   # inbound packets
            flow[4] = flow[4] + int(lengthIP)       # inbound bytes

        flow[8] = float(timestamp) - flow[3]        # flow duration

        # tls handshake
        if 'TLS' in str(pkt.layers) and 'handshake' in pkt.tls.field_names:
            if pkt.tls.handshake == 'Handshake Protocol: Client Hello':
                flow[9] = pkt.tls.handshake_cipher_suites_length                    # number of supported client tls cipher suites
                flow[10] = pkt.tls.handshake_extensions_length                      # number of supported client tls extensions
                flow[11] = pkt.tls.handshake_extensions_supported_groups_length     # number of supported client tls elliptic curve groups
                flow[12] = pkt.tls.handshake_extensions_ec_point_formats_length     # number of supported client tls elliptic curve point formats
            elif pkt.tls.handshake == 'Handshake Protocol: Server Hello':
                flow[13] = pkt.tls.handshake_extensions_length                      # number of supported server tls extensions

        last_ks=ks
        npkts=npkts+1


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('-i', '--input', nargs='?',required=True, help='input file')
    parser.add_argument('-o', '--output', nargs='?',required=False, help='output file')
    parser.add_argument('-f', '--format', nargs='?',required=True, help='format',default=1)
    parser.add_argument('-d', '--delta', nargs='?',required=False, help='samplig delta interval')
    parser.add_argument('-c', '--cnet', nargs='+',required=True, help='client network(s)')
    parser.add_argument('-s', '--snet', nargs='+',required=True, help='service network(s)')
    
    args=parser.parse_args()
    
    if args.delta is None:
        sampDelta=1
    else:
        sampDelta=float(args.delta)
    
    cnets=[]
    for n in args.cnet:
        try:
            nn=IPNetwork(n)
            cnets.append(nn)
        except:
            print('{} is not a network prefix'.format(n))
    print("Client networks: " + str(cnets))
    if len(cnets)==0:
        print("No valid client network prefixes.")
        sys.exit()
    global scnets
    scnets=IPSet(cnets)

    snets=[]
    for n in args.snet:
        try:
            nn=IPNetwork(n)
            snets.append(nn)
        except:
            print('{} is not a network prefix'.format(n))
    print("Server networks: " + str(snets))
    if len(snets)==0:
        print("No valid service network prefixes.")
        sys.exit()
        
    global ssnets
    ssnets=IPSet(snets)
        
    fileInput=args.input
    fileFormat=int(args.format)
    
    if args.output is None:
        fileOutput=fileInput+"_d"+str(sampDelta)+".dat"
    else:
        fileOutput=args.output
        
    global npkts
    global T0
    global outc
    global last_ks

    npkts=0
    outc=[0,0,0,0]
    print('Sampling interval: {} second'.format(sampDelta))

    outfile = open(fileOutput,'w') 

    if fileFormat in [1,2]:
        infile = open(fileInput,'r') 
        for line in infile: 
            pktData=line.split()
            if fileFormat==1 and len(pktData)==9: #script format
                timestamp,srcIP,dstIP,lengthIP=pktData[0],pktData[4],pktData[6],pktData[8]
                pktHandler(timestamp,srcIP,dstIP,lengthIP,sampDelta,outfile)
            elif fileFormat==2 and len(pktData)==4: #tshark format "-T fileds -e frame.time_relative -e ip.src -e ip.dst -e ip.len"
                timestamp,srcIP,dstIP,lengthIP=pktData[0],pktData[1],pktData[2],pktData[3]
                pktHandler(timestamp,srcIP,dstIP,lengthIP,sampDelta,outfile)
        infile.close()
    elif fileFormat==3: #pcap format
        capture = pyshark.FileCapture(fileInput,display_filter='tls && tcp') # grab all tls packets
        for pkt in capture:
            pktHandler(pkt,sampDelta,outfile)

    
    outfile.close()

    print("Total TLS packets: " + str(npkts))

if __name__ == '__main__':
    main()
