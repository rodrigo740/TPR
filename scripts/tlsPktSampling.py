import sys
import argparse
import datetime
from netaddr import IPNetwork, IPAddress, IPSet
import pyshark

# tls flow metadata format:
#   - stream index
#   - srcIP
#   - dstIP
#   - srcPort
#   - dstPort
#   - initial flow timestamp
#   - flow duration
#   - flow ended flag
#   - number of inbound bytes
#   - number of outbound bytes
#   - number of inbound packets
#   - number of outbound packets
#   - number of tcp packets
#   - number of tls packets
#   - number of supported client tls cipher suites
#   - number of supported client tls extensions
#   - number of supported client tls elliptic curve groups
#   - number of supported client tls elliptic curve point formats
#   - number of supported server tls extensions
class TLSFlow:
    def __init__(self, stream, srcIP, dstIP, srcPort, dstport):
        self.stream = stream
        self.srcIP = srcIP
        self.dstIP = dstIP
        self.srcPort = srcPort
        self.dstPort = dstport
        self.start_time = 0
        self.duration = 0
        self.endFlags = 0
        self.inbound_byte_count = 0
        self.outbound_byte_count = 0
        self.inbound_packet_count = 0
        self.outbound_packet_count = 0
        self.tcp_packet_count = 0
        self.tls_packet_count = 0
        self.tls_client_cipher_suite_count = 0
        self.tls_client_extension_count = 0
        self.tls_client_elliptic_curve_group_count = 0
        self.tls_client_elliptic_curve_point_format_count = 0
        self.tls_server_extension_count = 0

    def __hash__(self):
        return hash(self.srcIP) + hash(self.dstIP) + hash(self.srcPort) + hash(self.dstPort)
    
    def __eq__(self, other):
        return ((self.srcIP == other.srcIP and self.dstIP == other.dstIP) or (self.srcIP == other.dstIP and self.dstIP == other.srcIP)) and \
            ((self.srcPort == other.srcPort and self.dstPort == other.dstPort) or (self.srcPort == other.dstPort and self.dstPort == other.srcPort))

flows = {}

def clear_flow(flow):
    flows[flow].outbound_packet_count = 0
    flows[flow].outbound_byte_count = 0
    flows[flow].inbound_packet_count = 0
    flows[flow].inbound_byte_count = 0
    flows[flow].tcp_packet_count = 0
    flows[flow].tls_packet_count = 0

def extract_metrics(outfile, flow):
    outfile.write('{} {} {} {} {} {} {} {} {} {} {} {}\n'.format(
                    flows[flow].duration,                                               # 0
                    flows[flow].inbound_byte_count,                                     # 1
                    flows[flow].outbound_byte_count,                                    # 2
                    flows[flow].inbound_packet_count,                                   # 3
                    flows[flow].outbound_packet_count,                                  # 4
                    flows[flow].tcp_packet_count,                                       # 5
                    flows[flow].tls_packet_count,                                       # 6
                    flows[flow].tls_client_cipher_suite_count,                          # 7
                    flows[flow].tls_client_extension_count,                             # 8
                    flows[flow].tls_client_elliptic_curve_group_count,                  # 9
                    flows[flow].tls_client_elliptic_curve_point_format_count,           # 10
                    flows[flow].tls_server_extension_count                              # 11
    ))

def pktHandler(pkt,sampDelta,outfile):
    global scnets
    global ssnets
    global npkts
    global last_ks
    global T0

    timestamp,srcIP,dstIP,lengthIP = pkt.sniff_timestamp,pkt.ip.src,pkt.ip.dst,pkt.ip.len
    
    if (IPAddress(srcIP) in scnets and IPAddress(dstIP) in ssnets) or (IPAddress(srcIP) in ssnets and IPAddress(dstIP) in scnets):

        try:
            srcPort = pkt.tcp.srcPort
            dstport = pkt.tcp.dstport
            stream = pkt.tcp.stream
        except AttributeError:
            print("AttributeError on packet:")
            print(pkt)
            print("Skipping packet...")
            return 

        if npkts == 0:
            T0 = float(timestamp)
            last_ks = 0

        flow = TLSFlow(stream, srcIP, dstIP, srcPort, dstport)

        if flow not in flows:           # new tls flow
            flow.start_time = float(timestamp)
            flows[flow] = flow

        flow = flows[flow]

        if 'TLS' in str(pkt.layers):
            flows[flow].tls_packet_count += 1           # tls packet
        elif 'TCP' in str(pkt.layers):
            flows[flow].tcp_packet_count += 1           # tcp only packet
            if pkt.tcp.flags_fin.int_value:
                flows[flow].endFlags += 1               

        if IPAddress(srcIP) in scnets: #Upload (outbound)
            flows[flow].outbound_packet_count += 1                      # outbound packets
            flows[flow].outbound_byte_count += int(lengthIP)            # outbound bytes

        if IPAddress(dstIP) in scnets: #Download (inbound)
            flows[flow].inbound_packet_count += 1                       # inbound packets
            flows[flow].inbound_byte_count += int(lengthIP)             # inbound bytes

        flows[flow].duration = float(timestamp) - flows[flow].start_time        # flow duration

        if 'TLS' in str(pkt.layers) and 'handshake' in pkt.tls.field_names:     # tls handshake
            if pkt.tls.handshake == 'Handshake Protocol: Client Hello':
                flows[flow].tls_client_cipher_suite_count = pkt.tls.handshake_cipher_suites_length                              # number of supported client tls cipher suites
                flows[flow].tls_client_extension_count = pkt.tls.handshake_extensions_length                                    # number of supported client tls extensions
                flows[flow].tls_client_elliptic_curve_group_count = pkt.tls.handshake_extensions_supported_groups_length        # number of supported client tls elliptic curve groups
                flows[flow].tls_client_elliptic_curve_point_format_count = pkt.tls.handshake_extensions_ec_point_formats_length # number of supported client tls elliptic curve point formats
            elif pkt.tls.handshake == 'Handshake Protocol: Server Hello':
                flows[flow].tls_server_extension_count = pkt.tls.handshake_extensions_length    # number of supported server tls extensions   
            
        ks = int((float(timestamp)-T0)/sampDelta)
        metrics_extracted = False
        
        if ks > last_ks:
            extract_metrics(outfile, flow)
            clear_flow(flow)
            metrics_extracted = True

        if ks > last_ks+1:
            for j in range(last_ks+1,ks):
                extract_metrics(outfile, flow)
            metrics_extracted = True
            
        if flows[flow].endFlags == 2 or pkt.tcp.flags_reset.int_value:
            if not metrics_extracted:
                extract_metrics(outfile, flow)
            del flows[flow]         # flow ended
        
        last_ks=ks
        npkts += 1


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
    global last_ks
    global T0

    npkts=0
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
        capture = pyshark.FileCapture(fileInput,display_filter='tcp and (tcp.dstport==443 or tcp.srcport==443)') # grab all tls flow packets
        for pkt in capture:
            pktHandler(pkt,sampDelta,outfile)

    
    outfile.close()

    print("Total TLS flow packets: " + str(npkts))

if __name__ == '__main__':
    main()
