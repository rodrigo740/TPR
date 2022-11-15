import argparse
import pyshark

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', nargs = '?', required = True, help = 'input file')
    parser.add_argument('-o', '--output', nargs = '?', required = False, help = 'output file')
    args = parser.parse_args()

    fileInput = args.input
    if args.output is None:
        fileOutput = fileInput + "_data.dat"
    else:
        fileOutput = args.output

    outfile = open(fileOutput, 'w')

    capture = pyshark.FileCapture(fileInput, display_filter='ip') 
    for pkt in capture:
        if 'TLS' in str(pkt.layers) and 'handshake_extensions_server_name' in pkt.tls.field_names:
            #print('PACKET: ', pkt.tls)
            #print('FIELDS: ', pkt.tls.field_names)
            print('SERVER: ', pkt.tls.handshake_extensions_server_name)
            outfile.write(pkt.tls.handshake_extensions_server_name + '\n')
    outfile.close()

if __name__ == '__main__':
    main()