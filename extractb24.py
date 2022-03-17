import argparse
import os
import sys
from scapy.all import PcapReader
from scapy.packet import Raw

def extract_pcap(file_name):
    count = 0
    pfile = PcapReader(file_name)
    for packet in pfile:
        try:
            data = packet[Raw].load
            header = data[0:2]
            msize = int(header[0:2].hex(),16) # size of ISO 8583 packet
            message = data[2:]
            print('TCP Message size from data {} bytes, size from header {} bytes'.format(len(data),msize))
            hmessage = message[0:48]
            print('ISO 8583 Header {}'.format(hmessage.hex()))
            bmessage = message[48:]
            print('ISO 8583 Message {}'.format(bmessage.hex()))
            count += 1
        except Exception:
            pass
    print('{} contains {} packets with ISO 8583 Base 24 information'.format(file_name, count))
    pfile.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader for print ISO 8583 Base 24 on HEX format')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to extrat ISO 8582 Base 24 Messages', required=True)
    args = parser.parse_args()
    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)
    extract_pcap(file_name)
    sys.exit(0)