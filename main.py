import socket
import struct 
import textwrap


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)

        dest_mac, src_mac, eth_proto, data =ethernet_frame(raw_data)
        print("Ethernet frame\n")
        print("Dest:{}, Souce:{}, Protocol:{}".format(dest_mac, src_mac, eth_proto))



# unpacking the ethernet frame:
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
#takings the total of 14 bytes data ,6 and and g6 to the first two
#and 2 for the last one represented by H
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


#returning the properly formatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr) #formating the addr, making group of two elements
    mac_addr = ':'.join(bytes_str).upper() #formating in 09:7A:5R something like this
    return mac_addr

main()