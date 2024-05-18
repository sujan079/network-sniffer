import socket
import struct 
import textwrap
t1='\t - '
t2='\t\t - '
t3='\t\t\t - '
t4='\t\t\t\t - '

dt1='\t - '
dt2='\t\t - '
dt3='\t\t\t - '
dt4='\t\t\t\t - '

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)

        dest_mac, src_mac, eth_proto, data =ethernet_frame(raw_data)
        print("\nEthernet frame")
        print(t1+"Destination:{}, Souce:{}, Protocol:{}".format(dest_mac, src_mac, eth_proto))

        #8 for ipv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) =ipv4_packet(data)
            print(t1+ 'IPv4 packet:')
            print(t2+'version:{}, Header length: {}, ttl: {}'.format(version, header_length, ttl))
            print(t2+'protocol:{}, source: {}, target: {}'.format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data =icmp_packet(data)
                print(t1+ 'ICMP PACKET:')
                print(t2+ 'TYPE:{}, CODE:{}, checksum: {},'.format(icmp_type, code, checksum))
                print(t2+ 'Data:')
                print(format_multi_line(dt3,data))
            #TCP

            elif proto ==6 :
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flage_ack, flag_psh, flag_syn, flag_fin)= tcp_segment(data)
                print(t1+"Tcp segment:")
                print(t2+"source port : {}, Destination part: {}".format(src_port, dest_port))
                print(t2 +'Flags:')
                print(t3+ 'URG: { }, ACK:{}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh,flag_rst, flag_syn, flag_fin))

            #udp
            elif proto == 17:
                src_port, dest_port, length ,data = udp_segment(data)
                print(t1 +'udp segment:')
                print(t2 + 'Source port: {}, Desination port: {}, Length: {}'. format(src_port, dest_port,leng))

            


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

#unpacking the Ipv4  packet
def ipv4_packet(data):
    version_header_length =data[0]
    version = version_header_length>> 4
    header_length =(version_header_length & 15) *4
    ttl, proto, src, target =struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src),ipv4(target), data[header_length:]

#formating the ipv4
def ipv4(addr):
    return '.'.join(map(str,addr))


# unpack ICmp packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unnpack('! B B H', data[:4])
    return  icmp_type, code, checksum, data[4:]

#unpacket tcp
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) =struct.unpack('! H H L L H',data[:14])
    #here we grabbbed the first 14 bytes of the data
    offset = (offset_reserved_flags>>12)*4
    flag_urg =(offset_reserved_flags & 32)>>5
    flag_ack =(offset_reserved_flags & 16)>>4  
    flag_psh =(offset_reserved_flags & 8)>>3
    flag_rst =(offset_reserved_flags & 4)>>2
    flag_syn =(offset_reserved_flags & 2)>>1  
    flag_fin =offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement,flag_urg, flag_ack, flag_psh,flag_rst, flag_syn, flag_fin, data[offset:]


#unnpacking the UDP segment 
def udp_segment(data):
    src_port , dest_port,length = struct.unpack('! H H H 2x', data[:8])
    return src_port, dest_port, length, data[8:]

#formating the muli line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string= ''.join(r'\x{:02x}'.format(byte) for byte in string )
        if size % 2 :
            size-= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
main()
    