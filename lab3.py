import socket
import struct


class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


# Format source and Dest for tcp only
def parse_raw_ip_addr(raw_ip_addr: bytes):
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    raw_ip_str = map('{:x}'.format, raw_ip_addr)
    ip = '.'.join(raw_ip_str)
    temp = ip.split('.')
    ip = ""
    for i in range(len(temp)):
        fromhex = int(temp[i], 16)
        ip += "." + str(fromhex)
    return ip[1:]


# TcpPacket
def parse_application_layer_packet(ip_packet_payload: bytes):
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    source = ip_packet_payload[0:2]
    source = int.from_bytes(source, 'big')

    destination = ip_packet_payload[2:4]
    destination = int.from_bytes(destination, 'big')

    offset = ip_packet_payload[12] >> 4

    payload = ip_packet_payload[4*offset:]

    return TcpPacket(source, destination, offset, payload.decode("utf-8"))


# IpPacket
def parse_network_layer_packet(ip_packet: bytes):
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    protocol = ip_packet[9]

    IHL = ip_packet[0] & 0x0F

    source = ip_packet[12:16]
    source = struct.unpack("!4s", source)
    source = parse_raw_ip_addr(source[0])

    destination = ip_packet[16:20]
    destination = struct.unpack("!4s", destination)
    destination = parse_raw_ip_addr(destination[0])

    payload = ip_packet[4*IHL:]
    return IpPacket(protocol, IHL, source, destination, payload)


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)
    TCP = 0x0006
    stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW, TCP)
    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))

    while True:
        # Receive packets and do processing here
        packet, address = stealer.recv(4096)
        x = parse_network_layer_packet(packet)
        parse_application_layer_packet(x.payload)
        pass
    pass


if __name__ == "__main__":
    main()
