#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = 'EONRaider @ keybase.io/eonraider'


from ctypes import BigEndianStructure, create_string_buffer, c_ubyte, c_uint8, \
    c_uint16, c_uint32, sizeof
from socket import inet_ntop, AF_INET, AF_INET6


class Protocol(BigEndianStructure):
    _pack_ = 1

    def __new__(cls, packet):
        return cls.from_buffer_copy(packet)

    def __init__(self, packet=None):
        super().__init__()
        self.encapsulated_proto = None

    def __str__(self):
        return create_string_buffer(sizeof(self))[:]

    @staticmethod
    def addr_array_to_hdwr(address: str) -> str:
        """
        Converts a c_ubyte array of 6 bytes to IEEE 802 MAC address.
        Ex: From b'\xceP\x9a\xcc\x8c\x9d' to 'ce:50:9a:cc:8c:9d'
        """
        return ':'.join(format(octet, '02x') for octet in bytes(address))

    @staticmethod
    def hex_format(value: int, str_length: int) -> str:
        """
        Fills a hex value with zeroes to the left for compliance with
        the presentation of codes used in Internet protocols.
        Ex: From '0x800' to '0x0800'
        """
        return format(value, '#0{}x'.format(str_length))


class Ethernet(Protocol):      # IEEE 802.3 standard
    _fields_ = [
        ('dst', c_ubyte * 6),  # Destination hardware address
        ('src', c_ubyte * 6),  # Source hardware address
        ('eth', c_uint16)      # Ethertype
    ]
    header_len = 14
    ethertypes = {'0x0806': 'ARP', '0x0800': 'IPv4', '0x86dd': 'IPv6'}

    def __init__(self, packet: bytes):
        super().__init__(packet)
        self.dest = self.addr_array_to_hdwr(self.dst)
        self.source = self.addr_array_to_hdwr(self.src)
        self.ethertype = self.hex_format(self.eth, 6)
        # Limit implementation to common protocols
        self.encapsulated_proto = self.ethertypes.get(self.ethertype, None)


class IPv4(Protocol):              # IETF RFC 791
    _fields_ = [
        ("version", c_uint8, 4),   # Protocol version
        ("ihl", c_uint8, 4),       # Internet header length
        ("dscp", c_uint8, 6),      # Differentiated services code point
        ("ecp", c_uint8, 2),       # Explicit congestion notification
        ("len", c_uint16),         # Total packet length
        ("id", c_uint16),          # Identification
        ("flags", c_uint16, 3),    # Fragmentation control flags
        ("offset", c_uint16, 13),  # Fragment offset
        ("ttl", c_uint8),          # Time to live
        ("proto", c_uint8),        # Encapsulated protocol
        ("chksum", c_uint16),      # Header checksum
        ("src", c_ubyte * 4),      # Source address
        ("dst", c_ubyte * 4)       # Destination address
    ]
    header_len = 20
    proto_numbers = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

    def __init__(self, packet: bytes):
        super().__init__(packet)
        self.source = inet_ntop(AF_INET, self.src)
        self.dest = inet_ntop(AF_INET, self.dst)
        # Limit implementation to common protocols
        self.encapsulated_proto = self.proto_numbers.get(self.proto, None)


class IPv6(Protocol):               # IETF RFC 2460 / 8200
    _fields_ = [
        ("version", c_uint32, 4),   # Protocol version
        ("tclass", c_uint32, 8),    # Traffic class
        ("flabel", c_uint32, 20),   # Flow label
        ("payload_len", c_uint16),  # Payload length
        ("next_header", c_uint8),   # Type of next header
        ("hop_limit", c_uint8),     # Hop limit (replaces IPv4 TTL)
        ("src", c_ubyte * 16),      # Source address
        ("dst", c_ubyte * 16)       # Destination address
    ]
    header_len = 40

    def __init__(self, packet: bytes):
        super().__init__(packet)
        self.source = inet_ntop(AF_INET6, self.src)
        self.dest = inet_ntop(AF_INET6, self.dst)


class ARP(Protocol):           # IETF RFC 826
    _fields_ = [
        ("htype", c_uint16),   # Hardware type
        ("ptype", c_uint16),   # Protocol type
        ("hlen", c_uint8),     # Hardware length
        ("plen", c_uint8),     # Protocol length
        ("oper", c_uint16),    # Operation
        ("sha", c_ubyte * 6),  # Sender hardware address
        ("spa", c_ubyte * 4),  # Sender protocol address
        ("tha", c_ubyte * 6),  # Target hardware address
        ("tpa", c_ubyte * 4),  # Target protocol address
    ]
    header_len = 28

    def __init__(self, packet: bytes):
        super().__init__(packet)
        self.protocol = self.hex_format(self.ptype, 6)
        self.source_hdwr = self.addr_array_to_hdwr(self.sha)
        self.target_hdwr = self.addr_array_to_hdwr(self.tha)
        self.source_proto = inet_ntop(AF_INET, bytes(self.spa))
        self.target_proto = inet_ntop(AF_INET, bytes(self.tpa))


class TCP(Protocol):                # IETF RFC 675
    _fields_ = [
        ("sport", c_uint16),        # Source port
        ("dport", c_uint16),        # Destination port
        ("seq", c_uint32),          # Sequence number
        ("ack", c_uint32),          # Acknowledgement number
        ("offset", c_uint16, 4),    # Data offset
        ("reserved", c_uint16, 3),  # Reserved field
        ("flags", c_uint16, 9),     # TCP flag codes
        ("window", c_uint16),       # Size of the receive window
        ("chksum", c_uint16),       # TCP header checksum
        ("urg", c_uint16),          # Urgent pointer
    ]
    header_len = 32

    def __init__(self, packet: bytes):
        super().__init__(packet)
        self.flag_hex = self.hex_format(self.flags, 5)
        self.flag_txt = self.translate_flags()

    def translate_flags(self):
        f_names = 'NS', 'CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN'
        f_bits = format(self.flags, '09b')
        return ' '.join(flag_name for flag_name, flag_bit in
                            zip(f_names, f_bits) if flag_bit == '1')


class UDP(Protocol):          # IETF RFC 768
    _fields_ = [
        ("sport", c_uint16),  # Source port
        ("dport", c_uint16),  # Destination port
        ("len", c_uint16),    # Header length
        ("chksum", c_uint16)  # Header checksum
    ]
    header_len = 8

    def __init__(self, packet: bytes):
        super().__init__(packet)


class ICMP(Protocol):           # IETF RFC 792
    _fields_ = [
        ("type", c_uint8),      # Control message type
        ("code", c_uint8),      # Control message subtype
        ("chksum", c_uint16),   # Header checksum
        ("rest", c_ubyte * 4)   # Rest of header (contents vary)
    ]
    header_len = 8
    icmp_types = {0: 'REPLY', 8: 'REQUEST'}

    def __init__(self, packet: bytes):
        super().__init__(packet)
        # Limit implementation to ICMP ECHO
        self.type_txt = self.icmp_types.get(self.type, 'OTHER')
