#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = 'EONRaider @ keybase.io/eonraider'


import re
from ctypes import *
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
    def hardware_to_hex(mac: str) -> bytes:
        return b''.join(bytes.fromhex(octet) for octet in re.split('[:-]', mac))

    @staticmethod
    def hex_format(hex_value, str_len: int):
        return format(hex_value, '#0{}x'.format(str_len))


class Ethernet(Protocol):
    _fields_ = [
        ('dst', c_char * 6),
        ('src', c_char * 6),
        ('eth', c_uint16)
    ]
    ethertypes = {'0x0806': 'ARP', '0x0800': 'IPv4', '0x86dd': 'IPv6'}
    header_len = 14

    def __init__(self, packet: bytes = None):
        super().__init__(packet)
        self.dest = self.dst.hex(':')
        self.source = self.src.hex(':')
        self.ethertype = self.hex_format(self.eth, 6)
        self.encapsulated_proto = self.ethertypes[self.ethertype]


class IPv4(Protocol):
    _fields_ = [
        ("version", c_uint8, 4),
        ("ihl", c_uint8, 4),
        ("tos", c_uint8),
        ("len", c_uint16),
        ("id", c_uint16),
        ("offset", c_uint16),
        ("ttl", c_uint8),
        ("proto", c_uint8),
        ("sum", c_uint16),
        ("src", c_ubyte * 4),
        ("dst", c_ubyte * 4)
    ]
    proto_numbers = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    header_len = 20

    def __init__(self, packet: bytes = None):
        super().__init__()
        self.source = inet_ntop(AF_INET, self.src)
        self.dest = inet_ntop(AF_INET, self.dst)
        try:
            self.encapsulated_proto = self.proto_numbers[self.proto]
        except KeyError:  # Limit implementation to common protocols
            self.encapsulated_proto = None


class IPv6(Protocol):
    _fields_ = [
        ("vtfl", c_uint32),
        ("payload_len", c_uint16),
        ("next_header", c_uint8),
        ("hop_limit", c_uint8),
        ("src", c_ubyte * 16),
        ("dst", c_ubyte * 16)
    ]
    header_len = 40

    def __init__(self, packet: bytes = None):
        super().__init__()
        self.source = inet_ntop(AF_INET6, self.src)
        self.dest = inet_ntop(AF_INET6, self.dst)


class ARP(Protocol):
    _fields_ = [
        ("htype", c_uint16),
        ("ptype", c_uint16),
        ("hlen", c_uint8),
        ("plen", c_uint8),
        ("oper", c_uint16),
        ("sha", c_char * 6),
        ("spa", c_char * 4),
        ("tha", c_char * 6),
        ("tpa", c_char * 4),
    ]
    header_len = 28

    def __init__(self, packet: bytes = None):
        super().__init__()
        self.protocol = self.hex_format(self.ptype, 6)
        self.source_hdwr = self.sha.hex(':')
        self.target_hdwr = self.tha.hex(':')
        self.source_proto = inet_ntop(AF_INET, self.spa)
        self.target_proto = inet_ntop(AF_INET, self.tpa)


class TCP(Protocol):
    _fields_ = [
        ("sport", c_uint16),
        ("dport", c_uint16),
        ("seq", c_uint32),
        ("ack", c_uint32),
        ("offset", c_uint16, 4),
        ("reserved", c_uint16, 3),
        ("flags", c_uint16, 9),
        ("window", c_uint16),
        ("chksum", c_uint16),
        ("urg", c_uint16),
    ]
    header_len = 32

    def __init__(self, packet: bytes = None):
        super().__init__()
        self.flag_hex = self.hex_format(self.flags, 5)
        self.flag_txt = self.translate_flags()

    def translate_flags(self):
        f_names = 'NS', 'CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN'
        f_bits = format(self.flags, '09b')
        return ' '.join(flag_name for flag_name, flag_bit in
                            zip(f_names, f_bits) if flag_bit == '1')


class UDP(Protocol):
    _fields_ = [
        ("sport", c_uint16),
        ("dport", c_uint16),
        ("len", c_uint16),
        ("chksum", c_uint16)
    ]
    header_len = 8

    def __init__(self, packet: bytes = None):
        super().__init__()


class ICMP(Protocol):
    _fields_ = [
        ("type", c_uint8),
        ("code", c_uint8),
        ("chksum", c_uint16),
        ("id", c_uint16),
        ("seq", c_uint16)
    ]
    header_len = 8
    icmp_types = {0: 'REPLY', 8: 'REQUEST'}

    def __init__(self, packet: bytes = None):
        super().__init__()
        try:
            self.type_txt = self.icmp_types[self.type]
        except KeyError:
            self.type_txt = 'OTHER'  # Limit implementation to ICMP ECHO
