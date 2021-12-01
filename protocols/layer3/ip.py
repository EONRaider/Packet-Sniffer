#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = "EONRaider @ keybase.io/eonraider"

from ctypes import c_ubyte, c_uint8, c_uint16, c_uint32
from socket import inet_ntop, AF_INET, AF_INET6

from protocols import Protocol


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
    proto_numbers = {1: "ICMP", 6: "TCP", 17: "UDP"}

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
