#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = "EONRaider @ keybase.io/eonraider"

from ctypes import c_ubyte, c_uint8, c_uint16
from socket import inet_ntop, AF_INET

from protocols import Protocol


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
