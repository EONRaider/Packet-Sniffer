#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = "EONRaider @ keybase.io/eonraider"

from ctypes import c_ubyte, c_uint16

from protocols import Protocol


class Ethernet(Protocol):      # IEEE 802.3 standard
    _fields_ = [
        ("dst", c_ubyte * 6),  # Destination hardware address
        ("src", c_ubyte * 6),  # Source hardware address
        ("eth", c_uint16)      # Ethertype
    ]
    header_len = 14
    ethertypes = {"0x0806": "ARP", "0x0800": "IPv4", "0x86dd": "IPv6"}

    def __init__(self, packet: bytes):
        super().__init__(packet)
        self.dest = self.addr_array_to_hdwr(self.dst)
        self.source = self.addr_array_to_hdwr(self.src)
        self.ethertype = self.hex_format(self.eth, 6)
        # Limit implementation to common protocols
        self.encapsulated_proto = self.ethertypes.get(self.ethertype, None)
