#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = "EONRaider @ keybase.io/eonraider"

import time
from abc import ABC, abstractmethod


class OutputMethod(ABC):
    """Interface for the implementation of all classes responsible for
    further processing and/or output of the information gathered by
    the PacketSniffer class."""

    i = " " * 4  # Basic indentation level

    def __init__(self, subject):
        subject.register(self)

    @abstractmethod
    def update(self, *args, **kwargs):
        pass


class OutputToScreen(OutputMethod):
    def __init__(self, subject, *, display_data: bool):
        super().__init__(subject)
        self._packet = None
        self._display_data = display_data

    def update(self, packet) -> None:
        self._packet = packet
        self._display_output_header()
        self._display_packet_info()
        self._display_packet_contents()

    def _display_output_header(self) -> None:
        local_time = time.strftime("%H:%M:%S", time.localtime())
        interface = "all" if self._packet.interface is None \
            else self._packet.interface
        print(f"[>] Packet #{self._packet.packet_num} at {local_time} from "
              f"interface \"{interface}\":")

    def _display_packet_info(self) -> None:
        for proto in self._packet.protocol_queue:
            getattr(self, f"_display_{proto.lower()}_data")()

    def _display_ethernet_data(self) -> None:
        ethernet = self._packet.ethernet
        print(f"{self.i}[+] Ethernet {ethernet.src:.>23} -> {ethernet.dst}")

    def _display_ipv4_data(self) -> None:
        ipv4 = self._packet.ipv4
        print(f"{self.i}[+] IPv4 {ipv4.src:.>27} -> {ipv4.dst: <15} | "
              f"PROTO: {ipv4.encapsulated_proto} TTL: {ipv4.ttl}")

    def _display_ipv6_data(self) -> None:
        ipv6 = self._packet.ipv6
        print(f"{self.i}[+] IPv6 {ipv6.src:.>27} -> {ipv6.dst: <15}")

    def _display_arp_data(self) -> None:
        arp = self._packet.arp
        if arp.oper == 1:  # ARP Request
            print(f"{self.i}[+] ARP Who has {arp.tpa:.>18} ? -> Tell {arp.spa}")
        else:              # ARP Reply
            print(f"{self.i}[+] ARP {arp.spa:.>28} -> Is at {arp.sha}")

    def _display_tcp_data(self) -> None:
        tcp = self._packet.tcp
        print(f"{self.i}[+] TCP {tcp.sport:.>28} -> {tcp.dport: <15} | "
              f"Flags: {tcp.flags_hex} > {tcp.flags_txt}")

    def _display_udp_data(self) -> None:
        udp = self._packet.udp
        print(f"{self.i}[+] UDP {udp.sport:.>27} -> {udp.dport}")

    def _display_icmp_data(self) -> None:
        ipv4 = self._packet.ipv4
        icmpv4 = self._packet.icmpv4
        print(f"{self.i}[+] ICMP {ipv4.sre:.>27} -> {ipv4.dst: <15} | "
              f"Type: {icmpv4.type_name}")

    def _display_packet_contents(self) -> None:
        if self._display_data is True:
            print(f"{self.i}[+] DATA:")
            data = (self._packet.data.decode(errors="ignore").
                    replace("\n", f"\n{self.i * 2}"))
            print(f"{self.i}{data}")
