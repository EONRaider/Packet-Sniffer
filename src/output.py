#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = "EONRaider @ keybase.io/eonraider"

import time
from abc import ABC, abstractmethod


class OutputMethod(ABC):
    """Interface for the implementation of all classes responsible for
    further processing/output of the information gathered by the
    PacketSniffer class."""

    i = " " * 4  # Basic indentation level

    def __init__(self, subject):
        subject.register(self)

    @abstractmethod
    def update(self, *args, **kwargs):
        pass


class OutputToScreen(OutputMethod):
    def __init__(self, subject, *, display_data: bool):
        """Output data from a decoded frame to screen.

        :param subject: Instance of PacketSniffer to be observed.
        :param display_data: Boolean specifying the output of captured
            data.
        """
        super().__init__(subject)
        self._frame = None
        self._display_data = display_data
        self._initialize()

    @staticmethod
    def _initialize() -> None:
        print("\n[>>>] Packet Sniffer initialized. Waiting for incoming "
              "data. Press Ctrl-C to abort...\n")

    def update(self, frame) -> None:
        self._frame = frame
        self._display_output_header()
        self._display_protocol_info()
        self._display_packet_contents()

    def _display_output_header(self) -> None:
        local_time = time.strftime("%H:%M:%S", time.localtime())
        print(f"[>] Frame #{self._frame.packet_num} at {local_time}:")

    def _display_protocol_info(self) -> None:
        """Iterate through a protocol queue and call the appropriate
        display protocol method."""
        for proto in self._frame.protocol_queue:
            getattr(self, f"_display_{proto.lower()}_data")()

    def _display_ethernet_data(self) -> None:
        ethernet = self._frame.ethernet
        interface = "all" if self._frame.interface is None \
            else self._frame.interface
        frame_length: int = self._frame.frame_length
        epoch_time: float = self._frame.epoch_time
        print(f"{self.i}[+] Ethernet {ethernet.src:.>23} -> {ethernet.dst}")
        print(f"{2 * self.i}  Interface: {interface}")
        print(f"{2 * self.i}  Frame Length: {frame_length}")
        print(f"{2 * self.i}  Epoch Time: {epoch_time}")

    def _display_ipv4_data(self) -> None:
        ipv4 = self._frame.ipv4
        print(f"{self.i}[+] IPv4 {ipv4.src:.>27} -> {ipv4.dst: <15}")
        print(f"{2 * self.i}  DSCP: {ipv4.dscp}")
        print(f"{2 * self.i}  Total Length: {ipv4.len}")
        print(f"{2 * self.i}  ID: {ipv4.id}")
        print(f"{2 * self.i}  Flags: {ipv4.flags_str}")
        print(f"{2 * self.i}  TTL: {ipv4.ttl}")
        print(f"{2 * self.i}  Protocol: {ipv4.encapsulated_proto}")
        print(f"{2 * self.i}  Header Checksum: {ipv4.chksum_hex_str}")

    def _display_ipv6_data(self) -> None:
        ipv6 = self._frame.ipv6
        print(f"{self.i}[+] IPv6 {ipv6.src:.>27} -> {ipv6.dst: <15}")
        print(f"{2 * self.i}  Traffic Class: {ipv6.tclass_hex_str}")
        print(f"{2 * self.i}  Flow Label: {ipv6.flabel_txt_str}")
        print(f"{2 * self.i}  Payload Length: {ipv6.payload_len}")
        print(f"{2 * self.i}  Next Header: {ipv6.encapsulated_proto}")
        print(f"{2 * self.i}  Hop Limit: {ipv6.hop_limit}")

    def _display_arp_data(self) -> None:
        arp = self._frame.arp
        if arp.oper == 1:  # ARP Request
            print(f"{self.i}[+] ARP Who has {arp.tpa:.>18} ? -> Tell {arp.spa}")
        else:              # ARP Reply
            print(f"{self.i}[+] ARP {arp.spa:.>28} -> Is at {arp.sha}")
        print(f"{2 * self.i}  Hardware Type: {arp.htype}")
        print(f"{2 * self.i}  Protocol Type: {arp.ptype_str} "
              f"({arp.ptype_hex_str})")
        print(f"{2 * self.i}  Hardware Length: {arp.hlen}")
        print(f"{2 * self.i}  Protocol Length: {arp.plen}")
        print(f"{2 * self.i}  Operation: {arp.oper} ({arp.oper_str})")
        print(f"{2 * self.i}  Sender Hardware Address: {arp.sha}")
        print(f"{2 * self.i}  Sender Protocol Address: {arp.spa}")
        print(f"{2 * self.i}  Target Hardware Address: {arp.tha}")
        print(f"{2 * self.i}  Target Protocol Address: {arp.tpa}")

    def _display_tcp_data(self) -> None:
        tcp = self._frame.tcp
        print(f"{self.i}[+] TCP {tcp.sport:.>28} -> {tcp.dport: <15}")
        print(f"{2 * self.i}  Sequence Number: {tcp.seq}")
        print(f"{2 * self.i}  ACK Number: {tcp.ack}")
        print(f"{2 * self.i}  Flags: {tcp.flags_hex_str} > {tcp.flags_str}")
        print(f"{2 * self.i}  Window Size: {tcp.window}")
        print(f"{2 * self.i}  Checksum: {tcp.chksum_hex_str}")
        print(f"{2 * self.i}  Urgent Pointer: {tcp.urg}")

    def _display_udp_data(self) -> None:
        udp = self._frame.udp
        print(f"{self.i}[+] UDP {udp.sport:.>28} -> {udp.dport}")
        print(f"{2 * self.i}  Header Length: {udp.len}")
        print(f"{2 * self.i}  Header Checksum: {udp.chksum}")

    def _display_icmpv4_data(self) -> None:
        ipv4 = self._frame.ipv4
        icmpv4 = self._frame.icmpv4
        print(f"{self.i}[+] ICMPv4 {ipv4.src:.>27} -> {ipv4.dst: <15}")
        print(f"{2 * self.i}  ICMP Type: {icmpv4.type} ({icmpv4.type_str})")
        print(f"{2 * self.i}  Header Checksum: {icmpv4.chksum_hex_str}")

    def _display_icmpv6_data(self) -> None:
        ipv6 = self._frame.ipv6
        icmpv6 = self._frame.icmpv6
        print(f"{self.i}[+] ICMPv6 {ipv6.src:.>27} -> {ipv6.dst: <15}")
        print(f"{2 * self.i}  Control Message Type: {icmpv6.type} "
              f"({icmpv6.type_str})")
        print(f"{2 * self.i}  Control Message Subtype: {icmpv6.code}")
        print(f"{2 * self.i}  Header Checksum: {icmpv6.chksum_hex_str}")

    def _display_packet_contents(self) -> None:
        if self._display_data is True:
            print(f"{self.i}[+] DATA:")
            data = (self._frame.data.decode(errors="ignore").
                    replace("\n", f"\n{self.i * 2}"))
            print(f"{self.i}{data}")
