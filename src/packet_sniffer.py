#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = "EONRaider @ keybase.io/eonraider"

import itertools
from socket import PF_PACKET, SOCK_RAW, ntohs, socket
from typing import Iterator

from src.output import OutputToScreen

import netprotocols


class Decoder:
    def __init__(self, interface: str):
        """Decodes packets incoming from a given interface.

        :param interface: Interface from which packets will be captured
            and decoded.
        """
        self.interface = interface
        self.data = None
        self.protocol_queue = ["Ethernet"]
        self.packet_num: int = 0

    def listen(self) -> Iterator:
        """Yields a decoded packet as an instance of Protocol."""
        with socket(PF_PACKET, SOCK_RAW, ntohs(0x0003)) as sock:
            if self.interface is not None:
                sock.bind((self.interface, 0))
            for self.packet_num in itertools.count(1):
                raw_packet = sock.recv(9000)
                start = 0
                for proto in self.protocol_queue:
                    proto_class = getattr(netprotocols, proto)
                    end = start + proto_class.header_len
                    protocol = proto_class.decode(raw_packet[start:end])
                    setattr(self, proto.lower(), protocol)
                    if protocol.encapsulated_proto in (None, "undefined"):
                        break
                    self.protocol_queue.append(protocol.encapsulated_proto)
                    start = end
                self.data = raw_packet[end:]
                yield self
                del self.protocol_queue[1:]


class PacketSniffer:
    def __init__(self):
        """Monitor a network interface for incoming data, decode it and
        send to pre-defined output methods."""
        self._observers = list()

    def register(self, observer) -> None:
        """Register an observer for processing/output of decoded
        packets."""
        self._observers.append(observer)

    def _notify_all(self, *args, **kwargs) -> None:
        """Send a decoded packet to all registered observers."""
        [observer.update(*args, **kwargs) for observer in self._observers]

    def execute(self, display_data: bool, *, interface: str) -> None:
        """Start the packet sniffer.

        :param display_data: Output packet data during capture.
        :param interface: Interface from which packets will be captured
            and decoded.
        """
        OutputToScreen(subject=self, display_data=display_data)
        try:
            print("\n[>>>] Packet Sniffer initialized. Waiting for incoming "
                  "data. Press Ctrl-C to abort...\n")
            [self._notify_all(packet) for packet in Decoder(interface).listen()]
        except KeyboardInterrupt:
            raise SystemExit("Aborting packet capture...")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Network packet sniffer")
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Interface from which packets will be captured (monitors all "
             "available interfaces by default)."
    )
    parser.add_argument(
        "-d", "--display-data",
        action="store_true",
        help="Output packet data during capture."
    )
    _args = parser.parse_args()

    PacketSniffer().execute(_args.display_data, interface=_args.interface)
