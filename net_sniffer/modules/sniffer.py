#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = "EONRaider @ keybase.io/eonraider"

from typing import Iterator

from net_sniffer.modules.decoder import Decoder


class PacketSniffer:
    def __init__(self):
        """Monitor a network interface for incoming data, decode it and
        send to pre-defined output methods."""
        self._observers = list()

    def register(self, observer) -> None:
        """Register an observer for processing/output of decoded
        frames.

        :param observer: Any object that implements the interface
        defined by the Output abstract base-class."""
        self._observers.append(observer)

    def _notify_all(self, *args, **kwargs) -> None:
        """Send a decoded frame to all registered observers for further
        processing/output."""
        [observer.update(*args, **kwargs) for observer in self._observers]

    def listen(self, interface: str) -> Iterator:
        """Directly output a captured Ethernet frame while
        simultaneously notifying all registered observers, if any.

        :param interface: Interface from which a given frame will be
            captured and decoded.
        """
        for frame in Decoder(interface).execute():
            self._notify_all(frame)
            yield frame
