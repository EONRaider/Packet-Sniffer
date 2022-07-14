#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = "EONRaider @ keybase.io/eonraider"

from abc import ABC, abstractmethod


class Output(ABC):
    """Interface for the implementation of all classes responsible for
    further processing/output of the information gathered by the
    PacketSniffer class."""

    def __init__(self, subject):
        subject.register(self)

    @abstractmethod
    def update(self, *args, **kwargs):
        pass
