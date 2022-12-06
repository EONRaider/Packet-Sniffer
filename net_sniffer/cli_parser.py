#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = "EONRaider @ keybase.io/eonraider"

import argparse

_banner = r"""
    _   ___________________       _ ________         
   / | / / ____/_  __/ ___/____  (_) __/ __/__  _____
  /  |/ / __/   / /  \__ \/ __ \/ / /_/ /_/ _ \/ ___/
 / /|  / /___  / /  ___/ / / / / / __/ __/  __/ /    
/_/ |_/_____/ /_/  /____/_/ /_/_/_/ /_/  \___/_/     

A network packet sniffer that disassembles packets upon
arrival at a given network interface controller and
displays their information on screen.

             Developed by EONRaider
   https://github.com/EONRaider/Packet-Sniffer

"""


class _CLIParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description=_banner,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

    def parse(self) -> argparse.Namespace:
        self.parser.add_argument(
            "-i",
            "--interface",
            type=str,
            default=None,
            help="Interface from which Ethernet frames will be captured "
            "(monitors all available interfaces by default).",
        )
        self.parser.add_argument(
            "-d",
            "--data",
            action="store_true",
            help="Output packet data during capture.",
        )
        return self.parser.parse_args()
