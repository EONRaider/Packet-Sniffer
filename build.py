#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = "EONRaider @ keybase.io/eonraider"

import PyInstaller.__main__ as pyinstaller


def build() -> None:
    """Set-up the arguments required by PyInstaller to build the Network
    Packet Sniffer binary."""
    pyinstaller.run(("packet_sniffer.py", "--onefile"))


if __name__ == "__main__":
    build()
