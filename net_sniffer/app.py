#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = "EONRaider @ keybase.io/eonraider"

import os
import platform

from net_sniffer.cli_parser import CLIParser
from net_sniffer.modules.sniffer import PacketSniffer
from net_sniffer.output.screen import OutputToScreen


def run():
    args = CLIParser().parse()

    if platform.system() == "Windows":
        raise SystemExit(
            "Error: Unsupported OS. This application depends on calls to "
            "socket.PF_PACKET and will only run on operating systems based "
            "on the Linux kernel. Aborting..."
        )

    if os.getuid() != 0:
        raise SystemExit(
            "Error: Permission denied. This application requires "
            "administrator privileges to run. Aborting..."
        )

    OutputToScreen(subject=(sniffer := PacketSniffer()), display_data=args.data)

    try:
        for _ in sniffer.listen(args.interface):
            """Iterate through the frames yielded by the listener in an
            infinite cycle while feeding them to all registered observers
            for further processing/output"""
            pass
    except KeyboardInterrupt:
        raise SystemExit("[!] Aborting packet capture...")


if __name__ == "__main__":
    run()
