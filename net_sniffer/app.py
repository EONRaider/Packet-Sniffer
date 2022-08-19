import argparse
import os

from net_sniffer.modules.sniffer import PacketSniffer
from net_sniffer.output.screen import OutputToScreen


def parse_cli_options():
    parser = argparse.ArgumentParser(description="Network packet sniffer")
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Interface from which Ethernet frames will be captured (monitors "
        "all available interfaces by default).",
    )
    parser.add_argument(
        "-d",
        "--data",
        action="store_true",
        help="Output packet data during capture.",
    )
    return parser.parse_args()


def run():
    args = parse_cli_options()

    if os.getuid() != 0:
        raise SystemExit(
            "Error: Permission denied. This application requires "
            "administrator privileges to run."
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
