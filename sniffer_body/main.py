from db import init_db
from sniffer import start_sniffing


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="fingerpy network fingerprinter")
    parser.add_argument("-i", "--interface", required=True, help="Interface to sniff on, e.g. eth0")
    parser.add_argument(
        "-s",
        "--server-ip",
        required=True,
        help="IP address of THIS host (used to orient flows)",
    )
    parser.add_argument(
        "--summary-interval",
        type=int,
        default=30,
        help="Seconds between automatic summaries (default: 30)",
    )

    args = parser.parse_args()

    init_db()
    start_sniffing(
        interface=args.interface,
        server_ip=args.server_ip,
        summary_interval=args.summary_interval,
    )


if __name__ == "__main__":
    main()
