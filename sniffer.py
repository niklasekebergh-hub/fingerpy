from typing import Optional

from scapy.all import sniff, IP, TCP, UDP, Raw  # type: ignore

from fingerprinting_core import Fingerprinter, FlowKey
from rules import build_default_fingerprinter


def _handle_packet(pkt, fingerprinter: Fingerprinter) -> None:
    # Only process IP packets with TCP/UDP
    if IP not in pkt:
        return

    ip_layer = pkt[IP]

    proto: Optional[str]
    sport: Optional[int]
    dport: Optional[int]

    if TCP in pkt:
        l4 = pkt[TCP]
        proto = "tcp"
        sport = int(l4.sport)
        dport = int(l4.dport)
    elif UDP in pkt:
        l4 = pkt[UDP]
        proto = "udp"
        sport = int(l4.sport)
        dport = int(l4.dport)
    else:
        return

    if sport is None or dport is None or proto is None:
        return

    payload = bytes(pkt[Raw].load) if Raw in pkt else b""

    key: FlowKey = (ip_layer.src, ip_layer.dst, sport, dport, proto)
    fingerprinter.update_flow(key, src_ip=ip_layer.src, payload=payload)


def start_sniffing(
    interface: str,
    server_ip: Optional[str] = None,
    summary_interval: int = 30,
) -> None:
    
    import time

    fingerprinter = build_default_fingerprinter(server_ip)

    last_summary = time.time()

    def _prn(pkt):
        nonlocal last_summary
        _handle_packet(pkt, fingerprinter)
        now = time.time()
        if now - last_summary >= summary_interval:
            fingerprinter.summarize()
            print("# Suggested drop rules (manual review required):")
            fingerprinter.suggest_drop_rules()
            last_summary = now

    print(f"[+] Sniffing on {interface}, server_ip={server_ip or 'UNKNOWN'}")
    try:
        sniff(iface=interface, prn=_prn, store=False)
    except KeyboardInterrupt:
        print("\n[!] KeyboardInterrupt – final summary:")
        fingerprinter.summarize()
        print("# Final suggested drop rules:")
        fingerprinter.suggest_drop_rules()


def main() -> None:
    #Minimal CLI entry point

    import argparse

    parser = argparse.ArgumentParser(description="Simple competition fingerprinter/sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Interface to sniff on, e.g. eth0")
    parser.add_argument(
        "-s",
        "--server-ip",
        help="IP of THIS box (used to orient flows and drop rules)",
    )
    parser.add_argument(
        "--summary-interval",
        type=int,
        default=30,
        help="Seconds between automatic summaries (default: 30)",
    )

    args = parser.parse_args()
    start_sniffing(args.interface, server_ip=args.server_ip, summary_interval=args.summary_interval)


if __name__ == "__main__":
    main()
