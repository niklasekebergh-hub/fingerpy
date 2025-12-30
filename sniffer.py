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
            last_summary = now

    print(f"[+] Sniffing on {interface}, server_ip={server_ip or 'UNKNOWN'}")
    try:
        sniff(iface=interface, prn=_prn, store=False)
    except KeyboardInterrupt:
        print("\n[!] KeyboardInterrupt – Results stored to database. (netmon.db)")