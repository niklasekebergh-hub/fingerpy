from typing import Optional
from db import DP_PATH
from scapy.all import sniff, IP, TCP, UDP, Raw,   # type: ignore

from fingerprinting_core import Aggregator, FlowKey, build_default_aggregator, print_top_flows

def _handle_packet(pkt, fingerprinter: Aggregator, server_ip: str) -> None:
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
    fingerprinter.update_flow(key=key, payload=payload, pkt_len=len(payload), ts=pkt.time, server_ip=server_ip)


def start_sniffing(
    interface: str,
    server_ip: str,
    summary_interval: int = 30,
) -> None:
    
    import time

    agg = build_default_aggregator(server_ip)

    last_summary = time.time()

    def _on_packet(pkt):
        nonlocal last_summary
        _handle_packet(pkt, agg, server_ip)
        now = time.time()
        if now - last_summary >= summary_interval:
            print(f"\n[+] Summary at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}:")
            print_top_flows(agg)
            last_summary = now

    print(f"[+] Sniffing on {interface}, server_ip={server_ip or 'UNSPECIFIED'}")
    try:
        sniff(iface=interface, prn=_on_packet, store=False)
    except KeyboardInterrupt:
        print(f"\n[!] KeyboardInterrupt – Results stored to {DP_PATH}")