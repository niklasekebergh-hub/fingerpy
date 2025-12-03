from scapy.all import sniff, IP, TCP, UDP, Raw
from fingerprint_core import Fingerprinter
from rules import build_default_fingerprinter

INTERFACE = "eth0"          # change for comp
SERVER_IP = "10.0.0.5"      # your box
SUMMARY_INTERVAL = 30       # seconds between summaries

fingerprinter = build_default_fingerprinter(SERVER_IP)


def handle_packet(pkt):
    # Only process IP packets with TCP/UDP
    if not IP in pkt:
        return

    ip = pkt[IP]
    proto = None
    sport = None
    dport = None

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

    # Extract payload if present
    payload = b""
    if Raw in pkt:
        payload = bytes(pkt[Raw].load)

    key = (ip.src, ip.dst, sport, dport, proto)
    fingerprinter.update_flow(key, src_ip=ip.src, payload=payload)


def main():
    import time
    last_summary = time.time()

    def _prn(pkt):
        nonlocal last_summary
        handle_packet(pkt)
        now = time.time()
        if now - last_summary > SUMMARY_INTERVAL:
            fingerprinter.summarize()
            print("# Suggested drop rules (manual review required):")
            fingerprinter.suggest_drop_rules()
            last_summary = now

    print(f"[+] Sniffing on {INTERFACE}, server_ip={SERVER_IP}")
    sniff(iface=INTERFACE, prn=_prn, store=False)


if __name__ == "__main__":
    main()
