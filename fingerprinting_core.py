from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional
import time

FlowKey = Tuple[str, str, int, int, str]  # src_ip, dst_ip, src_port, dst_port, proto


@dataclass
class FlowStats:
    packets: int = 0
    bytes: int = 0
    client_to_server: int = 0
    server_to_client: int = 0
    first_payload_bytes: bytes = b""
    last_seen: float = 0.0

    def update(self, payload: bytes, direction: str, now: float) -> None:
        self.packets += 1
        self.bytes += len(payload)
        if direction == "c2s":
            self.client_to_server += len(payload)
        elif direction == "s2c":
            self.server_to_client += len(payload)
        if not self.first_payload_bytes and payload:
            # store a small prefix
            self.first_payload_bytes = payload[:64]
        self.last_seen = now


@dataclass
class FingerprintRule:
    name: str
    dst_port: Optional[int] = None
    src_port: Optional[int] = None
    contains_bytes: Optional[bytes] = None  # e.g. b"HTTP/1.1" or b"score"
    min_bytes: Optional[int] = None
    max_bytes: Optional[int] = None
    scoring: bool = False  # True = scoring service, False = noise pattern

    def matches(self, key: FlowKey, stats: FlowStats) -> bool:
        src_ip, dst_ip, sport, dport, proto = key

        if self.dst_port is not None and dport != self.dst_port:
            return False
        if self.src_port is not None and sport != self.src_port:
            return False
        if self.min_bytes is not None and stats.bytes < self.min_bytes:
            return False
        if self.max_bytes is not None and stats.bytes > self.max_bytes:
            return False
        if self.contains_bytes is not None:
            if self.contains_bytes not in stats.first_payload_bytes:
                return False
        return True


class Fingerprinter:
    def __init__(self, server_ip: Optional[str] = None):
        # server_ip: your box in the competition environment
        self.server_ip = server_ip
        self.flows: Dict[FlowKey, FlowStats] = {}
        self.rules: Dict[str, FingerprintRule] = {}

    def add_rule(self, rule: FingerprintRule) -> None:
        self.rules[rule.name] = rule

    def flow_direction(self, key: FlowKey, src_ip: str) -> str:
        # crude assumption: "client" == not our server_ip
        if self.server_ip is None:
            return "c2s"
        return "c2s" if src_ip != self.server_ip else "s2c"

    def update_flow(self, key: FlowKey, src_ip: str, payload: bytes) -> None:
        now = time.time()
        if key not in self.flows:
            self.flows[key] = FlowStats()
        direction = self.flow_direction(key, src_ip)
        self.flows[key].update(payload, direction, now)

    def classify_flow(self, key: FlowKey, stats: FlowStats) -> str:
        # Return "scoring", "noise", or "unknown"
        best_match = None
        for rule in self.rules.values():
            if rule.matches(key, stats):
                best_match = rule
                break  # simple: first match wins

        if best_match is None:
            return "unknown"
        return "scoring" if best_match.scoring else "noise"

    def summarize(self) -> None:
        print("=" * 80)
        for key, stats in list(self.flows.items()):
            label = self.classify_flow(key, stats)
            src_ip, dst_ip, sport, dport, proto = key
            print(f"[{label.upper():7}] {src_ip}:{sport} -> {dst_ip}:{dport}/{proto} "
                  f"pkts={stats.packets} bytes={stats.bytes}")
        print("=" * 80)

    def suggest_drop_rules(self, server_ip: Optional[str] = None) -> None:
        """
        Print suggested iptables drop rules for noise flows.
        You add/modify these manually – do NOT blindly paste in prod.
        """
        server_ip = server_ip or self.server_ip
        printed = set()

        for key, stats in self.flows.items():
            label = self.classify_flow(key, stats)
            if label != "noise":
                continue
            src_ip, dst_ip, sport, dport, proto = key

            # Only suggest rules that drop traffic TO your server.
            if server_ip is not None and dst_ip != server_ip:
                continue

            rule = (dst_ip, dport, proto)
            if rule in printed:
                continue
            printed.add(rule)

            if proto.lower() == "tcp":
                print(f"# Noise flow: {dst_ip}:{dport}/tcp")
                print(f"iptables -A INPUT -p tcp --dport {dport} -j DROP")
            elif proto.lower() == "udp":
                print(f"# Noise flow: {dst_ip}:{dport}/udp")
                print(f"iptables -A INPUT -p udp --dport {dport} -j DROP")
