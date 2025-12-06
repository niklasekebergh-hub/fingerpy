from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional
import time

from db import record_flow, add_alert

FlowKey = Tuple[str, str, int, int, str]  # src_ip, dst_ip, src_port, dst_port, proto

@dataclass
class FlowStats:
    packets: int = 0
    bytes: int = 0
    client_to_server: int = 0
    server_to_client: int = 0
    first_payload_bytes: bytes = b""
    last_seen: float = 0.0

@dataclass
class FingerprintRule:
    name: str
    dst_port: Optional[int] = None
    proto: Optional[str] = None  # "tcp" or "udp"
    min_bytes: Optional[int] = None
    max_bytes: Optional[int] = None
    scoring: bool = False  # True => scoring service, False => noise / attacker

    def matches(self, key: FlowKey, stats: FlowStats) -> bool:
        _, dst_ip, _sport, dport, proto = key
        proto = proto.lower()

        if self.proto and proto != self.proto.lower():
            return False
        if self.dst_port is not None and dport != self.dst_port:
            return False

        length = len(stats.first_payload_bytes) if stats.first_payload_bytes else stats.bytes
        if self.min_bytes is not None and length < self.min_bytes:
            return False
        if self.max_bytes is not None and length > self.max_bytes:
            return False

        return True


@dataclass
class Fingerprinter:
    server_ip: Optional[str] = None
    flows: Dict[FlowKey, FlowStats] = field(default_factory=dict)
    rules: Dict[str, FingerprintRule] = field(default_factory=dict)

    def add_rule(self, rule: FingerprintRule) -> None:
        self.rules[rule.name] = rule

    def flow_direction(self, key: FlowKey, src_ip: str) -> str:
        if self.server_ip:
            return "c2s" if src_ip != self.server_ip else "s2c"
        # Assume src is client.
        return "c2s"

    def update_flow(self, key: FlowKey, src_ip: str, payload: bytes) -> None:
        now = time.time()
        stats = self.flows.get(key)
        if not stats:
            stats = FlowStats()
            self.flows[key] = stats

        stats.packets += 1
        pkt_len = len(payload)
        stats.bytes += pkt_len
        stats.last_seen = now

        if not stats.first_payload_bytes and payload:
            stats.first_payload_bytes = payload[:64]

        direction = self.flow_direction(key, src_ip)
        if direction == "c2s":
            stats.client_to_server += 1
        else:
            stats.server_to_client += 1

        label, rule = self.classify_flow(key, stats)
        rule_name = rule.name if rule else None
        classification = label or "unknown"

        src_ip, dst_ip, _sport, dport, proto = key
        record_flow(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dport,
            proto=proto,
            classification=classification,
            rule_name=rule_name,
            bytes_count=pkt_len,
            server_ip=self.server_ip,
        )

        if label == "noise":
            add_alert(
                ip=src_ip,
                alert_type="noise_flow",
                reason=f"Rule={rule_name} dst={dst_ip}:{dport}/{proto} bytes={pkt_len}",
            )

    def classify_flow(
        self, key: FlowKey, stats: FlowStats) -> Tuple[Optional[str], Optional[FingerprintRule]]:
        matching_scoring: Optional[FingerprintRule] = None
        matching_noise: Optional[FingerprintRule] = None

        for rule in self.rules.values():
            if not rule.matches(key, stats):
                continue
            if rule.scoring:
                matching_scoring = rule
            else:
                matching_noise = rule

        if matching_scoring:
            return "scoring", matching_scoring
        if matching_noise:
            return "noise", matching_noise
        return None, None

    def summarize(self) -> None:
        print("\n=== Flow summary ===")
        now = time.time()
        by_dst: Dict[Tuple[str, int, str], FlowStats] = {}

        for (src_ip, dst_ip, _sport, dport, proto), stats in self.flows.items():
            key = (dst_ip, dport, proto)
            agg = by_dst.get(key)
            if not agg:
                agg = FlowStats()
                by_dst[key] = agg
            agg.packets += stats.packets
            agg.bytes += stats.bytes
            agg.last_seen = max(agg.last_seen, stats.last_seen)

        for (dst_ip, dport, proto), stats in sorted(
            by_dst.items(), key=lambda x: (x[0][0], x[0][1], x[0][2])
        ):
            age = now - stats.last_seen
            # Label this aggregated flow according to our rules.
            fake_key: FlowKey = ("0.0.0.0", dst_ip, 0, dport, proto)
            label, rule = self.classify_flow(fake_key, stats)
            label = label or "unknown"
            rule_name = rule.name if rule else "-"

            print(
                f"{dst_ip:>15}:{dport:<5}/{proto:<3}  "
                f"bytes={stats.bytes:<8} pkts={stats.packets:<6} "
                f"age={age:5.1f}s  class={label:<7} rule={rule_name}"
            )

    def suggest_drop_rules(self, server_ip: Optional[str] = None) -> None:
        server_ip = server_ip or self.server_ip
        printed: set = set()

        for (src_ip, dst_ip, _sport, dport, proto), stats in self.flows.items():
            key = (src_ip, dst_ip, _sport, dport, proto)
            label, rule = self.classify_flow(key, stats)
            if label != "noise":
                continue

            # If server_ip is known, we only care about noise *towards* us.
            if server_ip is not None and dst_ip != server_ip:
                continue

            dedup_key = (dst_ip, dport, proto.lower())
            if dedup_key in printed:
                continue
            printed.add(dedup_key)

            if proto.lower() == "tcp":
                print(f"# Noise flow: {dst_ip}:{dport}/tcp  (rule={rule.name if rule else '?'} src={src_ip})")
                print(f"iptables -A INPUT -p tcp --dport {dport} -j DROP")
            elif proto.lower() == "udp":
                print(f"# Noise flow: {dst_ip}:{dport}/udp  (rule={rule.name if rule else '?'} src={src_ip})")
                print(f"iptables -A INPUT -p udp --dport {dport} -j DROP")
