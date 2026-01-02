from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional
from time import datetime
from categorize import Services 

FlowKey = Tuple[str, str, int, int, str]  # src_ip, dst_ip, src_port, dst_port, proto

@dataclass
class FlowStats:
    packets: int = 0
    byte_count: int = 0
    packets_c2s: int = 0
    packets_s2c: int = 0
    first_payload_bytes: bytes = b""
    first_seen: datetime = None
    last_seen: datetime = None
    service_name: Optional[str] = None

@dataclass
class Aggregator:
    flows: Dict[FlowKey, FlowStats] = field(default_factory=dict)
    
    def update_flow(self, key: FlowKey, payload: bytes, pkt_len: int, ts: float, server_ip: str) -> None:
        if self.flows.get(key) is None:
            self.flows[key] = FlowStats(first_payload_bytes=payload,first_seen=datetime.fromtimestamp(ts), last_seen=datetime.fromtimestamp(ts))
        else:
            self.flows[key].last_seen = datetime.fromtimestamp

        self.flows[key].packets += 1
        self.flows[key].byte_count += pkt_len

        direction = 'c2s' if key[0] != server_ip else 's2c'
        if direction == 'c2s':
            self.flows[key].packets_c2s += 1
        else:
            self.flows[key].packets_s2c += 1
        
        for FlowKey, stats in self.flows.items():
            if stats.service_name is None:
                services = Services()
                service_name = services.get_service(FlowKey[3])  # dst_port
                if service_name:
                    stats.service_name = service_name
            


def build_default_aggregator(server_ip: str) -> Aggregator:
    return Aggregator() 

def print_top_flows(aggregator: Aggregator, top: int = 5) -> None:
    sorted_flows = sorted(aggregator.flows.items(), key=lambda item: item[1].byte_count, reverse=True)
    for i, (key, stats) in enumerate(sorted_flows[:top]):
        print(f"Flow {i+1}: {key} - Packets: {stats.packets}, Bytes: {stats.byte_count},  First Seen: {stats.first_seen}, Last Seen: {stats.last_seen}")

def update_db(aggregator: Aggregator) -> None:
    from db import update_host, update_service, update_flow
    for key, stats in aggregator.flows.items():
        src_ip, dst_ip, src_port, dst_port, proto = key
        update_host(src_ip, stats.first_seen.timestamp(), stats.last_seen.timestamp())
        update_host(dst_ip, stats.first_seen.timestamp(), stats.last_seen.timestamp())
        if stats.service_name:
            update_service(dst_ip, dst_port, stats.service_name, stats.first_seen.timestamp(), stats.last_seen.timestamp())
        update_flow(src_ip, dst_ip, src_port, dst_port, proto, stats.packets, stats.byte_count, stats.first_seen.timestamp(), stats.last_seen.timestamp())