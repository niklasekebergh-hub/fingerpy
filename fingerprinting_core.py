from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional
from time import datetime

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
        

def build_default_aggregator(server_ip: Optional[str] = None) -> Aggregator:
    return Aggregator() 
