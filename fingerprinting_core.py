from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional
from time import datetime

from db import record_flow, add_alert

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
