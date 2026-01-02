from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional

@dataclass
class Services:
    service_map: Dict[int, str] = field(default_factory=lambda: {
        21: "FTP",
        20: "FTP-Data",
        80: "HTTP",
        443: "HTTPS",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        8000: "HTTP-Dev",
        8888: "HTTP-Proxy / Alt",        
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        5900: "VNC",
        2222: "SSH-Alt",
        53: "DNS",
        25: "SMTP",
        465: "SMTPS",
        587: "SMTP-Submission",
        110: "POP3",
        995: "POP3S",
        143: "IMAP",
        993: "IMAPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
        11211: "Memcached",
        9200: "Elasticsearch",
        9042: "Cassandra",
        445: "SMB",
        139: "NetBIOS",
        389: "LDAP",
        636: "LDAPS",
        2049: "NFS",
        1194: "OpenVPN",
        51820: "WireGuard",
        1701: "L2TP",
        500: "ISAKMP/IKE",
        4500: "IPsec-NAT-T",
        123: "NTP",
        161: "SNMP",
        162: "SNMP-Trap",
        514: "Syslog",
    })

    def get_service(self, port: int) -> Optional[str]:
        return self.service_map.get(port)