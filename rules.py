from fingerprinting_core import Fingerprinter, FingerprintRule


def build_default_fingerprinter(server_ip: str) -> Fingerprinter:
    """
    Build a fingerprinter configured with rules to detect scoring services
    and malicious/noisy traffic patterns in a competition environment.
    
    Scoring rules: legitimate traffic to critical services
    Noise rules: detection patterns for malicious/scanners/floods
    """
    fp = Fingerprinter(server_ip=server_ip)
    ##SCORING SERVICE DECECTION##
    # Web service scoring engine (HTTP/HTTPS)
    fp.add_rule(FingerprintRule(
        name="scoring_http_8080",
        dst_port=8080,
        contains_bytes=b"HTTP",
        min_bytes=50,
        max_bytes=100000,
        scoring=True
    ))

    fp.add_rule(FingerprintRule(
        name="scoring_https_8443",
        dst_port=8443,
        min_bytes=50,
        max_bytes=100000,
        scoring=True
    ))

    # REST API scoring endpoint
    fp.add_rule(FingerprintRule(
        name="scoring_api_5000",
        dst_port=5000,
        min_bytes=50,
        max_bytes=50000,
        scoring=True
    ))

    # Alternative web score server
    fp.add_rule(FingerprintRule(
        name="scoring_http_9000",
        dst_port=9000,
        contains_bytes=b"HTTP",
        min_bytes=50,
        max_bytes=100000,
        scoring=True
    ))

    # SSH scoring service (legitimate SSH access for scoring checks)
    fp.add_rule(FingerprintRule(
        name="scoring_ssh_22",
        dst_port=22,
        min_bytes=300,  # legitimate SSH handshake + auth data
        max_bytes=50000,
        scoring=True
    ))

    # ICMP scoring service (ping-based health checks)
    fp.add_rule(FingerprintRule(
        name="scoring_icmp",
        src_port=None,
        dst_port=None,
        min_bytes=8,   # ICMP echo request/reply minimum
        max_bytes=1500,
        scoring=True
    ))

    ## MALICIOUS DETECTIONS / NOISE PATTERNS ##    
    # Port scanners (rapid small packets to high-numbered ports)
    fp.add_rule(FingerprintRule(
        name="port_scan_syn",
        dst_port=None,  # any port
        min_bytes=0,
        max_bytes=100,  # tiny packets = scan-like
        scoring=False
    ))

    # UDP floods (small packets to random high ports)
    fp.add_rule(FingerprintRule(
        name="udp_flood_31337",
        dst_port=31337,
        min_bytes=0,
        max_bytes=None,
        scoring=False
    ))

    # Noisy telemetry/monitoring that shouldn't affect scoring
    fp.add_rule(FingerprintRule(
        name="snmp_noise_161",
        dst_port=161,
        min_bytes=40,
        max_bytes=500,
        scoring=False
    ))

    # DNS queries (often noise/scanning)
    fp.add_rule(FingerprintRule(
        name="dns_queries_53",
        dst_port=53,
        min_bytes=12,
        max_bytes=512,
        scoring=False
    ))

    # SSH brute forces (small login attempts)
    fp.add_rule(FingerprintRule(
        name="ssh_bruteforce_22",
        dst_port=22,
        min_bytes=20,
        max_bytes=300,
        scoring=False
    ))

    # NTP (time sync - often used in DDoS)
    fp.add_rule(FingerprintRule(
        name="ntp_noise_123",
        dst_port=123,
        min_bytes=48,
        max_bytes=48,
        scoring=False
    ))

    return fp

