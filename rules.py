from fingerprinting_core import Fingerprinter, FingerprintRule


def build_default_fingerprinter(server_ip: str) -> Fingerprinter:
    fp = Fingerprinter(server_ip=server_ip)

    # === SCORING / LEGITIMATE SERVICES ===
    # HTTP on common scoring ports.
    fp.add_rule(
        FingerprintRule(
            name="scoring_http_80",
            dst_port=80,
            proto="tcp",
            min_bytes=1,
            scoring=True,
        )
    )
    fp.add_rule(
        FingerprintRule(
            name="scoring_http_8080",
            dst_port=8080,
            proto="tcp",
            min_bytes=1,
            scoring=True,
        )
    )
    fp.add_rule(
        FingerprintRule(
            name="scoring_http_8000",
            dst_port=8000,
            proto="tcp",
            min_bytes=1,
            scoring=True,
        )
    )

    # HTTPS
    fp.add_rule(
        FingerprintRule(
            name="scoring_https_443",
            dst_port=443,
            proto="tcp",
            min_bytes=1,
            scoring=True,
        )
    )

    # SSH – we mark it as scoring so that the tool will *never* recommend
    # dropping it automatically.
    fp.add_rule(
        FingerprintRule(
            name="scoring_ssh_22",
            dst_port=22,
            proto="tcp",
            min_bytes=1,
            scoring=True,
        )
    )

    # DNS – same logic: important infra, don't auto-drop.
    fp.add_rule(
        FingerprintRule(
            name="scoring_dns_53_udp",
            dst_port=53,
            proto="udp",
            min_bytes=1,
            scoring=True,
        )
    )

    # === NOISE / SUSPICIOUS PATTERNS ===
    # NTP amplification probes (very stereotyped 48-byte UDP packets).
    fp.add_rule(
        FingerprintRule(
            name="ntp_noise_123",
            dst_port=123,
            proto="udp",
            min_bytes=48,
            max_bytes=48,
            scoring=False,
        )
    )

    # SSDP / UPnP floods (UDP/1900) – rarely needed on a scored server.
    fp.add_rule(
        FingerprintRule(
            name="ssdp_noise_1900",
            dst_port=1900,
            proto="udp",
            min_bytes=100,
            scoring=False,
        )
    )

    # Generic RDP noise (often not used on Linux scoring boxes).
    fp.add_rule(
        FingerprintRule(
            name="rdp_noise_3389",
            dst_port=3389,
            proto="tcp",
            min_bytes=40,
            scoring=False,
        )
    )

    return fp
