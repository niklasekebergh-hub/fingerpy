from fingerprint_core import Fingerprinter, FingerprintRule

def build_default_fingerprinter(server_ip: str) -> Fingerprinter:
    fp = Fingerprinter(server_ip=server_ip)

    # Example: scoring web service on port 8080, smallish HTTP responses,
    # first payload includes "HTTP/1.1"
    fp.add_rule(FingerprintRule(
        name="scoring_http_8080",
        dst_port=8080,
        contains_bytes=b"HTTP/1.1",
        min_bytes=100,
        max_bytes=100000,  # 100 KB
        scoring=True
    ))

    # Example: noisy UDP flood to port 31337
    fp.add_rule(FingerprintRule(
        name="udp_noise_31337",
        dst_port=31337,
        min_bytes=0,
        max_bytes=None,
        scoring=False
    ))

    return fp
