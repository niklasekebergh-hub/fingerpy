import sqlite3
import time
from typing import Optional, Tuple

DB_PATH = "netmon.db"


def get_conn() -> sqlite3.Connection:
    """
    Return a new sqlite3 connection. Callers are responsible for closing it.
    """
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    """
    Initialize the competition database if it does not already exist.

    The schema is intentionally simple and competition-focused:

    - hosts:    one row per IP we have seen.
    - services: one row per (host, port, proto) we have seen, with counters.
    - alerts:   one row per interesting / suspicious observation.
    """
    conn = get_conn()
    cur = conn.cursor()

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            first_seen REAL NOT NULL,
            last_seen  REAL NOT NULL,
            role TEXT DEFAULT 'unknown'  -- e.g. 'server', 'client', 'scoring', 'noise'
        );

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            proto TEXT NOT NULL,        -- 'tcp' or 'udp'
            classification TEXT NOT NULL,  -- 'scoring', 'noise', 'unknown'
            rule_name TEXT,
            total_bytes INTEGER NOT NULL DEFAULT 0,
            last_seen REAL NOT NULL,
            UNIQUE(host_id, port, proto),
            FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            alert_type TEXT NOT NULL,   -- e.g. 'noise_flow', 'scanner', etc.
            reason TEXT NOT NULL,
            ts REAL NOT NULL,
            FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE SET NULL
        );
        """
    )

    conn.commit()
    conn.close()


def _get_or_create_host(cur: sqlite3.Cursor, ip: str, role: str = "unknown") -> int:
    """
    Return host_id for an IP, creating the row if necessary.
    """
    now = time.time()
    cur.execute("SELECT id, role FROM hosts WHERE ip = ?", (ip,))
    row = cur.fetchone()
    if row:
        host_id, existing_role = row
        # Do not downgrade an existing more-specific role.
        new_role = existing_role if existing_role != "unknown" else role
        cur.execute(
            "UPDATE hosts SET last_seen = ?, role = ? WHERE id = ?",
            (now, new_role, host_id),
        )
        return host_id

    cur.execute(
        "INSERT INTO hosts (ip, first_seen, last_seen, role) VALUES (?, ?, ?, ?)",
        (ip, now, now, role),
    )
    return cur.lastrowid


def record_flow(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    proto: str,
    classification: str,
    rule_name: Optional[str],
    bytes_count: int,
    server_ip: Optional[str] = None,
) -> None:
    """
    Persist a summarized view of a flow to the DB.

    We try to log *server side* information because that's most relevant
    for firewall decisions.
    """
    proto = proto.lower()
    now = time.time()
    conn = get_conn()
    cur = conn.cursor()

    try:
        # Decide which IP is the "host" for the services table.
        # If server_ip is known, use that side as the host.
        if server_ip and dst_ip == server_ip:
            host_ip = dst_ip
            client_ip = src_ip
            host_role = "server"
        elif server_ip and src_ip == server_ip:
            host_ip = src_ip
            client_ip = dst_ip
            host_role = "server"
        else:
            # Fallback: treat dst as "server"
            host_ip = dst_ip
            client_ip = src_ip
            host_role = "unknown"

        host_id = _get_or_create_host(cur, host_ip, role=host_role)
        _get_or_create_host(cur, client_ip, role="client")

        # Upsert into services table.
        cur.execute(
            """
            SELECT id, total_bytes, classification, rule_name
            FROM services
            WHERE host_id = ? AND port = ? AND proto = ?
            """,
            (host_id, dst_port, proto),
        )
        row = cur.fetchone()
        if row:
            svc_id, total_bytes, existing_cls, existing_rule = row
            new_total = total_bytes + bytes_count
            # Prefer a non-unknown classification if we didn't have one before.
            new_cls = existing_cls
            if existing_cls == "unknown" and classification != "unknown":
                new_cls = classification
            # Keep whichever rule name we already have, unless we didn't have one.
            new_rule = existing_rule or rule_name
            cur.execute(
                """
                UPDATE services
                SET total_bytes = ?, last_seen = ?, classification = ?, rule_name = ?
                WHERE id = ?
                """,
                (new_total, now, new_cls, new_rule, svc_id),
            )
        else:
            cur.execute(
                """
                INSERT INTO services (
                    host_id, port, proto, classification, rule_name, total_bytes, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (host_id, dst_port, proto, classification, rule_name, bytes_count, now),
            )

        conn.commit()
    finally:
        conn.close()


def add_alert(ip: Optional[str], alert_type: str, reason: str) -> None:
    """
    Insert an alert row. If ip is provided, we attach it to a host.
    """
    conn = get_conn()
    cur = conn.cursor()
    now = time.time()

    host_id: Optional[int] = None
    if ip:
        cur.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
        row = cur.fetchone()
        if row:
            host_id = row[0]
        else:
            # Create the host row so the alert can link to it.
            host_id = _get_or_create_host(cur, ip, role="unknown")

    cur.execute(
        "INSERT INTO alerts (host_id, alert_type, reason, ts) VALUES (?, ?, ?, ?)",
        (host_id, alert_type, reason, now),
    )
    conn.commit()
    conn.close()


# Best-effort automatic initialization so that importing db
# in a long-running sniffer process does not fail writes.
try:
    init_db()
except Exception:
    # In a misconfigured environment we still want the rest of the
    # tool to run; you can always run init_db() manually.
    pass
