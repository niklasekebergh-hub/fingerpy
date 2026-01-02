import sqlite3
import time
from typing import Optional, Tuple

DB_PATH = "netmon.db"

conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)
cursor = conn.cursor()

def init_db():
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS hosts (
            ip TEXT PRIMARY KEY,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP
        )
        """)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS services (
            ip TEXT,
            port INTEGER,
            service_name TEXT,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            PRIMARY KEY (ip, port)
        ) 
        """)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS flows (
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            packets INTEGER,
            bytes INTEGER,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            PRIMARY KEY (src_ip, dst_ip, src_port, dst_port, protocol)
        )
        """)
def update_host(ip: str, first_seen: float, last_seen: float) -> None:
    cursor.execute(
        """
        INSERT INTO hosts (ip, first_seen, last_seen)
        VALUES (?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen
        """,
        (ip, first_seen, last_seen)
    )
def update_service(ip: str, port: int, service_name: str, first_seen: float, last_seen: float) -> None:
    cursor.execute(
        """
        INSERT INTO services (ip, port, service_name, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip, port) DO UPDATE SET last_seen=excluded.last_seen
        """,
        (ip, port, service_name, first_seen, last_seen)
    )
def update_flow(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    packets: int,
    bytes_count: int,
    first_seen: float,
    last_seen: float
) -> None:
    cursor.execute(
        """
        INSERT INTO flows (src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(src_ip, dst_ip, src_port, dst_port, protocol) DO UPDATE 
        SET packets=excluded.packets, bytes=excluded.bytes, last_seen=excluded.last_seen
        """,
        (src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes_count, first_seen, last_seen)
    )