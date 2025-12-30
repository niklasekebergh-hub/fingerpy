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
        
        """
    )

    conn.commit()
    conn.close()


