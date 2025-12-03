import sqlite3

def get_conn():
    return sqlite3.connect("netmon.db")

def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        role TEXT DEFAULT 'unknown'
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        alert_type TEXT NOT NULL,
        reason TEXT NOT NULL,
        ts TEXT NOT NULL
    );
    """)

    conn.commit()
    conn.close()