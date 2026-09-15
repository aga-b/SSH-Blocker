"""Durable state. Every firewall mutation is serialized by BEGIN IMMEDIATE."""

import contextlib
import ipaddress
import sqlite3
import time
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS bans (
    ip TEXT PRIMARY KEY,
    first_banned_at REAL NOT NULL,
    banned_at REAL NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0,1)),
    unbanned_at REAL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    occurred_at REAL NOT NULL,
    minute INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_minute ON events(minute, ip);
CREATE TABLE IF NOT EXISTS unbans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    occurred_at REAL NOT NULL,
    reason TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path):
        Path(path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=30, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.executescript(SCHEMA)
        self.db.execute("INSERT OR IGNORE INTO meta VALUES ('created_at', ?)", (str(time.time()),))

    def close(self):
        self.db.close()

    @contextlib.contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield self
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def get_meta(self, key, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_meta(self, key, value):
        self.db.execute("INSERT INTO meta VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

    def active_ips(self):
        return [row[0] for row in self.db.execute("SELECT ip FROM bans WHERE active=1 ORDER BY ip")]

    def is_active(self, ip):
        row = self.db.execute("SELECT active FROM bans WHERE ip=?", (ip,)).fetchone()
        return bool(row and row[0])

    def record_ban(self, ip, now):
        """Only call after nft succeeds, inside a transaction including the cursor."""
        ip = str(ipaddress.ip_address(ip))
        if self.is_active(ip):
            return False
        self.db.execute("""INSERT INTO bans VALUES (?,?,?,1,NULL)
            ON CONFLICT(ip) DO UPDATE SET banned_at=excluded.banned_at, active=1, unbanned_at=NULL""", (ip, now, now))
        self.db.execute("INSERT INTO events(ip,occurred_at,minute) VALUES (?,?,?)", (ip, now, int(now // 60) * 60))
        return True

    def record_unban(self, ip, now, reason="manual"):
        if not self.is_active(ip):
            return False
        self.db.execute("UPDATE bans SET active=0,unbanned_at=? WHERE ip=?", (now, ip))
        self.db.execute("INSERT INTO unbans(ip,occurred_at,reason) VALUES (?,?,?)", (ip, now, reason))
        return True

    def list_bans(self, include_inactive=False):
        query = "SELECT * FROM bans" + ("" if include_inactive else " WHERE active=1") + " ORDER BY banned_at DESC, ip"
        return [dict(row) for row in self.db.execute(query)]

    def rates(self, minutes=60, now=None):
        now = time.time() if now is None else now
        current = int(now // 60) * 60
        start = current - (minutes - 1) * 60
        counts = dict(self.db.execute("SELECT minute,COUNT(DISTINCT ip) FROM events WHERE minute BETWEEN ? AND ? GROUP BY minute", (start, current)))
        return [{"minute": minute, "blocked_ips": counts.get(minute, 0)} for minute in range(start, current + 1, 60)]
