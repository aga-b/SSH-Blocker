"""Persistent email digests and rate alerts, isolated from the banning loop.

SMTP server acceptance is recorded per recipient. A crash after server acceptance
but before the SQLite commit can cause a duplicate; SMTP cannot provide exactly
once delivery. The stable Message-ID helps downstream duplicate detection.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import smtplib
import sqlite3
import ssl
import threading
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from typing import Callable


LOG = logging.getLogger(__name__)


def _utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")


class SMTPTransport:
    """TLS-only transport returning the SMTP dictionary of refused recipients."""

    def __init__(self, config: dict):
        self.config = config

    def __call__(self, message: EmailMessage, recipients: list[str]) -> dict:
        config = self.config
        mode = config["mode"]
        if mode not in {"starttls", "ssl"}:
            raise ValueError("SMTP mode must be 'starttls' or 'ssl'")
        password = None
        if config.get("username"):
            variable = config["password_env"]
            password = os.environ.get(variable)
            if not password:
                raise ValueError("SMTP password environment variable is missing or empty")
        context = ssl.create_default_context()
        arguments = {
            "host": config["host"],
            "port": config["port"],
            "timeout": config.get("timeout_seconds", 15),
        }
        if mode == "ssl":
            client = smtplib.SMTP_SSL(context=context, **arguments)
        else:
            client = smtplib.SMTP(**arguments)
        try:
            client.ehlo()
            if mode == "starttls":
                client.starttls(context=context)
                client.ehlo()
            if config.get("username"):
                client.login(config["username"], password)
            # send_message may partially succeed: only its returned keys failed.
            refused = client.send_message(
                message, from_addr=message["From"], to_addrs=recipients
            )
            return refused
        finally:
            # A QUIT/disconnect error after successful DATA must not turn known
            # acceptance into a retry to already accepted recipients.
            try:
                client.quit()
            except Exception:
                client.close()


class NotificationEngine:
    """Call tick from one background thread; never share its DB connection."""

    def __init__(
        self,
        config: dict,
        db_path: str | None = None,
        sender: Callable[[EmailMessage, list[str]], dict] | None = None,
    ):
        self.config = config
        self.options = config["notifications"]
        self.smtp = config["smtp"]
        self.sender = sender or SMTPTransport(self.smtp)
        self.db = sqlite3.connect(db_path or config["database"], timeout=5, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self._schema()

    def _schema(self) -> None:
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS notification_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at REAL NOT NULL,
                message_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notification_recipients (
                outbox_id INTEGER NOT NULL REFERENCES notification_outbox(id),
                recipient TEXT NOT NULL,
                accepted_at REAL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at REAL NOT NULL DEFAULT 0,
                last_error TEXT,
                PRIMARY KEY (outbox_id, recipient)
            );
            CREATE INDEX IF NOT EXISTS notification_recipients_due
                ON notification_recipients(accepted_at, next_attempt_at);
            CREATE TABLE IF NOT EXISTS notification_alert_seen (
                minute INTEGER NOT NULL,
                threshold INTEGER NOT NULL,
                PRIMARY KEY (minute, threshold)
            );
            CREATE TABLE IF NOT EXISTS notification_threshold_state (
                threshold INTEGER PRIMARY KEY,
                last_queued_at REAL NOT NULL
            );
            """
        )

    def close(self) -> None:
        self.db.close()

    def _get(self, key: str, default: float) -> float:
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return float(row[0]) if row is not None else default

    def _set(self, key: str, value: float | int) -> None:
        self.db.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )

    def _queue(self, key: str, kind: str, subject: str, body: str,
               now: float, attachment: str | None = None) -> None:
        payload = {
            "subject": f"[{self.smtp.get('subject_prefix', 'SSH Guard')}] {subject}",
            "body": body,
            "from_addr": self.smtp["from_addr"],
            "recipients": list(dict.fromkeys(self.smtp["recipients"])),
            "attachment": attachment,
        }
        cursor = self.db.execute(
            "INSERT OR IGNORE INTO notification_outbox"
            "(event_key,kind,payload,created_at,message_id) VALUES(?,?,?,?,?)",
            (key, kind, json.dumps(payload, ensure_ascii=False), now,
             make_msgid(domain="ssh-guard.local")),
        )
        if cursor.rowcount:
            self.db.executemany(
                "INSERT INTO notification_recipients(outbox_id,recipient) VALUES(?,?)",
                [(cursor.lastrowid, recipient) for recipient in payload["recipients"]],
            )

    def _queue_alerts(self, now: float) -> None:
        last_id = int(self._get("notification_alert_event_id", 0))
        upper = self.db.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0]
        if upper <= last_id:
            return
        # Using event IDs also catches a prior-minute event committed after a tick
        # at minute rollover, and catches all buckets missed during a restart.
        buckets = self.db.execute(
            "SELECT minute,COUNT(DISTINCT ip) AS rate FROM events "
            "WHERE minute IN (SELECT DISTINCT minute FROM events WHERE id>? AND id<=?) "
            "GROUP BY minute ORDER BY minute", (last_id, upper)
        ).fetchall()
        thresholds = sorted(set(self.options["thresholds"]))
        cooldown = self.options["threshold_cooldown_seconds"]
        for bucket in buckets:
            minute, rate = bucket["minute"], bucket["rate"]
            crossed = []
            eligible = []
            for threshold in thresholds:
                if threshold > rate:
                    break
                already = self.db.execute(
                    "SELECT 1 FROM notification_alert_seen WHERE minute=? AND threshold=?",
                    (minute, threshold),
                ).fetchone()
                if already:
                    continue
                crossed.append(threshold)
                previous = self.db.execute(
                    "SELECT last_queued_at FROM notification_threshold_state WHERE threshold=?",
                    (threshold,),
                ).fetchone()
                if previous is None or now - previous[0] >= cooldown:
                    eligible.append(threshold)
            if eligible:
                threshold = max(eligible)
                body = (
                    f"SSH engelleme hızı eşiği aşıldı.\n\n"
                    f"UTC dakika başlangıcı: {_utc(minute)}\n"
                    f"Bu dakikada başarıyla engellenen farklı IP sayısı: {rate}\n"
                    f"Uyarı eşiği: {threshold} IP/dakika\n"
                    f"Uyarının kuyruğa alınma zamanı: {_utc(now)}\n\n"
                    "Aynı IP'nin aynı dakika içindeki tekrarları hızı artırmaz.\n"
                    "IP adreslerinin tamamı dönemsel özetin CSV ekinde bulunur.\n"
                )
                self._queue(f"rate:{minute}:{threshold}", "rate",
                            f"Hız uyarısı: {rate} IP/dakika (eşik {threshold})", body, now)
                # One jump crossing several levels sends one highest-level email.
                # Its lower levels share that suppression period as well.
                self.db.executemany(
                    "INSERT INTO notification_threshold_state(threshold,last_queued_at) "
                    "VALUES(?,?) ON CONFLICT(threshold) DO UPDATE "
                    "SET last_queued_at=excluded.last_queued_at",
                    [(value, now) for value in thresholds if value <= threshold],
                )
            # Crossings suppressed by cooldown are acknowledged, not postponed.
            self.db.executemany(
                "INSERT OR IGNORE INTO notification_alert_seen(minute,threshold) VALUES(?,?)",
                [(minute, value) for value in crossed],
            )
        self._set("notification_alert_event_id", upper)

    def _queue_digest(self, now: float) -> None:
        interval = self.options["digest_interval_seconds"]
        started = self._get("created_at", now)
        last_at = self._get("notification_digest_at", started)
        if now < last_at + interval:
            return
        last_id = int(self._get("notification_digest_event_id", 0))
        rows = self.db.execute(
            "SELECT id,ip,occurred_at,minute FROM events WHERE id>? ORDER BY id", (last_id,)
        ).fetchall()
        upper = rows[-1]["id"] if rows else last_id
        if rows or self.options.get("send_empty_digest", False):
            buffer = io.StringIO(newline="")
            writer = csv.writer(buffer)
            writer.writerow(["event_id", "ip", "blocked_at_utc", "minute_utc"])
            rates: dict[int, set[str]] = {}
            for row in rows:
                writer.writerow([row["id"], row["ip"], _utc(row["occurred_at"]),
                                 _utc(row["minute"])])
                rates.setdefault(row["minute"], set()).add(row["ip"])
            peak_minute = max(rates, key=lambda value: len(rates[value])) if rates else None
            peak = len(rates[peak_minute]) if peak_minute is not None else 0
            active = self.db.execute("SELECT COUNT(*) FROM bans WHERE active=1").fetchone()[0]
            body = (
                f"SSH engelleme özeti\n\n"
                f"Önceki özet sınırı (UTC): {_utc(last_at)}\n"
                f"Bu özet sınırı (UTC): {_utc(now)}\n"
                f"Dönemdeki başarılı engelleme sayısı: {len(rows)}\n"
                f"Dönemde engellenen farklı IP sayısı: {len({row['ip'] for row in rows})}\n"
                f"Halen engelli IP sayısı: {active}\n"
                f"Dönemdeki en yüksek dakika hızı: {peak} IP/dakika\n"
                f"Tepe dakikası (UTC): {_utc(peak_minute) if peak_minute is not None else '-'}\n\n"
                "Dönemdeki tüm engelleme kayıtları blocked_ips.csv ekindedir.\n"
                "Kayıtlar kalıcı sıra numarasıyla izlenir; e-posta kesintisinde kaybolmaz.\n"
            )
            self._queue(f"digest:{last_id}:{upper}:{now}", "digest",
                        f"Engelleme özeti: {len(rows)} kayıt", body, now, buffer.getvalue())
        # Advance only in the same transaction that durably snapshots the email.
        # SMTP failure cannot consume an interval because its outbox still exists.
        self._set("notification_digest_event_id", upper)
        self._set("notification_digest_at", now)

    def _message(self, row: sqlite3.Row) -> EmailMessage:
        payload = json.loads(row["payload"])
        message = EmailMessage()
        message["Subject"] = payload["subject"]
        message["From"] = payload["from_addr"]
        message["To"] = ", ".join(payload["recipients"])
        message["Message-ID"] = row["message_id"]
        message["Date"] = format_datetime(datetime.fromtimestamp(row["created_at"], timezone.utc))
        message.set_content(payload["body"])
        if payload["attachment"] is not None:
            message.add_attachment(payload["attachment"], subtype="csv",
                                   filename="blocked_ips.csv")
        return message

    def _deliver(self, now: float) -> None:
        # Limit each tick's network work so a large old outbox cannot indefinitely
        # delay scanning new rate crossings. SMTP has a bounded socket timeout.
        outbox = self.db.execute(
            "SELECT DISTINCT o.* FROM notification_outbox o "
            "JOIN notification_recipients r ON r.outbox_id=o.id "
            "WHERE r.accepted_at IS NULL AND r.next_attempt_at<=? "
            "ORDER BY o.id LIMIT 1", (now,)
        ).fetchall()
        for row in outbox:
            pending = self.db.execute(
                "SELECT recipient,attempts FROM notification_recipients "
                "WHERE outbox_id=? AND accepted_at IS NULL AND next_attempt_at<=?",
                (row["id"], now),
            ).fetchall()
            recipients = [item["recipient"] for item in pending]
            try:
                refused = self.sender(self._message(row), recipients) or {}
                errors = {recipient: "SMTP recipient refused" for recipient in refused}
            except smtplib.SMTPRecipientsRefused as error:
                errors = {recipient: "SMTP recipient refused" for recipient in error.recipients}
                # This exception means that no recipient accepted this message.
                errors.update({recipient: "SMTP recipient refused" for recipient in recipients})
            except Exception as error:
                # Do not persist raw SMTP error text: it can contain credentials.
                errors = {recipient: type(error).__name__ for recipient in recipients}
            self.db.execute("BEGIN IMMEDIATE")
            try:
                for item in pending:
                    recipient = item["recipient"]
                    if recipient in errors:
                        delay = min(3600, self.options["retry_seconds"] *
                                    (2 ** min(item["attempts"], 10)))
                        self.db.execute(
                            "UPDATE notification_recipients SET attempts=attempts+1,"
                            "next_attempt_at=?,last_error=? WHERE outbox_id=? AND recipient=?",
                            (now + delay, errors[recipient], row["id"], recipient),
                        )
                    else:
                        self.db.execute(
                            "UPDATE notification_recipients SET accepted_at=?,attempts=attempts+1,"
                            "last_error=NULL WHERE outbox_id=? AND recipient=?",
                            (now, row["id"], recipient),
                        )
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
            if errors:
                LOG.warning("Email outbox %s: %s recipient(s) require retry",
                            row["id"], len(errors))

    def tick(self, now: float | None = None) -> None:
        if not self.smtp.get("enabled", True):
            return
        now = time.time() if now is None else now
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._queue_alerts(now)
            self._queue_digest(now)
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        # No SQLite transaction or main-thread firewall work waits for SMTP.
        self._deliver(now)


class NotificationWorker:
    def __init__(self, config: dict, db_path: str | None = None):
        self.config = config
        self.db_path = db_path
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="ssh-guard-mail", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self, timeout: float | None = None) -> None:
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout=timeout)

    def _run(self) -> None:
        engine = None
        try:
            while not self.stop_event.is_set():
                try:
                    if engine is None:
                        engine = NotificationEngine(self.config, self.db_path)
                    engine.tick()
                except Exception as error:
                    LOG.error("Notification worker tick failed: %s", type(error).__name__)
                self.stop_event.wait(self.config["notifications"]["poll_seconds"])
        finally:
            if engine is not None:
                engine.close()
