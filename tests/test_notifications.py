import copy
import csv
import io
import os
import smtplib
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from ssh_guard.notifications import NotificationEngine, SMTPTransport


CONFIG = {
    "notifications": {
        "digest_interval_seconds": 3600,
        "thresholds": [10, 50, 100],
        "threshold_cooldown_seconds": 300,
        "poll_seconds": 2,
        "retry_seconds": 60,
        "send_empty_digest": False,
    },
    "smtp": {
        "enabled": True, "host": "smtp.example.com", "port": 587,
        "mode": "starttls", "from_addr": "guard@example.com",
        "recipients": ["one@example.com", "two@example.com"],
        "username": "", "password_env": "SSH_GUARD_SMTP_PASSWORD",
        "timeout_seconds": 15, "subject_prefix": "SSH Guard",
    },
}


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.temporary.name, "test.sqlite3")
        self.config = copy.deepcopy(CONFIG)
        self.config["database"] = self.path
        self.db = sqlite3.connect(self.path)
        self.db.executescript("""
            CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            INSERT INTO meta VALUES('created_at','0');
            CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,occurred_at REAL NOT NULL,minute INTEGER NOT NULL);
            CREATE TABLE bans(ip TEXT PRIMARY KEY,first_banned_at REAL,banned_at REAL,
                active INTEGER,unbanned_at REAL);
        """)
        self.messages = []
        self.engine = NotificationEngine(self.config, sender=self.send)

    def tearDown(self):
        self.engine.close()
        self.db.close()
        self.temporary.cleanup()

    def send(self, message, recipients):
        self.messages.append((message, recipients))
        return {}

    def insert(self, count, timestamp, offset=0):
        for number in range(count):
            address = f"2001:db8::{number + offset + 1:x}"
            self.db.execute("INSERT INTO events(ip,occurred_at,minute) VALUES(?,?,?)",
                            (address, timestamp, int(timestamp // 60) * 60))
            self.db.execute("INSERT OR IGNORE INTO bans VALUES(?,?,?,1,NULL)",
                            (address, timestamp, timestamp))
        self.db.commit()

    def outbox(self, kind=None):
        query = "SELECT * FROM notification_outbox"
        if kind:
            return self.db.execute(query + " WHERE kind=?", (kind,)).fetchall()
        return self.db.execute(query).fetchall()

    def test_highest_crossed_threshold_only_and_restart_no_repeat(self):
        self.insert(105, 10)
        self.engine.tick(11)
        self.assertEqual(len(self.outbox("rate")), 1)
        self.assertIn("eşik 100", str(self.messages[0][0]["Subject"]))
        self.engine.close()
        self.engine = NotificationEngine(self.config, sender=self.send)
        self.engine.tick(12)
        self.assertEqual(len(self.messages), 1)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM notification_alert_seen").fetchone()[0], 3)

    def test_higher_crossing_same_minute_and_persisted_cooldown(self):
        self.insert(10, 10)
        self.engine.tick(11)
        self.insert(40, 20, 10)
        self.engine.tick(21)
        self.assertEqual(len(self.outbox("rate")), 2)
        self.insert(10, 70, 100)
        self.engine.close()
        self.engine = NotificationEngine(self.config, sender=self.send)
        self.engine.tick(71)
        self.assertEqual(len(self.outbox("rate")), 2)
        self.insert(10, 370, 200)
        self.engine.tick(371)
        self.assertEqual(len(self.outbox("rate")), 3)

    def test_reban_in_same_minute_counts_distinct_ips(self):
        self.insert(9, 10)
        self.insert(9, 20)
        self.engine.tick(21)
        self.assertEqual(len(self.outbox("rate")), 0)
        self.insert(1, 30, 20)
        self.engine.tick(31)
        self.assertEqual(len(self.outbox("rate")), 1)

    def test_restart_catches_completed_minute_and_late_commit(self):
        self.engine.tick(61)
        self.insert(10, 59)
        self.engine.tick(62)
        self.assertEqual(len(self.outbox("rate")), 1)
        self.insert(50, 180, 50)
        self.engine.close()
        self.engine = NotificationEngine(self.config, sender=self.send)
        self.engine.tick(500)
        self.assertEqual(len(self.outbox("rate")), 2)

    def test_partial_recipient_retry_is_persisted_without_repeating_acceptance(self):
        self.insert(10, 1)
        calls = []
        def partial(message, recipients):
            calls.append((message["Message-ID"], recipients))
            return {"two@example.com": (450, b"try later")}
        self.engine.sender = partial
        self.engine.tick(2)
        self.engine.close()
        self.engine = NotificationEngine(self.config, sender=self.send)
        self.engine.tick(61)
        self.assertEqual(len(self.messages), 0)
        self.engine.tick(62)
        self.assertEqual(self.messages[0][1], ["two@example.com"])
        self.assertEqual(self.messages[0][0]["Message-ID"], calls[0][0])
        states = self.db.execute("SELECT accepted_at FROM notification_recipients").fetchall()
        self.assertTrue(all(state[0] is not None for state in states))

    def test_refused_all_and_transport_failure_never_drop_mail(self):
        self.insert(10, 1)
        self.engine.sender = MagicMock(side_effect=smtplib.SMTPRecipientsRefused(
            {"one@example.com": (550, b"no"), "two@example.com": (450, b"later")}))
        self.engine.tick(2)
        self.engine.sender = MagicMock(side_effect=OSError("network down"))
        self.engine.tick(62)
        self.assertEqual(len(self.outbox()), 1)
        self.assertEqual(self.db.execute("SELECT SUM(attempts) FROM notification_recipients").fetchone()[0], 4)
        self.engine.sender = self.send
        self.engine.tick(182)
        self.assertEqual(set(self.messages[0][1]), set(self.config["smtp"]["recipients"]))

    def test_digest_all_ips_attached_without_truncation_and_no_replay(self):
        self.config["notifications"]["thresholds"] = []
        self.insert(1200, 100)
        self.engine.tick(3599)
        self.assertEqual(len(self.messages), 0)
        self.engine.tick(3600)
        message = self.messages[0][0]
        attachment = list(message.iter_attachments())[0]
        records = list(csv.DictReader(io.StringIO(attachment.get_content())))
        self.assertEqual(len(records), 1200)
        self.assertEqual(records[-1]["ip"], "2001:db8::4b0")
        self.engine.tick(7200)
        self.assertEqual(len(self.messages), 1)
        self.insert(1, 100, 1300)  # a late row with an old timestamp
        self.engine.tick(10800)
        self.assertEqual(len(self.messages), 2)
        self.assertEqual(len(list(csv.DictReader(io.StringIO(
            list(self.messages[1][0].iter_attachments())[0].get_content())))), 1)

    def test_failed_digest_interval_remains_queued_while_next_interval_advances(self):
        self.config["notifications"]["thresholds"] = []
        self.insert(1, 100)
        self.engine.sender = MagicMock(side_effect=OSError("offline"))
        self.engine.tick(3600)
        self.insert(1, 3700, 1)
        self.engine.tick(7200)
        self.assertEqual(len(self.outbox("digest")), 2)
        self.engine.sender = self.send
        self.engine.tick(7320)
        self.engine.tick(7321)
        self.assertEqual(len(self.messages), 2)
        ip_sets = [set(row["ip"] for row in csv.DictReader(io.StringIO(
            list(message.iter_attachments())[0].get_content()))) for message, _ in self.messages]
        self.assertEqual(ip_sets, [{"2001:db8::1"}, {"2001:db8::2"}])

    def test_disabled_smtp_does_not_consume_watermarks(self):
        self.config["smtp"]["enabled"] = False
        self.insert(10, 1)
        self.engine.tick(3600)
        self.assertEqual(len(self.outbox()), 0)
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM meta WHERE key LIKE 'notification_%'").fetchone()[0], 0)

    def test_sender_runs_outside_database_transaction(self):
        self.insert(10, 1)
        def check_transaction(message, recipients):
            # A second connection must be able to write while SMTP is running.
            self.db.execute("INSERT INTO meta VALUES('smtp_write_probe','1')")
            self.db.commit()
            return {}
        self.engine.sender = check_transaction
        self.engine.tick(2)
        self.assertEqual(self.db.execute(
            "SELECT value FROM meta WHERE key='smtp_write_probe'").fetchone()[0], "1")


class SMTPTests(unittest.TestCase):
    def test_starttls_and_rehello_precede_login(self):
        config = copy.deepcopy(CONFIG["smtp"])
        config["username"] = "account"
        client = MagicMock()
        client.send_message.return_value = {}
        with patch("ssh_guard.notifications.smtplib.SMTP", return_value=client), \
             patch.dict(os.environ, {"SSH_GUARD_SMTP_PASSWORD": "test-secret"}):
            message = MagicMock()
            SMTPTransport(config)(message, ["one@example.com"])
        names = [call[0] for call in client.method_calls]
        self.assertEqual(names, ["ehlo", "starttls", "ehlo", "login", "send_message", "quit"])

    def test_quit_failure_does_not_retry_accepted_data(self):
        client = MagicMock()
        client.send_message.return_value = {}
        client.quit.side_effect = OSError("connection already closed")
        with patch("ssh_guard.notifications.smtplib.SMTP", return_value=client):
            self.assertEqual(SMTPTransport(CONFIG["smtp"])(MagicMock(), ["one@example.com"]), {})
        client.close.assert_called_once()

    def test_insecure_transport_rejected(self):
        config = copy.deepcopy(CONFIG["smtp"])
        config["mode"] = "plain"
        with self.assertRaises(ValueError):
            SMTPTransport(config)(MagicMock(), ["one@example.com"])


if __name__ == "__main__":
    unittest.main()
