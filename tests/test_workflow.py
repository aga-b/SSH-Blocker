"""Cross-module flow with a fake kernel/SMTP, real durable SQLite state."""

import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from ssh_guard.notifications import NotificationEngine
from ssh_guard.service import process_entry, reconcile, unban
from ssh_guard.storage import Store


class WorkflowTests(unittest.TestCase):
    def test_failure_ban_alert_digest_restart_and_manual_unban(self):
        with tempfile.TemporaryDirectory() as directory:
            config = json.loads((Path(__file__).resolve().parents[1] / "config.conf").read_text())
            config["database"] = str(Path(directory) / "state.sqlite3")
            config["notifications"]["thresholds"] = [1]
            config["notifications"]["digest_interval_seconds"] = 60
            store = Store(config["database"])
            store.set_meta("created_at", 0)
            firewall = Mock()
            messages = []
            def sender(message, recipients):
                messages.append((message, recipients))
                return {}
            engine = NotificationEngine(config, sender=sender)
            try:
                entry = {"__CURSOR": "first", "_SYSTEMD_UNIT": "ssh.service", "_COMM": "sshd",
                         "MESSAGE": "Failed password for root from 198.51.100.20 port 51000 ssh2"}
                self.assertTrue(process_entry(store, firewall, config, entry, now=10))
                firewall.ban.assert_called_once_with("198.51.100.20")
                engine.tick(11)
                self.assertEqual(len(messages), 1)
                self.assertIn("eşik 1", str(messages[0][0]["Subject"]))
                engine.tick(60)
                self.assertEqual(len(messages), 2)
                self.assertEqual(messages[0][1], messages[1][1])
                attachment = list(messages[1][0].iter_attachments())[0]
                rows = list(csv.DictReader(io.StringIO(attachment.get_content())))
                self.assertEqual([row["ip"] for row in rows], ["198.51.100.20"])
                engine.close()
                store.close()
                store = Store(config["database"])
                engine = NotificationEngine(config, sender=sender)
                reconcile(store, firewall, config, force=True)
                firewall.reconcile.assert_called_once_with(["198.51.100.20"])
                self.assertFalse(process_entry(store, firewall, config, entry, now=62))
                engine.tick(120)
                self.assertEqual(len(messages), 2)
                self.assertTrue(unban(store, firewall, config, "198.51.100.20", now=121))
                self.assertEqual(store.active_ips(), [])
                self.assertEqual(store.rates(minutes=3, now=121)[0]["blocked_ips"], 1)
                self.assertFalse(store.list_bans(include_inactive=True)[0]["active"])
            finally:
                engine.close()
                store.close()


if __name__ == "__main__":
    unittest.main()
