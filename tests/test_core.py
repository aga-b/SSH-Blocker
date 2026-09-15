import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from ssh_guard.config import ConfigError, is_allowed, validate
from ssh_guard.storage import Store


def example_config():
    return json.loads((Path(__file__).resolve().parents[1] / "config.conf").read_text())


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "state.sqlite3")
        self.store = Store(self.path)
        self.config = example_config()
        self.config["database"] = self.path

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_config_rejects_unsafe_and_typo_values(self):
        validate(self.config)
        for section, key, value in [(None, "firewall_table", "bad; drop"),
                                    ("smtp", "mode", "plain"),
                                    ("smtp", "recipients", ["a@example.org\nBcc:x@example.org"]),
                                    ("notifications", "thresholds", [100, 10]),
                                    (None, "reconcile_seconds", True)]:
            config = copy.deepcopy(self.config)
            (config[section] if section else config)[key] = value
            with self.assertRaises(ConfigError):
                validate(config)
        config = copy.deepcopy(self.config)
        config["unknown"] = 1
        with self.assertRaises(ConfigError):
            validate(config)

    def test_ip_and_cidr_allowlist(self):
        self.config["allowlist"] += ["192.0.2.0/24", "2001:db8::/32"]
        self.assertTrue(is_allowed("192.0.2.14", self.config))
        self.assertTrue(is_allowed("2001:db8::a", self.config))
        self.assertFalse(is_allowed("198.51.100.1", self.config))

    def test_persistence_dedup_and_calendar_minute_rate(self):
        with self.store.transaction():
            self.assertTrue(self.store.record_ban("192.0.2.1", 119))
            self.assertFalse(self.store.record_ban("192.0.2.1", 119))
            self.store.record_unban("192.0.2.1", 119.2)
            self.store.record_ban("192.0.2.1", 119.5)
            self.store.record_ban("192.0.2.2", 120)
        self.assertEqual(self.store.rates(2, now=120), [{"minute": 60, "blocked_ips": 1}, {"minute": 120, "blocked_ips": 1}])
        self.store.close()
        self.store = Store(self.path)
        self.assertEqual(self.store.active_ips(), ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 3)

    def test_transaction_rollback(self):
        with self.assertRaises(RuntimeError):
            with self.store.transaction():
                self.store.record_ban("192.0.2.1", 120)
                self.store.set_meta("journal_cursor", "new")
                raise RuntimeError("failure")
        self.assertEqual(self.store.active_ips(), [])
        self.assertIsNone(self.store.get_meta("journal_cursor"))

    def entry(self, cursor="c1", ip="192.0.2.1"):
        return {"__CURSOR": cursor, "_SYSTEMD_UNIT": "ssh.service", "_COMM": "sshd",
                "MESSAGE": f"Failed password for root from {ip} port 50001 ssh2"}

    def test_firewall_failure_never_counts_or_advances_cursor(self):
        from ssh_guard.service import process_entry
        firewall = Mock()
        firewall.ban.side_effect = RuntimeError("nft failed")
        with self.assertRaises(RuntimeError):
            process_entry(self.store, firewall, self.config, self.entry(), now=120)
        self.assertEqual(self.store.active_ips(), [])
        self.assertIsNone(self.store.get_meta("journal_cursor"))
        firewall.ban.side_effect = None
        self.assertTrue(process_entry(self.store, firewall, self.config, self.entry(), now=121))
        self.assertFalse(process_entry(self.store, firewall, self.config, self.entry(), now=122))
        self.assertFalse(process_entry(self.store, firewall, self.config, self.entry("c2"), now=123))
        self.assertEqual(self.store.rates(1, now=123)[0]["blocked_ips"], 1)

    def test_allowlist_advances_cursor_without_ban(self):
        from ssh_guard.service import process_entry
        firewall = Mock()
        self.assertFalse(process_entry(self.store, firewall, self.config, self.entry(ip="127.0.0.1")))
        firewall.ban.assert_not_called()
        self.assertEqual(self.store.get_meta("journal_cursor"), "c1")

    def test_unban_failures_and_allowlist_reconcile(self):
        from ssh_guard.service import reconcile, unban
        firewall = Mock()
        with self.store.transaction():
            self.store.record_ban("192.0.2.1", 120)
        firewall.unban.side_effect = RuntimeError("nft failed")
        with self.assertRaises(RuntimeError):
            unban(self.store, firewall, self.config, "192.0.2.1", now=130)
        self.assertTrue(self.store.is_active("192.0.2.1"))
        firewall.unban.side_effect = None
        self.assertTrue(unban(self.store, firewall, self.config, "192.0.2.1", now=130))
        with self.store.transaction():
            self.store.record_ban("127.0.0.1", 140)
        reconcile(self.store, firewall, self.config, force=True)
        firewall.reconcile.assert_called_once_with([])
        self.assertEqual(self.store.active_ips(), [])


if __name__ == "__main__":
    unittest.main()
