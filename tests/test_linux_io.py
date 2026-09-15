import copy
import io
import json
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from ssh_guard.firewall import NftFirewall, OWNER, PRIORITY
from ssh_guard.journal import JournalFollower, parse_failure


def journal_entry(message, **extra):
    return {"_SYSTEMD_UNIT": "ssh.service", "_COMM": "sshd", "MESSAGE": message,
            "__CURSOR": "s=saved;i=1", **extra}


def firewall_state(ips=(), scope="all", ports=(22,)):
    records = [{"metainfo": {"json_schema_version": 1}},
               {"table": {"family": "inet", "name": "ssh_guard", "comment": OWNER, "handle": 1}},
               {"chain": {"family": "inet", "table": "ssh_guard", "name": "input", "type": "filter",
                          "hook": "input", "prio": PRIORITY, "policy": "accept", "handle": 2}}]
    for version in (4, 6):
        records.append({"set": {"family": "inet", "table": "ssh_guard", "name": f"blocked_v{version}",
                                "type": f"ipv{version}_addr", "handle": version + 10,
                                "elem": [ip for ip in ips if (":" in ip) == (version == 6)]}})
    for version in (4, 6):
        expressions = [{"match": {"op": "==", "left": {"payload": {"protocol": "ip" if version == 4 else "ip6", "field": "saddr"}},
                                    "right": f"@blocked_v{version}"}}]
        if scope == "ssh":
            expressions.append({"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                            "right": ports[0] if len(ports) == 1 else {"set": list(ports)}}})
        expressions.append({"drop": None})
        records.append({"rule": {"family": "inet", "table": "ssh_guard", "chain": "input", "handle": version + 20,
                                 "expr": expressions}})
    return records


class ParseFailureTests(unittest.TestCase):
    def test_ipv4_ipv6_and_invalid_user(self):
        for user, ip, expected in [("root", "198.51.100.8", "198.51.100.8"),
                                   ("invalid user someone", "2001:db8:0:0::8", "2001:db8::8"),
                                   ("user", "::ffff:198.51.100.8", "198.51.100.8")]:
            with self.subTest(ip=ip):
                entry = journal_entry(f"Failed password for {user} from {ip} port 45678 ssh2 [preauth]")
                self.assertEqual(parse_failure(entry, ["ssh.service"]), expected)

    def test_username_cannot_inject_victim_address(self):
        message = ("Failed password for invalid user root from 203.0.113.9 port 22 ssh2 "
                   "from 198.51.100.7 port 34567 ssh2")
        self.assertEqual(parse_failure(journal_entry(message), ["ssh.service"]), "198.51.100.7")

    def test_session_process_supported(self):
        entry = journal_entry("Failed password for user from 192.0.2.2 port 1 ssh2", _COMM="sshd-session")
        self.assertEqual(parse_failure(entry, ["ssh.service"]), "192.0.2.2")

    def test_openssh_10_auth_process_supported(self):
        entry = journal_entry("Failed password for user from 192.0.2.2 port 1 ssh2", _COMM="sshd-auth")
        self.assertEqual(parse_failure(entry, ["ssh.service"]), "192.0.2.2")

    def test_untrusted_fields_are_rejected(self):
        good = journal_entry("Failed password for user from 192.0.2.2 port 22 ssh2")
        for extra in [{"_SYSTEMD_UNIT": "cron.service"}, {"_COMM": "logger"},
                      {"_COMM": None, "SYSLOG_IDENTIFIER": "sshd"}, {"_SYSTEMD_UNIT": ["ssh.service"]},
                      {"MESSAGE": [70, 65, 73, 76]}]:
            with self.subTest(extra=extra):
                self.assertIsNone(parse_failure({**good, **extra}, ["ssh.service"]))

    def test_non_failure_malformed_or_injected_logs_are_rejected(self):
        for message in ["Accepted password for root from 192.0.2.2 port 22 ssh2",
                        "Failed publickey for root from 192.0.2.2 port 22 ssh2",
                        "prefix Failed password for root from 192.0.2.2 port 22 ssh2",
                        "Failed password for root from 192.0.2.2 port 22 ssh2 trailing",
                        "Failed password for root from 192.0.2.2 port 22 ssh2\n",
                        "Failed password for root from example.com port 22 ssh2",
                        "Failed password for root from 999.0.0.1 port 22 ssh2",
                        "Failed password for root from fe80::1%eth0 port 22 ssh2",
                        "Failed password for root from 192.0.2.2 port 0 ssh2",
                        "Failed password for root from 192.0.2.2 port 99999 ssh2"]:
            with self.subTest(message=message):
                self.assertIsNone(parse_failure(journal_entry(message), ["ssh.service"]))


class FirewallTests(unittest.TestCase):
    def test_reconcile_is_single_transaction_for_owned_table(self):
        firewall = NftFirewall()
        with patch.object(firewall, "_read_table", return_value=firewall_state()), patch.object(firewall, "_run") as run:
            firewall.reconcile(["198.51.100.8", "2001:db8::1", "198.51.100.8"])
        run.assert_called_once()
        args, script = run.call_args.args
        self.assertEqual(args, ["--file", "-"])
        self.assertTrue(script.startswith('delete table inet "ssh_guard"\nadd table inet "ssh_guard"'))
        self.assertNotIn("flush ruleset", script)
        self.assertIn("ip saddr @blocked_v4 drop", script)
        self.assertIn("ip6 saddr @blocked_v6 drop", script)
        self.assertNotIn("ct state", script)
        self.assertEqual(script.count("198.51.100.8"), 1)

    def test_missing_table_created_and_ssh_scope_ports_restricted(self):
        firewall = NftFirewall(scope="ssh", ssh_ports=[2222, 22])
        with patch.object(firewall, "_read_table", return_value=None), patch.object(firewall, "_run") as run:
            self.assertTrue(firewall.ensure([]))
        script = run.call_args.args[1]
        self.assertNotIn("delete table", script)
        self.assertEqual(script.count("tcp dport { 22, 2222 } drop"), 2)

    def test_ensure_accepts_correct_state_without_writing(self):
        firewall = NftFirewall()
        with patch.object(firewall, "_read_table", return_value=firewall_state(["198.51.100.8"])), patch.object(firewall, "_run") as run:
            self.assertFalse(firewall.ensure(["198.51.100.8"]))
        run.assert_not_called()

    def test_ensure_accepts_scalar_or_anonymous_port_sets(self):
        for ports in ((22,), (22, 2222)):
            firewall = NftFirewall(scope="ssh", ssh_ports=ports)
            with patch.object(firewall, "_read_table", return_value=firewall_state(scope="ssh", ports=ports)), patch.object(firewall, "_run") as run:
                self.assertFalse(firewall.ensure([]))
            run.assert_not_called()

    def test_ensure_repairs_missing_or_changed_rules_chains_sets(self):
        original = firewall_state(["198.51.100.8"])
        variants = []
        state = copy.deepcopy(original)
        state[-1]["rule"]["expr"][-1] = {"accept": None}
        variants.append(state)
        state = copy.deepcopy(original)
        state[2]["chain"]["hook"] = "forward"
        variants.append(state)
        state = copy.deepcopy(original)
        state[3]["set"]["elem"] = []
        variants.append(state)
        state = copy.deepcopy(original)
        state[1]["table"]["flags"] = ["dormant"]
        variants.append(state)
        variants.append(original[:-1])
        for state in variants:
            with self.subTest(state=state):
                firewall = NftFirewall()
                with patch.object(firewall, "_read_table", return_value=state), patch.object(firewall, "_run") as run:
                    self.assertTrue(firewall.ensure(["198.51.100.8"]))
                run.assert_called_once()

    def test_existing_unowned_table_is_never_modified(self):
        firewall = NftFirewall()
        tables = [{"table": {"family": "inet", "name": "ssh_guard"}}]
        with patch.object(firewall, "_json", side_effect=[tables, tables]), patch.object(firewall, "_run") as run:
            with self.assertRaisesRegex(RuntimeError, "unowned"):
                firewall.reconcile([])
        run.assert_not_called()

    def test_invalid_inputs_rejected_before_command(self):
        for settings in [{"table": "safe; flush ruleset"}, {"scope": "anything"}, {"ssh_ports": [True]},
                         {"ssh_ports": [0]}, {"ssh_ports": []}, {"executable": "nft"}]:
            with self.subTest(settings=settings):
                with self.assertRaises(ValueError):
                    NftFirewall(**settings)
        firewall = NftFirewall()
        with patch.object(firewall, "_run") as run:
            for address in ["198.51.100.8; flush ruleset", "192.0.2.0/24", "fe80::1%eth0"]:
                with self.assertRaises(ValueError):
                    firewall.ban(address)
        run.assert_not_called()

    def test_ban_canonicalizes_ipv4_mapped_address(self):
        firewall = NftFirewall()
        with patch.object(firewall, "_run") as run:
            firewall.ban("::ffff:198.51.100.9")
        self.assertEqual(run.call_args.args[1], 'add element inet "ssh_guard" blocked_v4 { 198.51.100.9 }\n')

    def test_unban_is_noop_when_address_missing(self):
        firewall = NftFirewall()
        with patch.object(firewall, "_read_table", return_value=firewall_state()), patch.object(firewall, "_run") as run:
            firewall.unban("198.51.100.8")
        run.assert_not_called()

    def test_unban_deletes_only_present_address(self):
        firewall = NftFirewall()
        with patch.object(firewall, "_read_table", return_value=firewall_state(["198.51.100.8"])), patch.object(firewall, "_run") as run:
            firewall.unban("198.51.100.8")
        self.assertEqual(run.call_args.args[1], 'delete element inet "ssh_guard" blocked_v4 { 198.51.100.8 }\n')

    def test_nft_failure_is_reported_and_shell_is_unused(self):
        result = subprocess.CompletedProcess([], 1, "", "Permission denied")
        with patch("ssh_guard.firewall.subprocess.run", return_value=result) as run:
            with self.assertRaisesRegex(RuntimeError, "Permission denied"):
                NftFirewall().ban("198.51.100.8")
        self.assertIsInstance(run.call_args.args[0], list)
        self.assertFalse(run.call_args.kwargs.get("shell", False))


class JournalFollowerTests(unittest.TestCase):
    @staticmethod
    def process(lines="", stderr="", running=False):
        process = MagicMock()
        process.stdout = io.StringIO(lines)
        process.stderr = io.StringIO(stderr)
        process.poll.return_value = None if running else 1
        return process

    def test_first_start_follows_now_with_all_backlog_and_trusted_filter(self):
        process = self.process(json.dumps(journal_entry("ignored")) + "\n")
        with patch("ssh_guard.journal.subprocess.Popen", return_value=process) as popen:
            follower = JournalFollower(["ssh.service", "sshd.service"])
            follower.start()
            try:
                self.assertEqual(follower.next_event(1)["__CURSOR"], "s=saved;i=1")
            finally:
                follower.stop()
        command = popen.call_args.args[0]
        self.assertIn("--since=now", command)
        self.assertIn("--no-tail", command)
        self.assertIn("_SYSTEMD_UNIT=ssh.service", command)
        self.assertIn("_SYSTEMD_UNIT=sshd.service", command)
        self.assertFalse(popen.call_args.kwargs.get("shell", False))

    def test_cursor_is_verified_then_replayed_after_it(self):
        cursor = "s=saved;i=1"
        result = subprocess.CompletedProcess([], 0, json.dumps({"__CURSOR": cursor}) + "\n", "")
        process = self.process()
        with patch("ssh_guard.journal.subprocess.run", return_value=result) as run, patch("ssh_guard.journal.subprocess.Popen", return_value=process) as popen:
            follower = JournalFollower(["ssh.service"], cursor=cursor)
            follower.start()
            follower.stop()
        self.assertIn("--cursor=" + cursor, run.call_args.args[0])
        self.assertIn("--after-cursor=" + cursor, popen.call_args.args[0])
        self.assertIn("--no-tail", popen.call_args.args[0])
        self.assertNotIn("--since=now", popen.call_args.args[0])

    def test_vacuumed_cursor_does_not_silently_skip_logs(self):
        result = subprocess.CompletedProcess([], 0, json.dumps({"__CURSOR": "s=other;i=2"}) + "\n", "")
        with patch("ssh_guard.journal.subprocess.run", return_value=result), patch("ssh_guard.journal.subprocess.Popen") as popen:
            with self.assertRaisesRegex(RuntimeError, "no longer available"):
                JournalFollower(["ssh.service"], cursor="s=saved;i=1").start()
        popen.assert_not_called()

    def test_child_exit_and_stderr_are_observable(self):
        with patch("ssh_guard.journal.subprocess.Popen", return_value=self.process(stderr="Failed to seek cursor\n")):
            follower = JournalFollower(["ssh.service"])
            with self.assertLogs("ssh_guard.journal", level="WARNING"):
                follower.start()
                follower._threads[0].join(1)
            try:
                with self.assertRaisesRegex(RuntimeError, "Failed to seek cursor"):
                    follower.next_event(0.2)
            finally:
                follower.stop()

    def test_malformed_output_fails_instead_of_dropping_records(self):
        with patch("ssh_guard.journal.subprocess.Popen", return_value=self.process("not JSON\n")):
            follower = JournalFollower(["ssh.service"])
            follower.start()
            try:
                with self.assertRaisesRegex(RuntimeError, "journalctl stream ended"):
                    follower.next_event(0.2)
            finally:
                follower.stop()

    def test_bounded_queue_does_not_drop_a_large_replay(self):
        count = 1100
        lines = "\n".join(json.dumps({"__CURSOR": str(number)}) for number in range(count)) + "\n"
        with patch("ssh_guard.journal.subprocess.Popen", return_value=self.process(lines)):
            follower = JournalFollower(["ssh.service"])
            follower.start()
            try:
                self.assertEqual(follower.events.maxsize, 1024)
                received = [follower.next_event(1)["__CURSOR"] for _ in range(count)]
                self.assertEqual(received, [str(number) for number in range(count)])
            finally:
                follower.stop()

    def test_stop_terminates_and_reaps_child_without_removing_firewall(self):
        process = self.process(running=True)
        with patch("ssh_guard.journal.subprocess.Popen", return_value=process):
            follower = JournalFollower(["ssh.service"])
            follower.start()
            follower.stop()
        process.terminate.assert_called_once()
        process.wait.assert_called_once()
        self.assertIsNone(follower.next_event(0))
        self.assertTrue(all(not thread.is_alive() for thread in follower._threads))


if __name__ == "__main__":
    unittest.main()
