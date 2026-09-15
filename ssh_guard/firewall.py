"""A private nftables table for durable IPv4 and IPv6 bans.

All writes are nft transactions over stdin, without a shell. Only a table carrying
our ownership marker may be replaced or removed. The database remains authoritative.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
from typing import Iterable


OWNER = "managed by ssh-guard; do not edit"
PRIORITY = -10


def _address(value: str) -> str:
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Expected an IPv4 or IPv6 address without a scope ID")
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


class NftFirewall:
    def __init__(self, table="ssh_guard", scope="all", ssh_ports=None,
                 executable="/usr/sbin/nft"):
        if not isinstance(table, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", table):
            raise ValueError("Invalid nftables table name")
        if scope not in {"all", "ssh"}:
            raise ValueError("Firewall scope must be all or ssh")
        ports = [22] if ssh_ports is None else list(ssh_ports)
        if not ports or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
            raise ValueError("ssh_ports must contain TCP port numbers between 1 and 65535")
        if not isinstance(executable, str) or not os.path.isabs(executable):
            raise ValueError("nft executable must be an absolute path")
        self.table = table
        self.scope = scope
        self.ssh_ports = sorted(set(ports))
        self.executable = executable

    def _run(self, arguments, script=None):
        try:
            result = subprocess.run(
                [self.executable, *arguments], input=script, text=True,
                encoding="utf-8", errors="replace", capture_output=True,
                timeout=30, check=False,
                env={**os.environ, "LC_ALL": "C"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"nftables command failed: {exc}") from exc
        if result.returncode:
            raise RuntimeError(f"nftables exited {result.returncode}: {result.stderr.strip()[:4000]}")
        return result.stdout

    def _json(self, arguments):
        try:
            value = json.loads(self._run(["--json", "--numeric", *arguments]))
            records = value["nftables"]
            if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
                raise ValueError("nftables is not a list of objects")
            return records
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(f"Invalid nftables JSON response: {exc}") from exc

    def _read_table(self):
        tables = self._json(["list", "tables", "inet"])
        if not any(row.get("table", {}).get("name") == self.table
                   and row.get("table", {}).get("family") == "inet" for row in tables):
            return None
        # If another manager removes it between these reads, fail and retry through
        # the service restart policy instead of assuming that access was successful.
        records = self._json(["list", "table", "inet", self.table])
        table = [r["table"] for r in records if "table" in r]
        if len(table) != 1 or table[0].get("family") != "inet" or table[0].get("name") != self.table:
            raise RuntimeError("Unexpected table in nftables JSON response")
        if table[0].get("comment") != OWNER:
            raise RuntimeError(f"Refusing to modify unowned nftables table inet {self.table}")
        return records

    def _replace(self, ips: Iterable[str], existing: bool):
        addresses = sorted({_address(ip) for ip in ips},
                           key=lambda value: (ipaddress.ip_address(value).version,
                                              int(ipaddress.ip_address(value))))
        # Quote even validated identifiers so names that are nft keywords are safe.
        name = json.dumps(self.table)
        lines = [f"delete table inet {name}"] if existing else []
        lines.extend([
            f"add table inet {name} {{ comment {json.dumps(OWNER)}; }}",
            f"add set inet {name} blocked_v4 {{ type ipv4_addr; }}",
            f"add set inet {name} blocked_v6 {{ type ipv6_addr; }}",
            f"add chain inet {name} input {{ type filter hook input priority {PRIORITY}; policy accept; }}",
        ])
        port_match = ""
        if self.scope == "ssh":
            port_match = " tcp dport { " + ", ".join(map(str, self.ssh_ports)) + " }"
        for version, protocol in ((4, "ip"), (6, "ip6")):
            lines.append(f"add rule inet {name} input {protocol} saddr @blocked_v{version}{port_match} drop")
            elements = [ip for ip in addresses if ipaddress.ip_address(ip).version == version]
            if elements:
                lines.append(f"add element inet {name} blocked_v{version} {{ " + ", ".join(elements) + " }")
        self._run(["--file", "-"], "\n".join(lines) + "\n")

    def reconcile(self, ips: Iterable[str]):
        """Atomically replace our complete table from persistent state at startup."""
        addresses = [_address(ip) for ip in ips]
        records = self._read_table()
        self._replace(addresses, existing=records is not None)

    @staticmethod
    def _elements(record):
        result = set()
        for item in record.get("elem", []):
            # Plain address elements are emitted as strings. A timeout, prefix,
            # interval, verdict map or other unexpected object is configuration drift.
            if not isinstance(item, str):
                return None
            try:
                result.add(_address(item))
            except ValueError:
                return None
        return result

    def _rule_matches(self, record, version):
        if record.get("chain") != "input":
            return False
        expressions = record.get("expr")
        if not isinstance(expressions, list):
            return False
        expected = [{"match": {
            "op": "==", "left": {"payload": {"protocol": "ip" if version == 4 else "ip6", "field": "saddr"}},
            "right": f"@blocked_v{version}",
        }}]
        if self.scope == "ssh":
            if len(expressions) != 3 or not isinstance(expressions[1], dict):
                return False
            port = expressions[1].get("match", {})
            if port.get("op") != "==" or port.get("left") != {"payload": {"protocol": "tcp", "field": "dport"}}:
                return False
            right = port.get("right")
            # nft folds a one-element anonymous port set into its scalar value.
            ports = right.get("set") if isinstance(right, dict) else [right]
            if not isinstance(ports, list) or any(type(p) is not int for p in ports) or sorted(ports) != self.ssh_ports:
                return False
            expected.append(expressions[1])
        expected.append({"drop": None})
        return expressions == expected

    def _matches(self, records, ips):
        tables, chains, sets, rules = [], [], [], []
        for row in records:
            if "metainfo" in row:
                continue
            if len(row) != 1:
                return False
            kind, record = next(iter(row.items()))
            if not isinstance(record, dict) or record.get("family") != "inet":
                return False
            if kind != "table" and record.get("table") != self.table:
                return False
            if kind == "table":
                tables.append(record)
            elif kind == "chain":
                chains.append(record)
            elif kind == "set":
                sets.append(record)
            elif kind == "rule":
                rules.append(record)
            else:
                return False
        if len(tables) != 1 or tables[0].get("flags"):
            return False
        if len(chains) != 1 or len(sets) != 2 or len(rules) != 2:
            return False
        chain = chains[0]
        if any(chain.get(key) != value for key, value in {
            "name": "input", "type": "filter", "hook": "input", "prio": PRIORITY, "policy": "accept",
        }.items()):
            return False
        for version in (4, 6):
            matching = [s for s in sets if s.get("name") == f"blocked_v{version}"]
            if len(matching) != 1:
                return False
            record = matching[0]
            if record.get("type") != f"ipv{version}_addr" or record.get("flags") or record.get("timeout"):
                return False
            required = {ip for ip in ips if ipaddress.ip_address(ip).version == version}
            if self._elements(record) != required:
                return False
        return self._rule_matches(rules[0], 4) and self._rule_matches(rules[1], 6)

    def ensure(self, ips: Iterable[str]) -> bool:
        """Repair missing elements, chain/rule changes or a missing owned table."""
        addresses = {_address(ip) for ip in ips}
        records = self._read_table()
        if records is not None and self._matches(records, addresses):
            return False
        self._replace(addresses, existing=records is not None)
        return True

    def ban(self, ip: str):
        """Idempotently add an address. nft 'add element' tolerates existing keys."""
        address = _address(ip)
        version = ipaddress.ip_address(address).version
        self._run(["--file", "-"],
                  f"add element inet {json.dumps(self.table)} blocked_v{version} {{ {address} }}\n")

    def unban(self, ip: str):
        """Delete an address when present; report errors instead of hiding them."""
        address = _address(ip)
        version = ipaddress.ip_address(address).version
        records = self._read_table()
        if records is None:
            return
        matching = [r["set"] for r in records if r.get("set", {}).get("name") == f"blocked_v{version}"]
        if len(matching) != 1:
            raise RuntimeError("Missing ban set; reconcile the firewall before unbanning")
        elements = self._elements(matching[0])
        if elements is None:
            raise RuntimeError("Unexpected ban set elements; reconcile the firewall before unbanning")
        if address in elements:
            self._run(["--file", "-"],
                      f"delete element inet {json.dumps(self.table)} blocked_v{version} {{ {address} }}\n")

    def remove_table(self):
        """Explicit maintenance operation; ordinary service stop preserves bans."""
        if self._read_table() is not None:
            self._run(["--file", "-"], f"delete table inet {json.dumps(self.table)}\n")
