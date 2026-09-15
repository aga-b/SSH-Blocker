"""Strict, dependency-free JSON configuration loading."""

import ipaddress
import json
import os
import re
from pathlib import Path


class ConfigError(ValueError):
    pass


def _keys(value, expected, label):
    if not isinstance(value, dict):
        raise ConfigError(f"{label}: object required")
    unknown = set(value) - set(expected)
    missing = set(expected) - set(value)
    if unknown or missing:
        raise ConfigError(f"{label}: unknown={sorted(unknown)}, missing={sorted(missing)}")


def _integer(value, label, minimum=1, maximum=None):
    if type(value) is not int or value < minimum or (maximum and value > maximum):
        raise ConfigError(f"{label}: integer between {minimum} and {maximum or 'unlimited'} required")


def _string(value, label, empty=False):
    if not isinstance(value, str) or (not empty and not value) or any(c in value for c in "\r\n\x00"):
        raise ConfigError(f"{label}: nonempty single-line string required")


def validate(config):
    _keys(config, ["database", "journal_units", "allowlist", "block_scope", "ssh_ports",
                   "firewall_table", "reconcile_seconds", "notifications", "smtp"], "config")
    _string(config["database"], "database")
    if not os.path.isabs(config["database"]):
        raise ConfigError("database: absolute path required")
    units = config["journal_units"]
    if not isinstance(units, list) or not units:
        raise ConfigError("journal_units: nonempty array required")
    if any(not isinstance(u, str) or not re.fullmatch(r"[A-Za-z0-9_@.:-]+\.service", u) for u in units):
        raise ConfigError("journal_units: explicit systemd service names required")
    allowlist = config["allowlist"]
    if not isinstance(allowlist, list):
        raise ConfigError("allowlist: array required")
    try:
        for item in allowlist:
            if not isinstance(item, str):
                raise ValueError("IP or CIDR string required")
            ipaddress.ip_network(item, strict=False)
    except ValueError as exc:
        raise ConfigError(f"allowlist: {exc}") from exc
    if config["block_scope"] not in ("all", "ssh"):
        raise ConfigError("block_scope: all or ssh required")
    if not isinstance(config["ssh_ports"], list) or not config["ssh_ports"]:
        raise ConfigError("ssh_ports: nonempty array required")
    for port in config["ssh_ports"]:
        _integer(port, "ssh_ports", 1, 65535)
    if not isinstance(config["firewall_table"], str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,31}", config["firewall_table"]):
        raise ConfigError("firewall_table: simple nftables identifier required")
    _integer(config["reconcile_seconds"], "reconcile_seconds")
    n = config["notifications"]
    _keys(n, ["digest_interval_seconds", "thresholds", "threshold_cooldown_seconds",
              "poll_seconds", "retry_seconds", "send_empty_digest"], "notifications")
    for key in ("digest_interval_seconds", "poll_seconds", "retry_seconds"):
        _integer(n[key], key)
    _integer(n["threshold_cooldown_seconds"], "threshold_cooldown_seconds", 0)
    if not isinstance(n["thresholds"], list):
        raise ConfigError("thresholds: array required (empty disables threshold alerts)")
    for threshold in n["thresholds"]:
        _integer(threshold, "thresholds")
    if sorted(set(n["thresholds"])) != n["thresholds"]:
        raise ConfigError("thresholds: unique, ascending positive integers required")
    if type(n["send_empty_digest"]) is not bool:
        raise ConfigError("send_empty_digest: boolean required")
    s = config["smtp"]
    _keys(s, ["enabled", "host", "port", "mode", "from_addr", "recipients", "username",
              "password_env", "timeout_seconds", "subject_prefix"], "smtp")
    if type(s["enabled"]) is not bool:
        raise ConfigError("smtp.enabled: boolean required")
    for key in ("host", "from_addr", "password_env", "subject_prefix"):
        _string(s[key], f"smtp.{key}")
    _string(s["username"], "smtp.username", empty=True)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s["password_env"]):
        raise ConfigError("password_env: environment variable name required")
    if s["mode"] not in ("starttls", "ssl"):
        raise ConfigError("smtp.mode: starttls or ssl required")
    _integer(s["port"], "smtp.port", 1, 65535)
    _integer(s["timeout_seconds"], "smtp.timeout_seconds", 1, 120)
    if not isinstance(s["recipients"], list) or not s["recipients"]:
        raise ConfigError("smtp.recipients: nonempty array required")
    for addr in [s["from_addr"]] + s["recipients"]:
        _string(addr, "email address")
        if not re.fullmatch(r"[^\s<>@,;]+@[^\s<>@,;]+\.[^\s<>@,;]+", addr):
            raise ConfigError("email addresses must be bare addresses, e.g. admin@example.org")
    if len(s["recipients"]) != len(set(s["recipients"])):
        raise ConfigError("smtp.recipients: duplicate recipient")
    return config


def load(path):
    try:
        with Path(path).open(encoding="utf-8") as handle:
            return validate(json.load(handle))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Cannot read configuration {path}: {exc}") from exc


def validate_runtime(config):
    """Check deploy-time values without sending email or changing the firewall."""
    s = config["smtp"]
    if s["enabled"]:
        if s["host"].endswith("example.com") or any(a.endswith("@example.com") for a in s["recipients"]):
            raise ConfigError("Configure real SMTP settings and recipients before starting, or set smtp.enabled=false")
        if s["username"] and not os.environ.get(s["password_env"]):
            raise ConfigError(f"SMTP password environment variable {s['password_env']} is missing")


def is_allowed(ip, config):
    address = ipaddress.ip_address(ip)
    return any(address in ipaddress.ip_network(network, strict=False) for network in config["allowlist"])
