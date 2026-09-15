"""Trusted OpenSSH log parsing and bounded, resumable journalctl streaming."""

from __future__ import annotations

from collections import deque
import ipaddress
import json
import logging
import os
import queue
import re
import subprocess
import threading


LOG = logging.getLogger(__name__)
MAX_LINE = 1024 * 1024
FAILURE = re.compile(
    r"Failed password for (?:invalid user )?.+ from (?P<ip>[^\s]+) "
    r"port (?P<port>[0-9]{1,5}) ssh2(?: \[preauth\])?"
)


def parse_failure(entry: dict, units: list[str]) -> str | None:
    """Extract only failed-password events emitted by a trusted sshd process.

    Greedy username matching deliberately selects the LAST 'from IP port N ssh2'
    suffix: an attacker controls the username and may put fake suffixes inside it.
    _COMM and _SYSTEMD_UNIT are journal trusted fields; SYSLOG_IDENTIFIER is not.
    """
    if not isinstance(entry, dict):
        return None
    if entry.get("_SYSTEMD_UNIT") not in units or entry.get("_COMM") not in ("sshd", "sshd-session", "sshd-auth"):
        return None
    message = entry.get("MESSAGE")
    if not isinstance(message, str):
        return None
    match = FAILURE.fullmatch(message)
    if match is None or not 1 <= int(match["port"]) <= 65535 or "%" in match["ip"]:
        return None
    try:
        address = ipaddress.ip_address(match["ip"])
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


class JournalFollower:
    def __init__(self, units, cursor=None, since="now", executable="/usr/bin/journalctl"):
        self.units = list(units)
        if not self.units or any(not isinstance(unit, str) or not re.fullmatch(r"[A-Za-z0-9_.@:\\-]+\.service", unit)
                                 for unit in self.units):
            raise ValueError("journal units must be systemd service names")
        if cursor is not None and (not isinstance(cursor, str) or not cursor or any(ord(c) < 32 for c in cursor)):
            raise ValueError("Invalid journal cursor")
        if not isinstance(since, str) or not since or any(ord(c) < 32 for c in since):
            raise ValueError("Invalid journal start time")
        if not isinstance(executable, str) or not os.path.isabs(executable):
            raise ValueError("journalctl executable must be an absolute path")
        self.cursor = cursor
        self.since = since
        self.executable = executable
        self.events = queue.Queue(maxsize=1024)
        self._stop = threading.Event()
        self._eof = threading.Event()
        self._errors = deque(maxlen=32)
        self._reader_error = None
        self._process = None
        self._threads = []

    def _verify_cursor(self):
        # sd_journal_seek_cursor can seek near a vacuumed cursor. Verify an exact
        # match so a removed journal segment never silently loses pending bans.
        if self.cursor is None:
            return
        command = [self.executable, "--no-pager", "--all", "--output=json",
                   f"--cursor={self.cursor}", "--lines=1"]
        try:
            result = subprocess.run(command, text=True, encoding="utf-8", errors="replace",
                                    capture_output=True, timeout=30, check=False,
                                    env={**os.environ, "LC_ALL": "C"})
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"Cannot verify saved journal cursor: {exc}") from exc
        if result.returncode:
            raise RuntimeError(f"Cannot read saved journal cursor: {result.stderr.strip()[:4000]}")
        try:
            records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        except (ValueError, TypeError) as exc:
            raise RuntimeError("Invalid journal response while verifying cursor") from exc
        if len(records) != 1 or not isinstance(records[0], dict) or records[0].get("__CURSOR") != self.cursor:
            raise RuntimeError("Saved journal cursor is no longer available; check journal retention before explicitly resetting it")

    def start(self):
        if self._process is not None or self._stop.is_set():
            raise RuntimeError("JournalFollower instances may only be started once")
        self._verify_cursor()
        command = [self.executable, "--follow", "--no-tail", "--output=json", "--no-pager", "--all"]
        if self.cursor:
            command.append(f"--after-cursor={self.cursor}")
        else:
            command.append(f"--since={self.since}")
        command.extend(f"_SYSTEMD_UNIT={unit}" for unit in self.units)
        try:
            self._process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
                env={**os.environ, "LC_ALL": "C"},
            )
        except OSError as exc:
            raise RuntimeError(f"Cannot start journalctl: {exc}") from exc
        self._threads = [threading.Thread(target=self._stderr, name="journal-stderr", daemon=True),
                         threading.Thread(target=self._stdout, name="journal-reader", daemon=True)]
        for thread in self._threads:
            thread.start()

    def _stderr(self):
        try:
            while not self._stop.is_set():
                line = self._process.stderr.readline(4097)
                if not line:
                    return
                message = line.rstrip()
                self._errors.append(message)
                LOG.warning("journalctl: %s", message)
        except (OSError, ValueError) as exc:
            if not self._stop.is_set():
                self._errors.append(str(exc))

    def _stdout(self):
        try:
            while not self._stop.is_set():
                line = self._process.stdout.readline(MAX_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_LINE:
                    raise RuntimeError("journalctl entry exceeds the supported 1 MiB limit")
                if not line.strip():
                    continue
                record = json.loads(line)
                if not isinstance(record, dict) or not isinstance(record.get("__CURSOR"), str):
                    raise RuntimeError("journalctl JSON entry has no usable cursor")
                while not self._stop.is_set():
                    try:
                        self.events.put(record, timeout=0.25)
                        break
                    except queue.Full:
                        continue
        except (OSError, ValueError, RuntimeError) as exc:
            if not self._stop.is_set():
                self._reader_error = exc
        finally:
            self._eof.set()

    def next_event(self, timeout=1.0):
        if self._process is None:
            raise RuntimeError("JournalFollower has not been started")
        if timeout < 0:
            raise ValueError("timeout cannot be negative")
        if self._stop.is_set():
            return None
        try:
            return self.events.get(timeout=timeout)
        except queue.Empty:
            pass
        if self._eof.is_set() or self._process.poll() is not None:
            # Give the independent stderr reader a chance to drain the exit reason.
            self._threads[0].join(timeout=0.1)
            detail = "; ".join(self._errors)
            if self._reader_error:
                detail = f"{self._reader_error}; {detail}"
            raise RuntimeError(f"journalctl stream ended (exit={self._process.poll()}): {detail[:4000]}")
        return None

    def stop(self):
        self._stop.set()
        if self._process is None:
            return
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=3)
        for thread in self._threads:
            thread.join(timeout=2)
        for stream in (self._process.stdout, self._process.stderr):
            if stream:
                stream.close()
