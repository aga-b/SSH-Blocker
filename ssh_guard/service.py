"""Journal ingestion and serialized firewall/state changes."""

import contextlib
import ipaddress
import logging
import os
import signal
import threading
import time

from .config import is_allowed, validate_runtime
from .firewall import NftFirewall
from .journal import JournalFollower, parse_failure
from .storage import Store

LOG = logging.getLogger(__name__)


def make_firewall(config):
    return NftFirewall(table=config["firewall_table"], scope=config["block_scope"], ssh_ports=config["ssh_ports"])


def process_entry(store, firewall, config, entry, now=None):
    """Commit cursor only when firewall + ban event are safely processed.

    A crash after nft succeeds but before SQLite commits replays the event;
    idempotent nft insertion makes this safe. No email happens on this path.
    """
    now = time.time() if now is None else now
    cursor = entry.get("__CURSOR")
    if not isinstance(cursor, str) or not cursor:
        raise RuntimeError("Journal record has no valid __CURSOR; refusing to skip it")
    ip = parse_failure(entry, config["journal_units"])
    with store.transaction():
        if store.get_meta("journal_cursor") == cursor:
            return False
        blocked = False
        if ip and not is_allowed(ip, config) and not store.is_active(ip):
            firewall.ban(ip)
            blocked = store.record_ban(ip, now)
        store.set_meta("journal_cursor", cursor)
    if blocked:
        LOG.warning("Blocked source IP %s after failed SSH password", ip)
    return blocked


def reconcile(store, firewall, config, force=False):
    with store.transaction():
        active = store.active_ips()
        removed = [ip for ip in active if is_allowed(ip, config)]
        desired = [ip for ip in active if not is_allowed(ip, config)]
        # Apply allowlist changes to existing bans as well as future failures.
        if force:
            firewall.reconcile(desired)
        else:
            firewall.ensure(desired)
        for ip in removed:
            store.record_unban(ip, time.time(), reason="allowlist")


def unban(store, firewall, config, ip, now=None):
    ip = str(ipaddress.ip_address(ip))
    with store.transaction():
        if not store.is_active(ip):
            return False
        # Repair a deleted table before removing a single element, preserving
        # other persisted bans. Serialize this with the running daemon.
        firewall.ensure(store.active_ips())
        firewall.unban(ip)
        return store.record_unban(ip, time.time() if now is None else now)


def reset_cursor(store, database, since):
    """Explicit recovery after journal vacuuming, only with the daemon stopped."""
    with daemon_lock(database):
        with store.transaction():
            store.db.execute("DELETE FROM meta WHERE key='journal_cursor'")
            store.set_meta("journal_since", since)


@contextlib.contextmanager
def daemon_lock(database):
    import fcntl  # Linux-only; keep parsing/tests importable elsewhere.
    with open(database + ".lock", "a", encoding="ascii") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Another SSH Guard daemon is already running for this database") from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def run(config):
    from .notifications import NotificationWorker

    if os.name != "posix" or os.geteuid() != 0:
        raise RuntimeError("run requires root on a systemd Linux host")
    validate_runtime(config)
    os.umask(0o077)
    store = Store(config["database"])
    stop = threading.Event()
    previous_handlers = {}
    for sig in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[sig] = signal.signal(sig, lambda *_: stop.set())
    follower = None
    worker = None
    try:
        with daemon_lock(config["database"]):
            firewall = make_firewall(config)
            reconcile(store, firewall, config, force=True)
            with store.transaction():
                # Persist the initial boundary before starting journalctl.
                # Crashes before the first cursor must not create a blind spot.
                if store.get_meta("journal_since") is None:
                    store.set_meta("journal_since", "@" + str(int(time.time())))
            follower = JournalFollower(config["journal_units"],
                                       cursor=store.get_meta("journal_cursor"),
                                       since=store.get_meta("journal_since"))
            follower.start()
            worker = NotificationWorker(config, config["database"])
            worker.start()
            next_reconcile = time.monotonic() + config["reconcile_seconds"]
            LOG.info("SSH Guard started: permanent bans; scope=%s", config["block_scope"])
            while not stop.is_set():
                entry = follower.next_event(timeout=1.0)
                if entry is not None:
                    process_entry(store, firewall, config, entry)
                if time.monotonic() >= next_reconcile:
                    reconcile(store, firewall, config)
                    next_reconcile = time.monotonic() + config["reconcile_seconds"]
    finally:
        if follower is not None:
            follower.stop()
        if worker is not None:
            worker.stop(timeout=5)
        store.close()
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
        LOG.info("SSH Guard stopped; existing firewall bans remain installed")
