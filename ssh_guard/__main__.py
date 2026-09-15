"""Administrative CLI. No live mutations unless run/unban is requested."""

import argparse
import datetime as dt
import json
import logging
import os
import sys

from .config import load, validate_runtime
from .storage import Store


def utc(value):
    return dt.datetime.fromtimestamp(value, dt.timezone.utc).isoformat(timespec="seconds")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Persistent SSH password-failure IP blocking and email reports")
    parser.add_argument("--config", default="/etc/ssh-guard/config.conf")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("run", help="Run the daemon (Linux root)")
    p = commands.add_parser("validate", help="Check config syntax; changes nothing")
    p.add_argument("--runtime", action="store_true", help="Also check SMTP placeholders and password environment")
    p = commands.add_parser("list", help="List persistent bans")
    p.add_argument("--all", action="store_true", help="Include manually removed bans")
    p.add_argument("--json", action="store_true")
    p = commands.add_parser("rates", help="New distinct blocked IPs per UTC calendar minute")
    p.add_argument("--minutes", type=int, default=60)
    p.add_argument("--json", action="store_true")
    p = commands.add_parser("unban", help="Remove an IP ban from firewall and database")
    p.add_argument("ip")
    p = commands.add_parser("reset-cursor", help="Recover after journal retention loss; daemon must be stopped")
    p.add_argument("--since", required=True, help="Explicit timezone-aware ISO timestamp, or now; older events will be skipped")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    store = None
    try:
        config = load(args.config)
        if args.command == "validate":
            if args.runtime:
                validate_runtime(config)
            print("Configuration valid" + (" (runtime settings checked)" if args.runtime else " (syntax and values only; SMTP not contacted)"))
            return 0
        if args.command == "run":
            from .service import run
            run(config)
            return 0
        if args.command == "rates" and not 1 <= args.minutes <= 525600:
            raise ValueError("--minutes must be between 1 and 525600")
        # Read commands must never silently create an empty database at a typo.
        if not os.path.isfile(config["database"]):
            raise ValueError("State database does not exist; start the configured service first")
        if args.command in ("unban", "reset-cursor") and (os.name != "posix" or os.geteuid() != 0):
            raise ValueError(f"{args.command} requires root on Linux")
        os.umask(0o077)
        store = Store(config["database"])
        if args.command == "list":
            rows = store.list_bans(args.all)
            if args.json:
                print(json.dumps(rows, indent=2))
            else:
                print("IP\tACTIVE\tBANNED_AT_UTC\tUNBANNED_AT_UTC")
                for row in rows:
                    print(f"{row['ip']}\t{bool(row['active'])}\t{utc(row['banned_at'])}\t{utc(row['unbanned_at']) if row['unbanned_at'] is not None else '-'}")
        elif args.command == "rates":
            rows = store.rates(args.minutes)
            if args.json:
                print(json.dumps(rows, indent=2))
            else:
                print("MINUTE_UTC\tNEW_BLOCKED_IPS")
                for row in rows:
                    print(f"{utc(row['minute'])}\t{row['blocked_ips']}")
        elif args.command == "unban":
            from .service import make_firewall, unban
            changed = unban(store, make_firewall(config), config, args.ip)
            print("Ban removed" if changed else "IP was not actively banned")
        elif args.command == "reset-cursor":
            from .service import reset_cursor
            if args.since == "now":
                moment = dt.datetime.now(dt.timezone.utc)
            else:
                moment = dt.datetime.fromisoformat(args.since.replace("Z", "+00:00"))
                if moment.tzinfo is None:
                    raise ValueError("--since requires a timezone, e.g. 2026-09-13T10:00:00+03:00")
            reset_cursor(store, config["database"], "@" + str(int(moment.timestamp())))
            print(f"Journal position reset to {utc(moment.timestamp())}; earlier journal events will be skipped. Bans and history preserved.")
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        logging.error("%s", exc)
        return 1
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    sys.exit(main())
