"""Cloud control for the Cobble feed - runs inside GitHub Actions.

The repo it runs in is the feed itself: manifest.json + the encrypted payload.
Every action edits the signed manifest and commits it, so the loader sees the
change on the next fetch.

    update        re-sign and republish the current build (also refreshes bans)
    kill_build    revoke every copy of a build
    kill_hwid     revoke one machine
    unban         lift a ban: build:N or hwid:X
    info          print the current state, change nothing
    poll_bans     read the ban inbox and apply every request (used by the cron)

The signing seed comes from the COBBLE_KEY secret and is written to keys/ for
the duration of the run; .gitignore keeps it out of the commit.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import sign  # noqa: E402

MANIFEST = os.path.join(ROOT, "manifest.json")
KILL = os.path.join(ROOT, "kill.json")
KEY_DIR = os.path.join(ROOT, "keys")
KEY_FILE = os.path.join(KEY_DIR, "cobble_feed.key")

# public inbox the loader writes to when it catches a replaced webhook link
INBOX = "https://ntfy.sh/cobble-9f24c7e1a83b5d60"


def mask(value: str) -> None:
    """Keep hwids out of the public run log."""
    if value:
        print(f"::add-mask::{value}")


def load() -> tuple[dict, dict]:
    # utf-8-sig: a file saved by powershell starts with a BOM, and json.load
    # refuses the whole document over it
    with open(MANIFEST, "r", encoding="utf-8-sig") as fh:
        man = json.load(fh)
    try:
        with open(KILL, "r", encoding="utf-8-sig") as fh:
            kill = json.load(fh)
    except (OSError, ValueError):
        kill = dict(man.get("kill") or {})
    kill.setdefault("builds", [])
    kill.setdefault("hwids", [])
    kill.setdefault("notes", {})
    return man, kill


def save(man: dict, kill: dict) -> None:
    man["kill"] = kill
    man["published_at"] = int(time.time())
    if not os.path.exists(KEY_FILE):
        seed = os.environ.get("COBBLE_KEY", "").strip()
        if not seed:
            raise SystemExit("COBBLE_KEY secret is not set")
        os.makedirs(KEY_DIR, exist_ok=True)
        with open(KEY_FILE, "w", encoding="ascii") as fh:
            fh.write(seed + "\n")
    sign.sign_feed(man)
    with open(MANIFEST, "w", encoding="utf-8") as fh:
        json.dump(man, fh, indent=2)
    with open(KILL, "w", encoding="utf-8") as fh:
        json.dump(kill, fh, indent=2)


def notify(man: dict, title: str, fields: list[dict], color: int = 0x5865F2) -> None:
    if os.environ.get("COBBLE_QUIET"):
        print(f"discord: suppressed ({title})")
        return
    address = str(os.environ.get("COBBLE_HOOK") or man.get("webhook") or "")
    if not address.startswith("https://"):
        print("discord: no hook configured")
        return
    payload = {
        "username": "cobble control",
        "embeds": [
            {
                "title": title,
                "color": color,
                "fields": fields,
                "footer": {"text": "cobble"},
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        ],
    }
    try:
        request = urllib.request.Request(
            address,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "cobble"},
            method="POST",
        )
        urllib.request.urlopen(request, timeout=8.0).read()
    except Exception as exc:  # noqa: BLE001 - the commit is what matters
        print(f"discord: {exc}")


def state(man: dict, kill: dict) -> str:
    return (
        f"build {man.get('build')} | {man.get('file')} | "
        f"bans: builds {len(kill['builds'])}, hwids {len(kill['hwids'])}"
    )


def add_ban(kill: dict, kind: str, value: str, note: str) -> bool:
    key = "builds" if kind == "build" else "hwids"
    item = int(value) if kind == "build" else str(value).lower()
    if item in [int(x) if kind == "build" else str(x).lower() for x in kill[key]]:
        return False
    kill[key].append(item)
    kill["notes"][str(item)] = note or "revoked"
    return True


def drop_ban(kill: dict, kind: str, value: str) -> bool:
    key = "builds" if kind == "build" else "hwids"
    before = len(kill[key])
    target = int(value) if kind == "build" else str(value).lower()
    kill[key] = [
        x for x in kill[key] if (int(x) if kind == "build" else str(x).lower()) != target
    ]
    kill["notes"].pop(str(value), None)
    kill["notes"].pop(str(value).lower(), None)
    return len(kill[key]) != before


def poll_inbox(since: int, seen: list[str]) -> tuple[list[dict], int, list[str]]:
    """Every ban request we have not handled yet.

    ntfy keeps messages for 12 h and `since` is inclusive, so the pointer is
    rewound ten minutes on every poll and message ids do the dedupe. That way
    neither a repeated poll nor a lift can resurrect an old request, and two
    requests inside the same second both land.
    """
    lower = max(0, int(since) - 600) if since else 0
    stamp = f"since={lower}" if lower else "since=all"
    try:
        request = urllib.request.Request(
            f"{INBOX}/json?poll=1&{stamp}",
            headers={"User-Agent": "cobble-control"},
        )
        with urllib.request.urlopen(request, timeout=15.0) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 - offline is not fatal
        print(f"inbox unreachable: {exc}")
        return [], int(since), list(seen)
    out = []
    highest = int(since)
    handled = list(seen)
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("event") != "message":
            continue
        highest = max(highest, int(event.get("time") or 0))
        ident = str(event.get("id") or "")
        if ident and ident in handled:
            continue
        if event.get("title") != "ban request":
            if ident:
                handled.append(ident)
            continue
        try:
            body = json.loads(event.get("message", "{}"))
        except ValueError:
            body = {}
        if ident:
            handled.append(ident)
        if body.get("hwid"):
            out.append(body)
    return out, highest, handled[-200:]


def main() -> None:
    ap = argparse.ArgumentParser(description="cobble feed control")
    ap.add_argument("--action", required=True,
                    choices=["update", "kill_build", "kill_hwid", "unban", "info", "poll_bans"])
    ap.add_argument("--target", default="")
    ap.add_argument("--note", default="")
    args = ap.parse_args()

    man, kill = load()

    if args.action == "info":
        print(state(man, kill))
        for build in kill["builds"]:
            print(f"  build  {build}")
        for hwid in kill["hwids"]:
            mask(str(hwid))
            print(f"  hwid   {hwid}")
        return

    changed = False

    if args.action == "update":
        changed = True
        note = args.note or man.get("notes") or f"build {man.get('build')}"
        man["notes"] = note
        notify(man, "cobble feed refreshed",
               [{"name": "build", "value": str(man.get("build")), "inline": True},
                {"name": "notes", "value": note[:900], "inline": False}])

    elif args.action == "kill_build":
        if not args.target.isdigit():
            raise SystemExit("kill_build needs a build number in target")
        changed = add_ban(kill, "build", args.target, args.note)
        if changed:
            notify(man, "build revoked",
                   [{"name": "build", "value": args.target, "inline": True},
                    {"name": "note", "value": args.note or "-", "inline": False}],
                   0xB03A48)

    elif args.action == "kill_hwid":
        if not args.target:
            raise SystemExit("kill_hwid needs an hwid in target")
        mask(args.target)
        changed = add_ban(kill, "hwid", args.target, args.note)
        if changed:
            notify(man, "machine revoked",
                   [{"name": "hwid", "value": args.target, "inline": False},
                    {"name": "note", "value": args.note or "-", "inline": False}],
                   0xB03A48)

    elif args.action == "unban":
        kind, _, value = args.target.partition(":")
        if kind not in ("build", "hwid") or not value:
            raise SystemExit("unban needs build:N or hwid:X in target")
        if kind == "hwid":
            mask(value)
        changed = drop_ban(kill, kind, value)
        if changed:
            notify(man, "ban lifted",
                   [{"name": kind, "value": value, "inline": False}], 0x2F6B4F)

    elif args.action == "poll_bans":
        messages, fresh, handled = poll_inbox(
            int(kill.get("inbox_since") or 0), list(kill.get("inbox_ids") or [])
        )
        for request in messages:
            hwid = str(request["hwid"]).strip()
            if not hwid:
                continue
            mask(hwid)
            note = str(request.get("reason", "webhook link replaced"))[:200]
            if add_ban(kill, "hwid", hwid, note):
                changed = True
                print(f"banned {hwid} ({note})")
                notify(man, "auto ban",
                       [{"name": "hwid", "value": hwid, "inline": False},
                        {"name": "reason", "value": note, "inline": False}],
                       0x8A6D3B)
        if handled != list(kill.get("inbox_ids") or []):
            kill["inbox_ids"] = handled
            changed = True
        if fresh > int(kill.get("inbox_since") or 0):
            kill["inbox_since"] = fresh
            changed = True
            print(f"inbox pointer {fresh}")

    if changed:
        save(man, kill)
        print("saved: " + state(man, kill))
    else:
        print("no change: " + state(man, kill))


if __name__ == "__main__":
    main()


