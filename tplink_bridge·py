#!/usr/bin/env python3
"""
Bridge helper for TP-Link Archer C80 (and other routers tplinkrouterc6u supports).

Why this exists: the C80's web admin API uses a proprietary RSA/AES handshake
that changes between firmware versions. Rather than re-implementing that
handshake by hand in Node (high risk of producing something that *looks*
right but silently fails or breaks on a firmware update), this script uses
the maintained, open-source `tplinkrouterc6u` library, which already
implements and tests that handshake.

Install on the server with:
    pip install tplinkrouterc6u --break-system-packages   # or in a venv

Usage (invoked by server.js via child_process):
    python3 tplink_bridge.py '{"action":"clients","host":"...","port":8888,
                                "https":true,"username":"admin","password":"..."}'

Only the "clients" action is implemented. Block/unblock is intentionally
NOT implemented here -- see README note in server.js for why, and what
to send me once you've captured the real request.
"""
import sys
import json
import traceback

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "error": "No arguments given"}))
        sys.exit(1)

    try:
        args = json.loads(sys.argv[1])
    except Exception:
        print(json.dumps({"ok": False, "error": "Argument was not valid JSON"}))
        sys.exit(1)

    action = args.get("action")
    host = args.get("host")
    password = args.get("password")
    username = args.get("username") or "admin"
    port = args.get("port")
    use_https = bool(args.get("https"))

    if not host or not password:
        print(json.dumps({"ok": False, "error": "host and password are required"}))
        sys.exit(1)

    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}" + (f":{port}" if port else "")

    try:
        from tplinkrouterc6u import TplinkC80Router
    except ImportError:
        print(json.dumps({
            "ok": False,
            "error": "tplinkrouterc6u is not installed on the server. Run: pip install tplinkrouterc6u"
        }))
        sys.exit(1)

    router = TplinkC80Router(url, password, username)

    try:
        router.authorize()

        if action == "clients":
            status = router.get_status()
            devices = []
            for d in (status.devices or []):
                devices.append({
                    "name": d.hostname or "Unknown device",
                    "ip": d.ipaddr or "",
                    "mac": d.macaddr or "",
                    "type": str(d.type) if d.type is not None else "",
                    "active": bool(d.active),
                })
            print(json.dumps({"ok": True, "devices": devices}))

        elif action in ("block", "unblock"):
            # Deliberately not implemented: tplinkrouterc6u does not document an
            # Access Control blacklist method for the C80 model, so there is no
            # verified call to make here. See README for how to capture the
            # real request and send it over so this can be filled in correctly.
            print(json.dumps({
                "ok": False,
                "error": "block/unblock for Archer C80 is not implemented yet "
                         "(no verified API call available) -- see README"
            }))
            sys.exit(2)

        else:
            print(json.dumps({"ok": False, "error": f"Unknown action '{action}'"}))
            sys.exit(1)

    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e), "trace": traceback.format_exc()}))
        sys.exit(1)
    finally:
        try:
            router.logout()
        except Exception:
            pass

if __name__ == "__main__":
    main()
