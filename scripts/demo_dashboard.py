"""Start the gateway with the dashboard on, fill it with a short scripted story, print the URL.

What it does:

  1. sets a demo signing key and a demo admin key in its own environment
     (TOOLGATE_DEMO_SIGNING_KEY, TOOLGATE_DEMO_ADMIN_KEY and the admin key's
     SHA-256 in TOOLGATE_DEMO_ADMIN_KEY_SHA256), unless they are already set
  2. builds the real service with `toolgate.server.build`, the repo's
     config/policy.example.yaml and `dashboard.enabled: true`, and serves it
     with uvicorn on 127.0.0.1 (a free port unless --port is given)
  3. drives scripted agent calls over HTTP: an orchestrator token, a child
     token for a sub-agent, allowed calls, denied calls, one approval that
     the admin approves through the API, and two approvals left pending
  4. prints the dashboard URL and the demo admin key, and serves until Ctrl-C

The tools are stand-ins: every one is `toolgate.server:echo`, which returns its
arguments. Nothing is read, sent or written anywhere. The audit log is a file
in a temporary directory that is removed on exit. The demo keys protect
nothing and must never be used for a real gateway.

Usage:  python scripts/demo_dashboard.py [--port N]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import uvicorn

from toolgate.server import build

ROOT = Path(__file__).resolve().parent.parent
POLICY_FILE = ROOT / "config" / "policy.example.yaml"
TOOLS = [
    "read_file",
    "write_file",
    "list_files",
    "delete_file",
    "send_email",
    "read_email",
    "list_events",
    "create_event",
]

USER_CAPS: list[dict[str, Any]] = [
    {"tool": "read_file", "args": {"path": {"any": True}}, "max_calls": 10},
    {"tool": "write_file", "args": {"path": {"any": True}, "content": {"any": True}}},
    {"tool": "delete_file", "args": {"path": {"any": True}}, "max_calls": 2},
    {"tool": "read_email", "args": {"id": {"any": True}}},
    {"tool": "send_email", "args": {"to": {"any": True}, "body": {"any": True}}, "max_calls": 5},
    {"tool": "list_events", "args": {"day": {"any": True}}},
    {
        "tool": "create_event",
        "args": {
            "title": {"any": True},
            "attendees": {"any": True},
            "duration_minutes": {"max": 600},
        },
    },
]
CHILD_CAPS: list[dict[str, Any]] = [
    {"tool": "read_file", "args": {"path": {"glob": "reports/*"}}, "max_calls": 5},
    {"tool": "send_email", "args": {"to": {"any": True}, "body": {"any": True}}, "max_calls": 3},
]

# (who, tool, args). "root" is the orchestrator's token, "child" the mailer sub-agent's.
STORY: list[tuple[str, str, dict[str, Any]]] = [
    ("root", "read_email", {"id": "m-17"}),
    ("child", "read_file", {"path": "reports/q3.txt"}),
    ("root", "list_events", {"day": "2026-11-18"}),
    ("root", "read_file", {"path": "secrets/api-key.pem"}),  # policy: deny-secret-paths
    ("child", "read_file", {"path": "payroll/2026.csv"}),  # grant: outside reports/*
    ("root", "delete_file", {"path": "reports/q2.txt"}),  # policy: deny-file-delete
    ("child", "send_email", {"to": "kim@example.com", "body": "Q3 numbers attached."}),
    ("root", "write_file", {"path": "drafts/q3-summary.md", "content": "Revenue up 4%."}),
    (
        "child",
        "send_email",
        {"to": "kim@partner.org", "body": "Q3 summary: revenue up 4%."},
    ),  # approval, approved at once by the admin
    (
        "child",
        "send_email",
        {"to": "audit@other.example", "body": "<script>alert('hi')</script> board notes"},
    ),  # approval, left pending
    (
        "root",
        "create_event",
        {
            "title": "Q3 review",
            "attendees": ["kim@partner.org", "sam@example.com"],
            "duration_minutes": 45,
        },
    ),  # approval, left pending
    ("child", "read_file", {"path": "reports/q3-appendix.txt"}),
]


@dataclass
class Demo:
    url: str
    admin_key: str
    server: uvicorn.Server
    thread: threading.Thread
    gateway: Any
    tmp: tempfile.TemporaryDirectory[str]
    pending: list[str]

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)
        self.gateway.flush()
        self.gateway.audit.close()
        self.tmp.cleanup()


def _set_demo_keys() -> None:
    os.environ.setdefault(
        "TOOLGATE_DEMO_SIGNING_KEY", base64.b64encode(secrets.token_bytes(32)).decode()
    )
    os.environ.setdefault("TOOLGATE_DEMO_ADMIN_KEY", secrets.token_urlsafe(32))
    key = os.environ["TOOLGATE_DEMO_ADMIN_KEY"]
    os.environ["TOOLGATE_DEMO_ADMIN_KEY_SHA256"] = hashlib.sha256(key.encode()).hexdigest()


def start(port: int = 0) -> Demo:
    """Serve the demo gateway in a background thread and run the story against it."""
    _set_demo_keys()
    tmp = tempfile.TemporaryDirectory(prefix="toolgate-dashboard-demo-")
    config = {
        "issuer": "https://gateway.example",
        "audience": "toolgate-demo",
        "signing_key_env": "TOOLGATE_DEMO_SIGNING_KEY",
        "admin_key_hash_env": "TOOLGATE_DEMO_ADMIN_KEY_SHA256",
        "policy_file": str(POLICY_FILE),
        "audit_log": "audit.jsonl",
        "tools": {name: "toolgate.server:echo" for name in TOOLS},
        "dashboard": {"enabled": True},
    }
    app, gateway, _ = build(config, os.environ, Path(tmp.name))
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="off")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("the demo server did not start")
        time.sleep(0.01)
    bound = server.servers[0].sockets[0].getsockname()[1]
    url = f"http://127.0.0.1:{bound}"
    demo = Demo(url, os.environ["TOOLGATE_DEMO_ADMIN_KEY"], server, thread, gateway, tmp, [])
    try:
        _run_story(demo)
    except BaseException:
        demo.stop()
        raise
    return demo


def _run_story(demo: Demo) -> None:
    admin = {"Authorization": f"Bearer {demo.admin_key}"}
    with httpx.Client(base_url=demo.url, timeout=10) as http:
        minted = http.post(
            "/token",
            headers=admin,
            json={
                "sub": "user:alice",
                "actor": "agent:orchestrator",
                "capabilities": USER_CAPS,
                "expires_in": 900,
            },
        )
        minted.raise_for_status()
        root = minted.json()["token"]
        child = http.post(
            "/token/exchange",
            headers={"Authorization": f"Bearer {root}"},
            json={"capabilities": CHILD_CAPS, "actor": "agent:mailer", "expires_in": 600},
        )
        child.raise_for_status()
        tokens = {"root": root, "child": child.json()["token"]}
        pending: list[str] = []
        approved = False
        for who, tool, args in STORY:
            response = http.post(
                "/call",
                headers={"Authorization": f"Bearer {tokens[who]}"},
                json={"tool": tool, "args": args},
            )
            body = response.json()
            if body.get("approval_id") and not approved:
                # The first parked call is approved at once, so the approval sits
                # in the middle of the log; the later ones stay pending.
                decided = http.post(
                    f"/approvals/{body['approval_id']}",
                    headers=admin,
                    json={"decision": "approve", "approver": "ana"},
                )
                decided.raise_for_status()
                approved = True
            elif body.get("approval_id"):
                pending.append(body["approval_id"])
            time.sleep(0.05)  # so the feed's clock column is not one instant
        demo.pending = pending
        left = http.get("/approvals", headers=admin).json()["pending"]
        if len(left) != 2:
            raise RuntimeError(f"expected 2 pending approvals, found {len(left)}")


def main() -> int:
    parser = argparse.ArgumentParser(prog="python scripts/demo_dashboard.py")
    parser.add_argument("--port", type=int, default=0)
    options = parser.parse_args()
    demo = start(options.port)
    print(f"dashboard: {demo.url}/dashboard")
    print(f"demo admin key (TOOLGATE_DEMO_ADMIN_KEY, protects nothing): {demo.admin_key}")
    print("Ctrl-C to stop; the demo audit log is deleted on exit.")
    try:
        while demo.thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        demo.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
