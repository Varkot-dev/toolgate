"""End to end over real HTTP: a uvicorn server on a free port and a scripted client.

The first test is the milestone's "done when": one script drives allow, deny
and approve through the public endpoints. The rest attack the HTTP boundary:
credential confusion, malformed bodies, header and path tricks, and races.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import shutil
import socket
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parent))

import caveat.server as server_module  # noqa: E402
from caveat.audit import verify  # noqa: E402
from caveat.server import (  # noqa: E402
    ConfigError,
    build,
    create_app,
    hash_admin_key,
    is_loopback,
    load_config,
    safe_text,
    strict_json,
)
from test_gateway import Blocker, Env  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

USER_CAPS = [
    {"tool": "read_file", "args": {"path": {"glob": "reports/*"}}, "max_calls": 10},
    {"tool": "send_email", "args": {"to": {"any": True}, "body": {"any": True}}, "max_calls": 3},
    {"tool": "delete_file", "args": {"path": {"any": True}}, "max_calls": 1},
    {"tool": "boom", "args": {}},
]
CHILD_CAPS = [
    {"tool": "read_file", "args": {"path": {"glob": "reports/q3/*"}}, "max_calls": 5},
    {"tool": "send_email", "args": {"to": {"any": True}, "body": {"any": True}}, "max_calls": 2},
    {"tool": "delete_file", "args": {"path": {"any": True}}, "max_calls": 1},
]


class Live:
    """A gateway behind a real uvicorn server, plus the client-side secrets."""

    def __init__(self, tmp_path: Path, env: Env | None = None, **app_options: Any) -> None:
        self.env = env if env is not None else Env(tmp_path)
        self.admin_key = secrets.token_urlsafe(32)
        app = create_app(self.env.gateway, hash_admin_key(self.admin_key), **app_options)
        config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error", lifespan="off")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started:
            assert time.monotonic() < deadline, "server did not start"
            time.sleep(0.005)
        self.port = self.server.servers[0].sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.http = httpx.Client(base_url=self.url, timeout=10)
        self.admin = {"Authorization": f"Bearer {self.admin_key}"}

    def close(self) -> None:
        self.http.close()
        self.server.should_exit = True
        self.thread.join(timeout=10)
        self.env.audit.close()

    @staticmethod
    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def mint(self, caps: list[dict[str, Any]] | None = None, expires_in: float = 600) -> Any:
        response = self.http.post(
            "/token",
            headers=self.admin,
            json={
                "sub": "user:alice",
                "actor": "agent:orchestrator",
                "capabilities": caps or USER_CAPS,
                "expires_in": expires_in,
            },
        )
        assert response.status_code == 200, response.text
        return response.json()

    def call(self, token: str, tool: str, args: dict[str, Any] | None = None) -> httpx.Response:
        return self.http.post(
            "/call", headers=self.bearer(token), json={"tool": tool, "args": args or {}}
        )

    def raw(self, request: bytes) -> bytes:
        """Send bytes exactly as written and return the whole response."""
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.sendall(request)
            chunks = []
            while chunk := sock.recv(65536):
                chunks.append(chunk)
        return b"".join(chunks)


@pytest.fixture
def live(tmp_path: Path) -> Iterator[Live]:
    server = Live(tmp_path)
    try:
        yield server
    finally:
        server.close()


# ----------------------------------------------------------------- the "done when"


def test_scripted_client_drives_allow_deny_and_approve(live: Live) -> None:
    http, env = live.http, live.env
    assert http.get("/healthz").json() == {"status": "ok"}

    # The admin mints a token for the user's orchestrator.
    parent = live.mint()
    assert set(parent) == {"token", "jti", "expires_at"}

    # The orchestrator exchanges it for a narrower child; widening is refused.
    wider = http.post(
        "/token/exchange",
        headers=live.bearer(parent["token"]),
        json={
            "capabilities": [{"tool": "read_file", "args": {"path": {"glob": "*"}}}],
            "actor": "agent:sub",
            "expires_in": 300,
        },
    )
    assert wider.status_code == 403
    assert wider.json()["error"] == "escalation" and "read_file" in wider.json()["reason"]
    exchanged = http.post(
        "/token/exchange",
        headers=live.bearer(parent["token"]),
        json={"capabilities": CHILD_CAPS, "actor": "agent:sub", "expires_in": 300},
    )
    assert exchanged.status_code == 200, exchanged.text
    child = exchanged.json()
    assert child["jti"] != parent["jti"] and child["expires_at"] <= parent["expires_at"]

    # 1. Allowed.
    allowed = live.call(child["token"], "read_file", {"path": "reports/q3/sales.csv"})
    assert allowed.status_code == 200
    assert allowed.json()["status"] == "allowed" and allowed.json()["result"] == "done"
    assert allowed.json()["rule"] == "allow-plain"
    assert env.spies["read_file"].calls == [{"path": "reports/q3/sales.csv"}]

    # 2. Denied by the child's grant (the parent could have read it).
    by_grant = live.call(child["token"], "read_file", {"path": "reports/q2/sales.csv"})
    assert by_grant.status_code == 403
    assert by_grant.json()["status"] == "denied" and by_grant.json()["stage"] == "grant"
    assert "rule" not in by_grant.json()

    # 3. Denied by operator policy, although the grant allows it.
    by_policy = live.call(child["token"], "delete_file", {"path": "reports/q3/sales.csv"})
    assert by_policy.status_code == 403
    assert by_policy.json()["rule"] == "deny-delete"
    assert by_policy.json()["reason"] == "Agents never delete files."
    assert env.spies["delete_file"].calls == []

    # 4. Parked for a person.
    mail = {"to": "partner@other.test", "body": "Q3 numbers attached"}
    pending = live.call(child["token"], "send_email", mail)
    assert pending.status_code == 202
    assert pending.json()["status"] == "pending"
    assert pending.json()["rule"] == "approve-external-email"
    approval_id = pending.json()["approval_id"]
    assert env.spies["send_email"].calls == []
    poll = http.get(f"/approvals/{approval_id}", headers=live.bearer(child["token"]))
    assert poll.status_code == 200
    assert poll.json()["state"] == "pending" and "outcome" not in poll.json()

    # The admin sees exactly what would be released, then approves it.
    listing = http.get("/approvals", headers=live.admin)
    assert listing.status_code == 200
    (row,) = listing.json()["pending"]
    assert row["id"] == approval_id
    assert (row["tool"], row["args"]) == ("send_email", mail)
    assert row["actors"] == ["agent:sub", "agent:orchestrator"]
    assert (row["sub"], row["jti"]) == ("user:alice", child["jti"])
    assert "token" not in row and child["token"] not in listing.text
    approved = http.post(
        f"/approvals/{approval_id}",
        headers=live.admin,
        json={"decision": "approve", "approver": "alice@example.com"},
    )
    assert approved.status_code == 200
    assert (approved.json()["state"], approved.json()["status"]) == ("approved", "allowed")
    assert env.spies["send_email"].calls == [mail]
    assert http.get("/approvals", headers=live.admin).json() == {"pending": []}

    # The agent polls and gets the result.
    poll = http.get(f"/approvals/{approval_id}", headers=live.bearer(child["token"]))
    assert poll.json()["state"] == "approved"
    assert poll.json()["outcome"]["status"] == "allowed"
    assert poll.json()["outcome"]["result"] == "done"

    # The admin revokes the PARENT; the child's next call is 401.
    revoked = http.post("/token/revoke", headers=live.admin, json={"jti": parent["jti"]})
    assert revoked.status_code == 200 and revoked.json() == {"revoked": parent["jti"]}
    after = live.call(child["token"], "read_file", {"path": "reports/q3/sales.csv"})
    assert after.status_code == 401
    assert after.json()["reason"] == "revoked"
    assert 'error="invalid_token"' in after.headers["www-authenticate"]
    assert len(env.spies["read_file"].calls) == 1  # still only the one allowed read

    # The audit log verifies, and holds one entry per decision made above.
    report = http.get("/audit/verify", headers=live.admin).json()
    assert report["ok"] is True and report["problem"] is None
    decisions = [e["decision"] for e in env.entries() if not e["tool"].startswith("token:")]
    assert decisions == ["allow", "deny", "deny", "approve", "approved", "deny"]
    # Minting, the refused and the accepted exchange and the revocation are entries too.
    lifecycle = [
        (e["tool"], e["decision"], e["rule"])
        for e in env.entries()
        if e["tool"].startswith("token:")
    ]
    assert lifecycle == [
        ("token:mint", "allow", "token: minted by admin"),
        ("token:exchange", "deny", "exchange: escalation"),
        ("token:exchange", "allow", f"token: exchanged from {parent['jti']}"),
        ("token:revoke", "allow", "token: revoked by admin"),
    ]
    assert report["entries"] == len(decisions) + len(lifecycle) == 10
    head = http.get("/audit/head", headers=live.admin).json()
    assert head == report["head"] and head["seq"] == 9
    assert verify(env.audit_path, head["hash"]).ok
    assert env.entries()[7]["approver"] == "alice@example.com"
    # No argument value and no credential ever reached the log.
    raw = env.audit_path.read_text()
    for secret in ("partner@other.test", "Q3 numbers", child["token"], live.admin_key):
        assert secret not in raw


def test_reject_expiry_and_conflicts_over_http(live: Live) -> None:
    http = live.http
    token = live.mint()["token"]
    mail = {"to": "x@other.test", "body": "b"}
    first = live.call(token, "send_email", mail).json()["approval_id"]
    body = {"decision": "reject", "approver": "alice"}
    rejected = http.post(f"/approvals/{first}", headers=live.admin, json=body)
    assert rejected.status_code == 200
    assert (rejected.json()["state"], rejected.json()["status"]) == ("rejected", "denied")
    again = http.post(
        f"/approvals/{first}", headers=live.admin, json={"decision": "approve", "approver": "al"}
    )
    assert again.status_code == 409 and again.json()["error"] == "not_pending"
    poll = http.get(f"/approvals/{first}", headers=live.bearer(token)).json()
    assert (poll["state"], poll["outcome"]["status"]) == ("rejected", "denied")

    second = live.call(token, "send_email", mail).json()["approval_id"]
    assert second != first
    live.env.clock.now += 300
    late = http.post(
        f"/approvals/{second}", headers=live.admin, json={"decision": "approve", "approver": "al"}
    )
    assert late.status_code == 410 and late.json()["error"] == "expired"
    unknown = http.post(
        "/approvals/nope", headers=live.admin, json={"decision": "approve", "approver": "al"}
    )
    assert unknown.status_code == 404
    assert live.env.spies["send_email"].calls == []
    assert http.get("/audit/verify", headers=live.admin).json()["ok"] is True


def test_approval_denied_at_release_time_over_http(live: Live) -> None:
    http = live.http
    minted = live.mint()
    approval_id = live.call(
        minted["token"], "send_email", {"to": "x@other.test", "body": "b"}
    ).json()["approval_id"]
    http.post("/token/revoke", headers=live.admin, json={"jti": minted["jti"]})
    released = http.post(
        f"/approvals/{approval_id}",
        headers=live.admin,
        json={"decision": "approve", "approver": "alice"},
    )
    assert released.status_code == 200
    assert (released.json()["state"], released.json()["status"]) == ("denied", "denied")
    assert released.json()["reason"] == "revoked"
    assert live.env.spies["send_email"].calls == []


def test_tool_error_is_502_and_internal_approval_fields_stay_private(live: Live) -> None:
    token = live.mint()["token"]
    failed = live.call(token, "boom")
    assert failed.status_code == 502
    assert failed.json()["status"] == "error" and "result" not in failed.json()


def test_audit_verify_runs_the_real_check(live: Live) -> None:
    token = live.mint()["token"]
    for name in ("a", "b", "c"):
        assert live.call(token, "read_file", {"path": f"reports/{name}"}).status_code == 200
    assert live.http.get("/audit/verify", headers=live.admin).json()["ok"] is True
    lines = live.env.audit_path.read_text().splitlines(keepends=True)
    lines[1] = lines[1].replace('"decision":"allow"', '"decision":"deny"')
    live.env.audit_path.write_text("".join(lines))
    report = live.http.get("/audit/verify", headers=live.admin).json()
    assert report["ok"] is False
    assert (report["entries"], report["first_bad_index"]) == (1, 1)
    # Truncating the tail keeps the chain consistent; the in-memory head still catches it.
    live.env.audit_path.write_text(lines[0])
    report = live.http.get("/audit/verify", headers=live.admin).json()
    assert report["ok"] is False and "removed" in report["problem"]


# ------------------------------------------------------------ credential confusion

ADMIN_ROUTES = [
    ("POST", "/token", {"sub": "u", "actor": "a", "capabilities": [], "expires_in": 60}),
    ("POST", "/token/revoke", {"jti": "x"}),
    ("GET", "/approvals", None),
    ("POST", "/approvals/abc", {"decision": "approve", "approver": "mallory"}),
    ("GET", "/audit/verify", None),
    ("GET", "/audit/head", None),
]
AGENT_ROUTES = [
    ("POST", "/call", {"tool": "read_file", "args": {"path": "reports/x"}}),
    ("POST", "/token/exchange", {"capabilities": [], "actor": "a", "expires_in": 60}),
    ("GET", "/approvals/abc", None),
]


def send(live: Live, method: str, path: str, body: Any, headers: Any) -> httpx.Response:
    if method == "GET":
        return live.http.get(path, headers=headers)
    return live.http.post(path, headers=headers, json=body)


def test_agent_token_is_not_an_admin_credential(live: Live) -> None:
    minted = live.mint()
    pending = live.call(minted["token"], "send_email", {"to": "x@other.test", "body": "b"}).json()
    routes = [
        *ADMIN_ROUTES,
        (
            "POST",
            f"/approvals/{pending['approval_id']}",
            {"decision": "approve", "approver": "self"},
        ),
    ]
    entries_before = len(live.env.entries())
    for method, path, body in routes:
        response = send(live, method, path, body, live.bearer(minted["token"]))
        assert response.status_code == 401, (method, path)
        assert response.headers["www-authenticate"].startswith("Bearer")
        assert minted["token"] not in response.text
    # The agent could not approve its own request, mint, revoke or read the log.
    assert live.env.spies["send_email"].calls == []
    assert len(live.env.gateway.list_pending()) == 1
    assert len(live.env.entries()) == entries_before
    assert live.call(minted["token"], "read_file", {"path": "reports/x"}).status_code == 200


def test_admin_key_is_not_an_agent_credential(live: Live) -> None:
    for method, path, body in AGENT_ROUTES:
        response = send(live, method, path, body, live.admin)
        assert response.status_code == 401, (method, path)
        assert live.admin_key not in response.text
    assert live.env.total_tool_calls() == 0
    # Not even a fingerprint of the admin key was written to the audit log.
    assert live.env.entries() == []


def test_missing_wrong_and_tricky_authorization_headers(live: Live) -> None:
    token = live.mint()["token"]
    key = live.admin_key
    bad_admin: list[Any] = [
        {},
        {"Authorization": ""},
        {"Authorization": key},
        {"Authorization": f"Basic {key}"},
        {"Authorization": f"Bearer  {key}"},
        {"Authorization": f"Bearer\t{key}"},
        {"Authorization": f"Bearer {key} extra"},
        {"Authorization": f"Bearer {key},Bearer {key}"},
        {"Authorization": f"Bearer {key[:-1]}"},
        {"Authorization": f"Bearer {key}x"},
        {"Authorization": f"Bearer {key.swapcase()}"},
        [("Authorization", f"Bearer {key}"), ("Authorization", f"Bearer {key}")],
        [("Authorization", f"Bearer {key}"), ("Authorization", "Bearer wrong")],
        [("Authorization", "Bearer wrong"), ("authorization", f"Bearer {key}")],
        {"X-Authorization": f"Bearer {key}", "Proxy-Authorization": f"Bearer {key}"},
    ]
    for headers in bad_admin:
        response = live.http.get("/approvals", headers=headers)
        assert response.status_code == 401, headers
        assert key not in response.text
    # A header too large for the HTTP parser never reaches the app at all.
    huge = live.http.get("/approvals", headers={"Authorization": "Bearer " + "A" * 70_000})
    assert huge.status_code in (400, 431)
    bad_agent: list[Any] = [
        {},
        {"Authorization": token},
        {"Authorization": f"Token {token}"},
        {"Authorization": f"Bearer  {token}"},
        [("Authorization", f"Bearer {token}"), ("Authorization", f"Bearer {token}")],
        [("Authorization", "Bearer junk"), ("Authorization", f"Bearer {token}")],
    ]
    for headers in bad_agent:
        response = live.http.post(
            "/call", headers=headers, json={"tool": "read_file", "args": {"path": "reports/x"}}
        )
        assert response.status_code == 401, headers
        assert "www-authenticate" in response.headers
    assert live.env.total_tool_calls() == 0
    # No credential presented properly, so nothing was decided: only the mint is on record.
    assert [e["tool"] for e in live.env.entries()] == ["token:mint"]

    # The scheme name is case-insensitive (RFC 9110); the credential is not.
    assert (
        live.http.get("/approvals", headers={"authorization": f"bearer {key}"}).status_code == 200
    )
    assert (
        live.http.get("/approvals", headers={"Authorization": f"BEARER {key}"}).status_code == 200
    )


def test_token_problems_on_call_are_401_with_a_challenge(live: Live) -> None:
    minted = live.mint(expires_in=30)
    head, payload, signature = minted["token"].split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["caps"] = [{"tool": "delete_file", "args": {"path": {"any": True}}}]
    widened = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    unsigned = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    cases = {
        "abc.def.ghi": "malformed",
        f"{head}.{widened}.{signature}": "bad_signature",
        f"{unsigned}.{payload}.": "bad_algorithm",
    }
    for token, code in cases.items():
        response = live.call(token, "delete_file", {"path": "x"})
        assert response.status_code == 401
        assert response.json()["reason"] == code
        assert f'error_description="{code}"' in response.headers["www-authenticate"]
        assert token not in response.text
    live.env.clock.now += 31
    response = live.call(minted["token"], "read_file", {"path": "reports/x"})
    assert (response.status_code, response.json()["reason"]) == (401, "expired")
    exchange = live.http.post(
        "/token/exchange",
        headers=live.bearer(minted["token"]),
        json={"capabilities": [], "actor": "a", "expires_in": 5},
    )
    assert exchange.status_code == 401
    assert live.env.total_tool_calls() == 0
    minted_entry, *refused = live.env.entries()
    assert (minted_entry["tool"], minted_entry["jti"]) == ("token:mint", minted["jti"])
    assert len(refused) == 5 and all(e["jti"].startswith("unverified:") for e in refused)
    assert (refused[-1]["tool"], refused[-1]["rule"]) == ("token:exchange", "exchange: expired")


def test_another_token_cannot_read_or_probe_an_approval(live: Live) -> None:
    owner, other = live.mint()["token"], live.mint()["token"]
    approval_id = live.call(owner, "send_email", {"to": "x@other.test", "body": "b"}).json()[
        "approval_id"
    ]
    assert live.http.get(f"/approvals/{approval_id}", headers=live.bearer(owner)).status_code == 200
    stranger = live.http.get(f"/approvals/{approval_id}", headers=live.bearer(other))
    missing = live.http.get("/approvals/" + "A" * len(approval_id), headers=live.bearer(other))
    assert stranger.status_code == missing.status_code == 404
    assert stranger.json() == missing.json() == {"error": "not_found"}
    assert live.http.get(f"/approvals/{approval_id}").status_code == 401
    # An agent cannot resolve, edit or delete an approval through any method.
    for method in ("PUT", "PATCH", "DELETE"):
        response = live.http.request(
            method,
            f"/approvals/{approval_id}",
            headers={**live.bearer(owner), "Content-Type": "application/json"},
            content=b'{"decision":"approve","approver":"me"}',
        )
        assert response.status_code == 405
    assert live.env.spies["send_email"].calls == []


def test_path_tricks_in_approval_ids(live: Live) -> None:
    token = live.mint()["token"]
    for path in (
        "/approvals/..%2Faudit%2Fhead",
        "/approvals/%2e%2e/audit/head",
        "/approvals/../audit/head",
        "/approvals//",
        "/approvals/a%00b",
        "/approvals/" + "a" * 500,
        "/approvals/%F0%9F%92%A5",
        "/audit/head/",
        "//audit/head",
    ):
        raw = live.raw(
            f"GET {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        status = int(raw.split(b" ", 2)[1])
        assert status in (401, 404, 307), (path, raw[:200])
        assert b'"seq"' not in raw and b'"hash"' not in raw


def test_exchange_limits_are_403_or_422_not_a_credential_error(live: Live) -> None:
    def exchange(token: str, caps: list[dict[str, Any]], actor: str = "agent:sub") -> Any:
        return live.http.post(
            "/token/exchange",
            headers=live.bearer(token),
            json={"capabilities": caps, "actor": actor, "expires_in": 60},
        )

    cap = [{"tool": "read_file", "args": {"path": {"glob": "reports/*"}}, "max_calls": 1}]
    root = live.mint()["token"]
    token = root
    for _ in range(live.env.authority.max_depth):
        response = exchange(token, cap)
        assert response.status_code == 200
        token = response.json()["token"]
    too_deep = exchange(token, cap)
    assert (too_deep.status_code, too_deep.json()["error"]) == (403, "depth_exceeded")
    assert "www-authenticate" not in too_deep.headers

    parent = live.mint()["token"]
    for n in range(live.env.authority.max_children):
        assert exchange(parent, cap, f"agent:{n}").status_code == 200
    too_many = exchange(parent, cap)
    assert (too_many.status_code, too_many.json()["error"]) == (403, "too_many_children")
    # The parent itself still works: the limit is on delegation, not on the token.
    assert live.call(parent, "read_file", {"path": "reports/x"}).status_code == 200

    wide = [
        {
            "tool": "read_file",
            "args": {"path": {"in": [f"reports/{'x' * 200}{i}" for i in range(250)]}},
        }
    ]
    oversized = exchange(live.mint()["token"], wide)
    assert oversized.status_code == 422, oversized.text
    assert "www-authenticate" not in oversized.headers


# ---------------------------------------------------------------- malformed bodies


def post_raw(live: Live, token: str, body: bytes, content_type: str | None = "application/json"):
    headers = live.bearer(token)
    if content_type is not None:
        headers["Content-Type"] = content_type
    return live.http.post("/call", headers=headers, content=body)


def test_malformed_bodies_are_refused_and_nothing_runs(live: Live) -> None:
    token = live.mint()["token"]
    nested = b'{"tool":"read_file","args":{"path":' + b"[" * 200 + b"]" * 200 + b"}}"
    cases: list[tuple[bytes, int]] = [
        (b"", 400),
        (b"{", 400),
        (b"not json", 400),
        (b'{"tool":"read_file","args":{"path":"reports/x"}} trailing', 400),
        (b"\xff\xfe", 400),
        # Parameter pollution: two parsers must never disagree about which key wins.
        (b'{"tool":"delete_file","tool":"read_file","args":{"path":"reports/x"}}', 400),
        (b'{"tool":"read_file","args":{"path":"secrets/x","path":"reports/x"}}', 400),
        (b'{"tool":"delete_file","\\u0074ool":"read_file","args":{"path":"reports/x"}}', 400),
        (b'{"tool":"read_file","args":{"path":' + b"9" * 5000 + b"}}", 400),
        (b'{"tool":"read_file","args":{"path":NaN}}', 400),
        (b'{"tool":"read_file","args":{"path":1e999}}', 400),
        (nested, 400),
        (b"[" * 30_000, 400),
        (b'["read_file"]', 422),
        (b'"read_file"', 422),
        (b"null", 422),
        (b'{"args":{"path":"reports/x"}}', 422),
        (b'{"tool":"read_file","args":{"path":"reports/x"},"token":"x"}', 422),
        (b'{"tool":"read_file","args":["reports/x"]}', 422),
        (b'{"tool":["read_file"],"args":{}}', 422),
        (b'{"tool":7,"args":{}}', 422),
        (b'{"tool":"","args":{}}', 422),
        (b'{"tool":"' + b"t" * 200 + b'","args":{}}', 422),
    ]
    for body, expected in cases:
        response = post_raw(live, token, body)
        assert response.status_code == expected, (body[:60], response.text)
        assert token not in response.text
    assert live.env.total_tool_calls() == 0
    assert [e["tool"] for e in live.env.entries()] == ["token:mint"]
    # The same bytes that were refused above are fine once well formed.
    assert (
        post_raw(live, token, b'{"tool":"read_file","args":{"path":"reports/x"}}').status_code
        == 200
    )


def test_validation_errors_do_not_echo_the_submitted_values(live: Live) -> None:
    response = live.http.post(
        "/approvals/abc",
        headers=live.admin,
        json={"decision": "SECRET-VALUE-1", "approver": "SECRET\nVALUE-2", "x": "SECRET-VALUE-3"},
    )
    assert response.status_code == 422
    assert "SECRET" not in response.text
    assert "decision" in response.json()["reason"]


def test_content_type_size_and_query_limits(live: Live) -> None:
    token = live.mint()["token"]
    good = b'{"tool":"read_file","args":{"path":"reports/x"}}'
    for content_type in (None, "text/plain", "application/x-www-form-urlencoded", "text/json"):
        assert post_raw(live, token, good, content_type).status_code == 415
    assert post_raw(live, token, good, "application/json; charset=utf-8").status_code == 200
    assert post_raw(live, token, good, "application/json; charset=utf-16").status_code == 415
    form = live.http.post("/call", headers=live.bearer(token), data={"tool": "read_file"})
    assert form.status_code == 415

    big = b'{"tool":"read_file","args":{"path":"reports/' + b"x" * 70_000 + b'"}}'
    assert post_raw(live, token, big).status_code == 413

    def chunks() -> Iterator[bytes]:  # no Content-Length: the limit must still hold
        yield b'{"tool":"read_file","args":{"path":"reports/'
        for _ in range(80):
            yield b"x" * 1000
        yield b'"}}'

    chunked = live.http.post(
        "/call",
        headers={**live.bearer(token), "Content-Type": "application/json"},
        content=chunks(),
    )
    assert chunked.status_code == 413

    gzipped = live.http.post(
        "/call",
        headers={
            **live.bearer(token),
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
        },
        content=good,
    )
    assert gzipped.status_code == 415

    for path in ("/call?tool=delete_file", "/call?args[path]=x", "/healthz?x=1"):
        response = (
            live.http.post(path, headers=live.bearer(token), content=good)
            if path.startswith("/call")
            else live.http.get(path)
        )
        assert response.status_code in (400, 415)
    assert len(live.env.spies["read_file"].calls) == 1  # only the one well-formed request ran
    assert live.env.spies["delete_file"].calls == []


def test_conflicting_content_lengths_are_refused(live: Live) -> None:
    token = live.mint()["token"]
    body = b'{"tool":"read_file","args":{"path":"reports/x"}}'
    smuggle = (
        f"POST /call HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
        "Content-Length: 5\r\nConnection: close\r\n\r\n"
    ).encode() + body
    raw = live.raw(smuggle)
    assert int(raw.split(b" ", 2)[1]) == 400
    assert live.env.total_tool_calls() == 0


def test_mint_and_exchange_reject_bad_requests(live: Live) -> None:
    http = live.http
    base = {"sub": "user:alice", "actor": "agent:a", "capabilities": USER_CAPS, "expires_in": 60}
    for change in (
        {"expires_in": 0},
        {"expires_in": -5},
        {"expires_in": "60"},
        {"expires_in": True},
        {"expires_in": 10**400},
        {"expires_in": 1e308},
        {"sub": ""},
        {"sub": "a\nb"},
        {"actor": " padded "},
        {"actor": "a" * 300},
        {"capabilities": "all"},
        {"capabilities": [{"tool": "read_file", "args": {"path": {"regex": ".*"}}}]},
        {"capabilities": [{"tool": "read_file", "admin": True}]},
        {"capabilities": [{"tool": "read_file", "max_calls": 0}]},
        {"aud": "elsewhere"},
        {"jti": "chosen-by-caller"},
    ):
        response = http.post("/token", headers=live.admin, json={**base, **change})
        assert response.status_code == 422, change
    live.env.clock.now += 0.5  # a float clock, as time.time() is
    token = live.mint()["token"]
    for body in (
        {"capabilities": USER_CAPS, "actor": "a", "expires_in": 60, "sub": "user:mallory"},
        {"capabilities": USER_CAPS, "actor": "", "expires_in": 60},
        {
            "capabilities": [{"tool": "x", "args": {"a": {"nope": 1}}}],
            "actor": "a",
            "expires_in": 9,
        },
    ):
        response = http.post("/token/exchange", headers=live.bearer(token), json=body)
        assert response.status_code == 422, body
    # A long expires_in is capped by the authority, never honoured as written.
    long = http.post("/token", headers=live.admin, json={**base, "expires_in": 10**7}).json()
    assert long["expires_at"] <= live.env.clock.now + 900


def test_no_cors_no_docs_and_unknown_routes(live: Live) -> None:
    preflight = live.http.options(
        "/call",
        headers={"Origin": "https://evil.test", "Access-Control-Request-Method": "POST"},
    )
    assert preflight.status_code == 405
    response = live.http.get("/healthz", headers={"Origin": "https://evil.test"})
    assert not any(name.lower().startswith("access-control") for name in response.headers)
    for path in ("/docs", "/redoc", "/openapi.json", "/", "/admin", "/token", "/call"):
        assert live.http.get(path).status_code in (404, 405)


# ---------------------------------------------------------------------------- races


def test_two_admins_racing_to_approve_execute_the_call_once(live: Live) -> None:
    for _round in range(5):
        token = live.mint()["token"]
        approval_id = live.call(token, "send_email", {"to": "x@other.test", "body": "b"}).json()[
            "approval_id"
        ]
        before = len(live.env.spies["send_email"].calls)
        barrier = threading.Barrier(8)
        statuses: list[int] = []

        def approve(i: int, approval_id: str = approval_id, barrier: Any = barrier) -> None:
            with httpx.Client(base_url=live.url, timeout=10) as client:
                barrier.wait()
                response = client.post(
                    f"/approvals/{approval_id}",
                    headers=live.admin,
                    json={"decision": "approve", "approver": f"admin-{i}"},
                )
                statuses.append(response.status_code)  # noqa: B023

        threads = [threading.Thread(target=approve, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(statuses) == [200] + [409] * 7
        assert len(live.env.spies["send_email"].calls) - before == 1
    assert live.http.get("/audit/verify", headers=live.admin).json()["ok"] is True


def test_concurrent_calls_and_verify_do_not_disagree(live: Live) -> None:
    token = live.mint()["token"]
    reports: list[dict[str, Any]] = []

    def caller(i: int) -> None:
        with httpx.Client(base_url=live.url, timeout=10) as client:
            for n in range(5):
                client.post(
                    "/call",
                    headers=live.bearer(token),
                    json={"tool": "read_file", "args": {"path": f"reports/{i}-{n}"}},
                )

    def checker() -> None:
        with httpx.Client(base_url=live.url, timeout=10) as client:
            for _ in range(10):
                reports.append(client.get("/audit/verify", headers=live.admin).json())

    threads = [threading.Thread(target=caller, args=(i,)) for i in range(4)]
    threads.append(threading.Thread(target=checker))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r["ok"] for r in reports), [r for r in reports if not r["ok"]]
    assert len(live.env.spies["read_file"].calls) == 10  # the budget, not the 20 attempts
    final = live.http.get("/audit/verify", headers=live.admin).json()
    assert final["ok"] and final["entries"] == 21  # 20 calls and the mint


# ----------------------------------------------------------------- app and config


def test_create_app_validates_its_inputs(tmp_path: Path) -> None:
    env = Env(tmp_path)
    for bad in ("", "admin", "A" * 64, "g" * 64, None, hash_admin_key("k") + "0"):
        with pytest.raises(ValueError):
            create_app(env.gateway, bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        create_app(env.gateway, hash_admin_key("k"), max_body_bytes=0)


def test_strict_json() -> None:
    assert strict_json(b'{"a":[1,2.5,"x",null,true]}') == {"a": [1, 2.5, "x", None, True]}
    for bad in (b'{"a":1,"a":2}', b"Infinity", b"-Infinity", b"1e400", b"[" * 100, b"\xc3"):
        with pytest.raises(Exception) as info:
            strict_json(bad)
        assert getattr(info.value, "status", None) == 400


def example_config(tmp_path: Path) -> Path:
    for name in ("gateway.example.yaml", "policy.example.yaml"):
        shutil.copy(ROOT / "config" / name, tmp_path / name)
    return tmp_path / "gateway.example.yaml"


def test_example_config_builds_a_working_app(tmp_path: Path) -> None:
    config = load_config(example_config(tmp_path))
    # Secrets are named by the file and come from the environment, never from the file.
    raw = (ROOT / "config" / "gateway.example.yaml").read_text()
    admin_key = secrets.token_urlsafe(32)
    environ = {
        config["signing_key_env"]: base64.b64encode(secrets.token_bytes(32)).decode(),
        config["admin_key_hash_env"]: hash_admin_key(admin_key),
    }
    assert all(value not in raw for value in environ.values())
    app, gateway, settings = build(config, environ, tmp_path)
    try:
        assert settings["host"] == "127.0.0.1"
        assert "echo" in gateway.tool_names
        assert gateway.approvals.ttl == config["approvals"]["ttl_seconds"]

        async def run() -> tuple[int, int]:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://gw") as client:
                health = await client.get("/healthz")
                listing = await client.get(
                    "/approvals", headers={"Authorization": f"Bearer {admin_key}"}
                )
                return health.status_code, listing.status_code

        import asyncio

        assert asyncio.run(run()) == (200, 200)
    finally:
        gateway.audit.close()
        if hasattr(gateway.authority.store, "close"):
            gateway.authority.store.close()


def test_config_errors_fail_closed(tmp_path: Path) -> None:
    path = example_config(tmp_path)
    config = load_config(path)
    good = {
        # Not all zero: that key is itself refused now (see the startup tests below).
        config["signing_key_env"]: base64.b64encode(bytes(range(32))).decode(),
        config["admin_key_hash_env"]: hash_admin_key("k"),
    }
    bad_environments = [
        {},
        {**good, config["signing_key_env"]: ""},
        {**good, config["signing_key_env"]: "not base64!"},
        {**good, config["signing_key_env"]: base64.b64encode(b"short").decode()},
        {**good, config["admin_key_hash_env"]: "plaintext-admin-key"},
    ]
    for environ in bad_environments:
        with pytest.raises(ConfigError):
            build(config, environ, tmp_path)
    bad_configs = [
        {**config, "signing_key_env": "literal secret, not a variable name"},
        {**config, "policy_file": "missing.yaml"},
        {**config, "tools": {"echo": "caveat.server:nope"}},
        {**config, "tools": {"bad name": "caveat.server:echo"}},
        {**config, "store": {"kind": "redis"}},
        {**config, "approvals": {"ttl_seconds": 0}},
        {**config, "approvals": {"surprise": 1}},
    ]
    for broken in bad_configs:
        with pytest.raises(ConfigError):
            build(broken, good, tmp_path / "unused")
    (tmp_path / "extra.yaml").write_text("issuer: x\nadmin_key: hunter2\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path / "extra.yaml")
    with pytest.raises(ConfigError):
        load_config(tmp_path / "does-not-exist.yaml")


# ====================================================================================
# Findings from the security reviews. Each test below failed before its fix.
# ====================================================================================

GHOST = [{"tool": "ghost", "args": {}}, {"tool": "read_file", "args": {"path": {"any": True}}}]


def serve(tmp_path: Path, tools: dict[str, Any] | None = None, **gateway_options: Any) -> Live:
    """A live server whose gateway has other tools or limits than Env's default."""
    env = Env(tmp_path)
    env.rebuild(tools, **gateway_options)
    return Live(tmp_path, env=env)


# ------------------------------------------------------------- 8. availability


def test_revoke_stays_prompt_while_every_shared_worker_runs_a_blocked_tool(tmp_path: Path) -> None:
    blocker = Blocker()
    live = serve(tmp_path, {"ghost": blocker})  # no cap and no timeout: the worst case
    workers = 40  # FastAPI's shared pool for plain `def` endpoints
    results: list[int] = []
    try:
        token = live.mint(GHOST)
        victim = live.mint(GHOST)

        def caller() -> None:
            with httpx.Client(base_url=live.url, timeout=60) as client:
                response = client.post(
                    "/call", headers=live.bearer(token["token"]), json={"tool": "ghost", "args": {}}
                )
                results.append(response.status_code)

        threads = [threading.Thread(target=caller) for _ in range(workers + 5)]
        for thread in threads:
            thread.start()
        blocker.wait_started(workers)  # every shared worker is now inside the tool
        assert blocker.calls == workers and results == []
        try:
            started = time.monotonic()
            revoked = live.http.post(
                "/token/revoke", headers=live.admin, json={"jti": victim["jti"]}, timeout=5
            )
            listing = live.http.get("/approvals", headers=live.admin, timeout=5)
            head = live.http.get("/audit/head", headers=live.admin, timeout=5)
            checked = live.http.get("/audit/verify", headers=live.admin, timeout=5)
            elapsed = time.monotonic() - started
            statuses = [r.status_code for r in (revoked, listing, head, checked)]
            assert statuses == [200, 200, 200, 200]
            assert elapsed < 3, f"admin endpoints took {elapsed:.1f}s behind blocked tools"
            assert results == [] and blocker.calls == workers  # the tools are all still blocked
        finally:
            blocker.release.set()
            for thread in threads:
                thread.join(30)
        assert sorted(results) == [200] * (workers + 5)
        # The revocation made while the pool was full took effect.
        assert live.call(victim["token"], "read_file", {"path": "x"}).status_code == 401
    finally:
        blocker.release.set()
        live.close()


def test_calls_over_the_in_flight_cap_get_429_with_retry_after(tmp_path: Path) -> None:
    blocker = Blocker()
    live = serve(tmp_path, {"ghost": blocker}, max_in_flight_per_root=2)
    statuses: list[int] = []
    try:
        token = live.mint(GHOST)["token"]

        def caller() -> None:
            with httpx.Client(base_url=live.url, timeout=60) as client:
                statuses.append(
                    client.post(
                        "/call", headers=live.bearer(token), json={"tool": "ghost", "args": {}}
                    ).status_code
                )

        threads = [threading.Thread(target=caller) for _ in range(2)]
        for thread in threads:
            thread.start()
        blocker.wait_started(2)
        try:
            for _ in range(20):  # a burst from the same token costs the pool nothing
                over = live.call(token, "ghost")
                assert over.status_code == 429 and over.headers["retry-after"] == "1"
                assert (over.json()["status"], over.json()["code"]) == ("denied", "in_flight_limit")
            assert blocker.calls == 2
            assert live.env.entries()[-1]["rule"] == "limit: in_flight"
        finally:
            blocker.release.set()
            for thread in threads:
                thread.join(30)
        assert statuses == [200, 200]
        assert live.call(token, "ghost").status_code == 200
    finally:
        blocker.release.set()
        live.close()


def test_a_tool_that_overruns_its_timeout_is_504(tmp_path: Path) -> None:
    blocker = Blocker()
    live = serve(tmp_path, {"ghost": blocker}, tool_timeout=0.05)
    try:
        token = live.mint([{"tool": "ghost", "args": {}, "max_calls": 3}])
        response = live.call(token["token"], "ghost")
        assert response.status_code == 504
        body = response.json()
        assert (body["status"], body["code"]) == ("error", "tool_timeout") and "result" not in body
        assert blocker.calls == 1
        assert live.env.store.usage(token["jti"], 0) == (1, 3)  # charged, not refunded
    finally:
        blocker.release.set()
        live.close()


# ------------------------------------------------------------- 11. lone surrogates

BAD = "\ud800zz"
_CAP = {"tool": "read_file", "args": {"path": {"glob": "reports/*"}}}
SURROGATE_CASES: list[tuple[str, str, Any]] = [
    ("admin", "/token", {"sub": BAD, "actor": "a", "capabilities": [_CAP], "expires_in": 60}),
    ("admin", "/token", {"sub": "u", "actor": BAD, "capabilities": [_CAP], "expires_in": 60}),
    (
        "admin",
        "/token",
        {"sub": "u", "actor": "a", "capabilities": [{"tool": BAD, "args": {}}], "expires_in": 60},
    ),
    (
        "admin",
        "/token",
        {
            "sub": "u",
            "actor": "a",
            "capabilities": [{"tool": "t", "args": {BAD: {"any": True}}}],
            "expires_in": 60,
        },
    ),
    (
        "admin",
        "/token",
        {
            "sub": "u",
            "actor": "a",
            "capabilities": [{"tool": "t", "args": {"p": {"eq": BAD}}}],
            "expires_in": 60,
        },
    ),
    ("admin", "/token", {"sub": "u", "actor": "a", "capabilities": [], "expires_in": 60, BAD: 1}),
    ("admin", "/token/revoke", {"jti": BAD}),
    ("admin", "/token/revoke", {BAD: "x"}),
    ("admin", "/approvals/abc", {"decision": BAD, "approver": "alice"}),
    ("admin", "/approvals/abc", {"decision": "approve", "approver": BAD}),
    ("agent", "/token/exchange", {"capabilities": [_CAP], "actor": BAD, "expires_in": 60}),
    (
        "agent",
        "/token/exchange",
        {"capabilities": [{"tool": BAD, "args": {}}], "actor": "a", "expires_in": 60},
    ),
    (
        "agent",
        "/token/exchange",
        {
            "capabilities": [{"tool": "read_file", "args": {BAD: {"any": True}}}],
            "actor": "a",
            "expires_in": 60,
        },
    ),
    (
        "agent",
        "/token/exchange",
        {
            "capabilities": [{"tool": "read_file", "args": {"path": {"glob": BAD}}}],
            "actor": "a",
            "expires_in": 60,
        },
    ),
    (
        "agent",
        "/token/exchange",
        {"capabilities": [{"tool": "read_file", BAD: 1}], "actor": "a", "expires_in": 60},
    ),
    ("agent", "/call", {"tool": BAD, "args": {}}),
    ("agent", "/call", {"tool": "read_file", "args": {BAD: 1}}),
    ("agent", "/call", {"tool": "read_file", "args": {"path": BAD}}),
    ("agent", "/call", {"tool": "read_file", "args": {"path": ["reports/x", {"k": BAD}]}}),
    ("agent", "/call", {"tool": "read_file", "args": {}, BAD: 1}),
]


@pytest.mark.parametrize(
    ("who", "path", "body"),
    SURROGATE_CASES,
    ids=[f"{path}-{i}" for i, (_, path, _) in enumerate(SURROGATE_CASES)],
)
def test_a_lone_surrogate_in_any_string_field_is_422_never_a_5xx(
    live: Live, who: str, path: str, body: Any
) -> None:
    token = live.mint()["token"]
    before = live.env.entries()
    raw = json.dumps(body).encode("ascii")  # the surrogate travels as the escape \\ud800
    assert b"\\ud800" in raw
    headers = live.admin if who == "admin" else live.bearer(token)
    response = live.http.post(
        path, headers={**headers, "Content-Type": "application/json"}, content=raw
    )
    assert response.status_code < 500, response.text
    assert response.status_code == 422 and response.json()["error"] == "invalid_request"
    response.content.decode("utf-8")  # and the answer itself is well-formed text
    assert live.env.total_tool_calls() == 0
    assert live.env.entries() == before  # refused at the door: no decision, no entry
    assert live.http.get("/healthz").status_code == 200


def test_error_bodies_can_always_be_encoded() -> None:
    assert safe_text("plain") == "plain"
    assert safe_text("a\ud800b") == "a\\ud800b"
    error = server_module.ApiError(403, "escalation", "tool '\udfff' is not covered")
    body = error.response().body
    assert json.loads(body)["reason"] == "tool '\\udfff' is not covered"
    # Whatever reaches the encoder, it does not raise.
    rendered = server_module._Json({"reason": "x\ud800"}).body
    assert rendered.decode("utf-8")


# ----------------------------------------------- 12. nothing for unverified callers


def test_unverified_callers_learn_nothing_about_the_audit_log(live: Live) -> None:
    good = live.mint()["token"]
    for token, body in [
        ("abc.def.ghi", {"tool": "read_file", "args": {"path": "reports/x"}}),
        ("junk", {"tool": "read_file", "args": {"path": "reports/x"}}),
        ("junk", {"tool": "bad tool name", "args": {"x": 1}}),
    ]:
        response = live.http.post("/call", headers=live.bearer(token), json=body)
        assert response.status_code == 401
        assert set(response.json()) == {"status", "reason"}  # no audit_seq, no stage
    assert len(live.env.entries()) == 4  # the entries exist; the caller is just not told
    # A caller whose token verifies still gets both, as before.
    denied = live.call(good, "read_file", {"path": "secrets/x"}).json()
    assert denied["stage"] == "grant" and denied["audit_seq"] == 4
    assert denied["code"] == "constraint_failed"


# ---------------------------------------------- 13. tool exception text over HTTP


def test_tool_exception_text_is_not_returned_by_a_configured_service(tmp_path: Path) -> None:
    def leaky() -> None:
        raise ConnectionError("postgres://svc:hunter2@10.0.0.7/prod at /srv/app/db.py")

    live = serve(tmp_path, {"ghost": leaky}, tool_error_detail=False)
    try:
        response = live.call(live.mint(GHOST)["token"], "ghost")
        assert response.status_code == 502
        assert response.json()["reason"] == "tool raised ConnectionError; details are withheld"
        assert "hunter2" not in response.text and "/srv/app" not in response.text
    finally:
        live.close()


# ------------------------------------------------------ 10, 14. startup and files


def good_environ(config: dict[str, Any], admin_key: str = "k" * 40) -> dict[str, str]:
    return {
        config["signing_key_env"]: base64.b64encode(bytes(range(32))).decode(),
        config["admin_key_hash_env"]: hash_admin_key(admin_key),
    }


def close(gateway: Any) -> None:
    gateway.audit.close()
    if hasattr(gateway.authority.store, "close"):
        gateway.authority.store.close()


def test_build_applies_the_service_limits_by_default(tmp_path: Path) -> None:
    config = load_config(example_config(tmp_path))
    _, gateway, settings = build(config, good_environ(config), tmp_path)
    try:
        assert gateway.max_in_flight_per_root == 8
        assert gateway.tool_timeout == 30
        assert gateway.tool_error_detail is False
        assert (gateway.unverified_audit_rate, gateway.unverified_audit_burst) == (20, 100)
        queue = gateway.approvals
        assert (queue.max_pending_per_root, queue.max_pending_per_sub) == (10, 20)
        assert settings == {
            "host": "127.0.0.1",
            "port": 8000,
            "limit_concurrency": 256,
            "timeout_keep_alive": 5,
            "access_log": False,
        }
    finally:
        close(gateway)
    custom = {
        **config,
        "limits": {"max_in_flight_per_root": 2, "tool_timeout_seconds": 1.5},
        "approvals": {"max_pending_per_root": 3, "max_pending_per_sub": 4},
        "server": {"limit_concurrency": 10, "timeout_keep_alive_seconds": 2, "admin_threads": 1},
    }
    _, gateway, settings = build(custom, good_environ(config), tmp_path)
    try:
        assert (gateway.max_in_flight_per_root, gateway.tool_timeout) == (2, 1.5)
        assert gateway.approvals.max_pending_per_root == 3
        assert (settings["limit_concurrency"], settings["timeout_keep_alive"]) == (10, 2)
    finally:
        close(gateway)
    for section, key, bad in [
        ("limits", "max_in_flight_per_root", 0),
        ("limits", "tool_timeout_seconds", -1),
        ("limits", "tool_error_detail", "yes"),
        ("limits", "unverified_audit_per_second", 0),
        ("limits", "unverified_audit_burst", 1.5),
        ("server", "limit_concurrency", 0),
        ("server", "timeout_keep_alive_seconds", float("inf")),
        ("server", "admin_threads", True),
        ("server", "access_log", "on"),
        ("approvals", "max_pending_per_root", 0),
    ]:
        with pytest.raises(ConfigError):
            build({**config, section: {key: bad}}, good_environ(config), tmp_path / "unused")


def test_weak_or_missing_secrets_are_refused_with_a_clear_message(tmp_path: Path) -> None:
    config = load_config(example_config(tmp_path))
    good = good_environ(config)
    signing, admin = config["signing_key_env"], config["admin_key_hash_env"]
    cases = [
        ({admin: good[admin]}, f"environment variable {signing} is not set"),
        ({**good, signing: "   "}, f"environment variable {signing} is not set"),
        ({signing: good[signing]}, f"environment variable {admin} is not set"),
        ({**good, signing: base64.b64encode(bytes(32)).decode()}, "all zero"),
        ({**good, admin: hashlib.sha256(b"").hexdigest()}, "empty string"),
    ]
    for environ, message in cases:
        with pytest.raises(ConfigError, match=message):
            build(config, environ, tmp_path)
    assert not (tmp_path / "audit.jsonl").exists()  # refused before anything was opened
    env = Env(tmp_path)
    with pytest.raises(ValueError, match="empty string"):
        create_app(env.gateway, hashlib.sha256(b"").hexdigest())
    env.audit.close()


def test_build_does_not_follow_a_symlinked_audit_log(tmp_path: Path) -> None:
    config = load_config(example_config(tmp_path))
    target = tmp_path / "elsewhere.jsonl"
    target.write_bytes(b"")
    (tmp_path / "audit.jsonl").symlink_to(target)
    with pytest.raises(ConfigError, match="symbolic link"):
        build(config, good_environ(config), tmp_path)
    assert target.read_bytes() == b""  # nothing was appended through the link


def test_build_creates_a_private_store_file_and_refuses_a_shared_one(tmp_path: Path) -> None:
    config = load_config(example_config(tmp_path))
    config = {**config, "store": {"kind": "sqlite", "path": "caveat.sqlite"}}
    _, gateway, _ = build(config, good_environ(config), tmp_path)
    close(gateway)
    store_file = tmp_path / "caveat.sqlite"
    assert store_file.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "audit.jsonl").stat().st_mode & 0o777 == 0o600
    os.chmod(store_file, 0o644)
    with pytest.raises(ConfigError, match="group- or world-accessible"):
        build(config, good_environ(config), tmp_path)


def test_main_sets_uvicorn_limits_warns_off_loopback_and_keeps_tokens_out_of_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import uvicorn as real_uvicorn

    path = example_config(tmp_path)
    config = load_config(path)
    for name, value in good_environ(config).items():
        monkeypatch.setenv(name, value)
    runs: list[dict[str, Any]] = []
    monkeypatch.setattr(real_uvicorn, "run", lambda app, **options: runs.append(options))

    assert server_module.main(["--config", str(path)]) == 0
    assert "not loopback" not in capsys.readouterr().err  # the default host is loopback
    (options,) = runs
    assert (options["host"], options["access_log"]) == ("127.0.0.1", False)
    assert (options["limit_concurrency"], options["timeout_keep_alive"]) == (256, 5)
    assert options["proxy_headers"] is False and options["server_header"] is False

    exposed = tmp_path / "exposed.yaml"
    exposed.write_text(path.read_text().replace('host: "127.0.0.1"', 'host: "0.0.0.0"') + "\n")
    (tmp_path / "audit.jsonl").unlink()
    assert server_module.main(["--config", str(exposed)]) == 0
    warning = capsys.readouterr().err
    assert "not loopback" in warning and "TLS" in warning
    assert runs[1]["host"] == "0.0.0.0"

    for host, expected in [
        ("127.0.0.1", True),
        ("127.8.9.1", True),
        ("::1", True),
        ("localhost", True),
        ("0.0.0.0", False),
        ("::", False),
        ("10.0.0.5", False),
        ("gateway.internal", False),
    ]:
        assert is_loopback(host) is expected, host

    # If the access log is turned on, the filter main() installs drops query strings.
    logger = logging.getLogger("uvicorn.access")
    assert any(type(f) is server_module._NoQueryStrings for f in logger.filters)
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        "",
        0,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:5", "POST", "/call?access_token=SECRETSECRET", "1.1", 400),
        None,
    )
    assert server_module._NoQueryStrings().filter(record) is True
    assert record.getMessage() == '127.0.0.1:5 - "POST /call HTTP/1.1" 400'
    for f in [f for f in logger.filters if type(f) is server_module._NoQueryStrings]:
        logger.removeFilter(f)


def test_deployment_notes_exist_and_name_what_the_proxy_must_do() -> None:
    text = (ROOT / "docs" / "DEPLOYMENT.md").read_text()
    for topic in ("TLS", "timeout", "percent-encoded", "--checkpoint", "0600", "loopback"):
        assert topic in text, topic
    assert "—" not in text
