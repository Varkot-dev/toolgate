"""End to end over real HTTP: a uvicorn server on a free port and a scripted client.

The first test is the milestone's "done when": one script drives allow, deny
and approve through the public endpoints. The rest attack the HTTP boundary:
credential confusion, malformed bodies, header and path tricks, and races.
"""

from __future__ import annotations

import base64
import json
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

from test_gateway import Env  # noqa: E402
from toolgate.audit import verify  # noqa: E402
from toolgate.server import (  # noqa: E402
    ConfigError,
    build,
    create_app,
    hash_admin_key,
    load_config,
    strict_json,
)

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

    def __init__(self, tmp_path: Path, **app_options: Any) -> None:
        self.env = Env(tmp_path)
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
    decisions = [e["decision"] for e in env.entries()]
    assert decisions == ["allow", "deny", "deny", "approve", "approved", "deny"]
    assert report["entries"] == len(decisions) == 6
    head = http.get("/audit/head", headers=live.admin).json()
    assert head == report["head"] and head["seq"] == 5
    assert verify(env.audit_path, head["hash"]).ok
    assert env.entries()[4]["approver"] == "alice@example.com"
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
    assert live.env.entries() == []  # no credential presented properly, so nothing was decided

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
    assert all(e["jti"].startswith("unverified:") for e in live.env.entries())


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
    assert live.env.entries() == []
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
    assert final["ok"] and final["entries"] == 20


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
        config["signing_key_env"]: base64.b64encode(bytes(32)).decode(),
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
        {**config, "tools": {"echo": "toolgate.server:nope"}},
        {**config, "tools": {"bad name": "toolgate.server:echo"}},
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
