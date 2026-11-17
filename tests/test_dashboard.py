"""The operator dashboard: admin-only access, CSRF, escaping, approvals and the tamper demo.

Rule for every refusal test: assert that nothing happened (the approval is
still pending, the tool spy was not called, the log is byte-identical), not
only that a status came back.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_gateway import Env  # noqa: E402
from toolgate.audit import FIELDS, verify  # noqa: E402
from toolgate.dashboard import (  # noqa: E402
    COOKIE,
    CSP,
    Sessions,
    mount_dashboard,
    tamper_demo,
)
from toolgate.server import ConfigError, build, create_app, hash_admin_key, load_config  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
EXTERNAL_MAIL = {"to": "kim@partner.org", "body": "<script>alert('arg')</script> Q3 notes"}


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


class Dash:
    """A gateway, the HTTP app with the dashboard mounted, and a browser-like client."""

    def __init__(self, tmp_path: Path, ttl: float = 900) -> None:
        self.env = Env(tmp_path)
        self.key = secrets.token_urlsafe(32)
        self.clock = Clock()
        self.app = create_app(self.env.gateway, hash_admin_key(self.key))
        self.sessions: Sessions = mount_dashboard(
            self.app,
            self.env.gateway,
            hash_admin_key(self.key),
            session_ttl_seconds=ttl,
            clock=self.clock,
        )
        self.client = TestClient(self.app)
        self.token = self.env.mint()

    def login(self, approver: str = "ana") -> str:
        """Sign in; returns the page's CSRF token."""
        response = self.client.post(
            "/dashboard/login", json={"key": self.key, "approver": approver}
        )
        assert response.status_code == 200, response.text
        page = self.client.get("/dashboard")
        assert page.status_code == 200
        match = re.search(r'name="csrf-token" content="([^"]+)"', page.text)
        assert match
        return match.group(1)

    def park(self, args: dict[str, Any] | None = None) -> str:
        """A send_email call that policy parks for approval; returns its id."""
        outcome = self.env.gateway.handle_call(self.token, "send_email", args or EXTERNAL_MAIL)
        assert outcome.status == "pending", outcome
        assert outcome.approval_id is not None
        return outcome.approval_id

    def pending_ids(self) -> list[str]:
        return [r.id for r in self.env.gateway.list_pending()]

    def close(self) -> None:
        self.client.close()
        self.env.audit.close()


@pytest.fixture
def dash(tmp_path: Path) -> Iterator[Dash]:
    d = Dash(tmp_path)
    try:
        yield d
    finally:
        d.close()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


GET_ROUTES = [
    "/dashboard/fragment/feed",
    "/dashboard/fragment/approvals",
    "/dashboard/fragment/chain",
    "/dashboard/fragment/verify",
]


def post_routes(approval_id: str) -> list[tuple[str, dict[str, Any]]]:
    return [
        (f"/dashboard/approvals/{approval_id}", {"decision": "approve"}),
        ("/dashboard/tamper", {"seq": 0, "field": "decision"}),
        ("/dashboard/logout", {}),
    ]


# ------------------------------------------------------------------ access


def test_every_data_route_refuses_a_caller_without_a_session(dash: Dash) -> None:
    approval_id = dash.park()
    log_before = sha256_file(dash.env.audit_path)
    admin_header = {"Authorization": f"Bearer {dash.key}"}
    forged = {COOKIE: secrets.token_urlsafe(32)}
    for headers, cookies in [({}, {}), (admin_header, {}), ({}, forged)]:
        dash.client.cookies.clear()
        for name, value in cookies.items():
            dash.client.cookies.set(name, value, path="/dashboard")
        page = dash.client.get("/dashboard", headers=headers, follow_redirects=False)
        assert page.status_code == 303
        assert page.headers["location"] == "/dashboard/login"
        assert "csrf-token" not in page.text
        for path in GET_ROUTES:
            response = dash.client.get(path, headers=headers)
            assert response.status_code == 401, path
            assert "send_email" not in response.text and "seq" not in response.text
        for path, body in post_routes(approval_id):
            response = dash.client.post(path, json=body, headers=headers)
            assert response.status_code == 401, path
    assert dash.pending_ids() == [approval_id]
    assert dash.env.spies["send_email"].calls == []
    assert sha256_file(dash.env.audit_path) == log_before


def test_login_with_a_wrong_key_fails_and_sets_no_cookie(dash: Dash) -> None:
    for key in ["", "wrong", dash.key + "x", dash.key.upper()]:
        response = dash.client.post("/dashboard/login", json={"key": key, "approver": "ana"})
        assert response.status_code == 401
        assert "set-cookie" not in response.headers
    # A bad approver name is refused even with the right key, and no session starts.
    for approver in ["", " ana", "ana\n", "a" * 257, 7]:
        response = dash.client.post(
            "/dashboard/login", json={"key": dash.key, "approver": approver}
        )
        assert response.status_code == 422
        assert "set-cookie" not in response.headers
    extra = dash.client.post(
        "/dashboard/login", json={"key": dash.key, "approver": "ana", "admin": True}
    )
    assert extra.status_code == 422 and "set-cookie" not in extra.headers
    assert dash.sessions.stored_keys() == []
    assert dash.client.get("/dashboard/fragment/feed").status_code == 401


def test_session_cookie_is_httponly_strict_and_only_its_hash_is_stored(dash: Dash) -> None:
    response = dash.client.post("/dashboard/login", json={"key": dash.key, "approver": "ana"})
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Path=/dashboard" in cookie
    assert "Max-Age=900" in cookie
    assert "Secure" not in cookie  # plain http here; see the next assertion for TLS
    value = dash.client.cookies[COOKIE]
    stored = dash.sessions.stored_keys()
    assert len(stored) == 1 and value not in stored[0]
    assert value not in str(dash.sessions.__dict__)

    tls = TestClient(dash.app, base_url="https://testserver")
    secure = tls.post("/dashboard/login", json={"key": dash.key, "approver": "ana"})
    assert "Secure" in secure.headers["set-cookie"]
    tls.close()


def test_session_expires(tmp_path: Path) -> None:
    dash = Dash(tmp_path, ttl=60)
    try:
        dash.login()
        assert dash.client.get("/dashboard/fragment/feed").status_code == 200
        dash.clock.now += 59
        assert dash.client.get("/dashboard/fragment/feed").status_code == 200
        dash.clock.now += 1
        assert dash.client.get("/dashboard/fragment/feed").status_code == 401
        page = dash.client.get("/dashboard", follow_redirects=False)
        assert page.status_code == 303
        assert dash.sessions.stored_keys() == []
    finally:
        dash.close()


def test_logout_ends_the_session(dash: Dash) -> None:
    csrf = dash.login()
    old = dash.client.cookies[COOKIE]
    assert dash.client.post("/dashboard/logout", json={}).status_code == 403  # no CSRF
    assert dash.client.get("/dashboard/fragment/feed").status_code == 200
    out = dash.client.post("/dashboard/logout", json={}, headers={"X-CSRF-Token": csrf})
    assert out.status_code == 200
    dash.client.cookies.set(COOKIE, old, path="/dashboard")  # replaying the old cookie
    assert dash.client.get("/dashboard/fragment/feed").status_code == 401


# ------------------------------------------------------------------- CSRF


def test_csrf_missing_wrong_or_cross_site_is_403_and_changes_nothing(dash: Dash) -> None:
    csrf = dash.login()
    approval_id = dash.park()
    log_before = sha256_file(dash.env.audit_path)
    other_csrf = dash.sessions.create("eve")[1].csrf  # another session's token
    bad_headers = [
        {},
        {"X-CSRF-Token": ""},
        {"X-CSRF-Token": csrf[:-1]},
        {"X-CSRF-Token": csrf + "x"},
        {"X-CSRF-Token": other_csrf},
        {"X-CSRF-Token": csrf, "Origin": "https://evil.example"},
        {"X-CSRF-Token": csrf, "Origin": "null"},
        {"X-CSRF-Token": csrf, "Sec-Fetch-Site": "cross-site"},
        {"X-CSRF-Token": csrf, "Sec-Fetch-Site": "same-site"},
    ]
    for headers in bad_headers:
        for decision in ("approve", "reject"):
            response = dash.client.post(
                f"/dashboard/approvals/{approval_id}", json={"decision": decision}, headers=headers
            )
            assert response.status_code == 403, headers
        tamper = dash.client.post(
            "/dashboard/tamper", json={"seq": 0, "field": "decision"}, headers=headers
        )
        assert tamper.status_code == 403
    # Two token headers are not one token.
    two = dash.client.post(
        f"/dashboard/approvals/{approval_id}",
        json={"decision": "approve"},
        headers=[("X-CSRF-Token", csrf), ("X-CSRF-Token", csrf)],
    )
    assert two.status_code == 403
    # A cross-site HTML form cannot even get its body read: the app takes JSON only.
    form = dash.client.post(
        f"/dashboard/approvals/{approval_id}",
        content=b"decision=approve",
        headers={"Content-Type": "application/x-www-form-urlencoded", "X-CSRF-Token": csrf},
    )
    assert form.status_code == 415
    record = dash.env.gateway.approvals.get(approval_id)
    assert record is not None and record.state == "pending"
    assert dash.pending_ids() == [approval_id]
    assert dash.env.spies["send_email"].calls == []
    assert sha256_file(dash.env.audit_path) == log_before


# -------------------------------------------------------------- approvals


def test_approve_runs_the_stored_call_exactly_once_and_logs_the_approver(dash: Dash) -> None:
    csrf = dash.login("Ana Lopez")
    approval_id = dash.park()
    queue = dash.client.get("/dashboard/fragment/approvals").text
    assert approval_id in queue and "kim@partner.org" in queue
    response = dash.client.post(
        f"/dashboard/approvals/{approval_id}",
        json={"decision": "approve"},
        headers={"X-CSRF-Token": csrf, "Origin": "http://testserver"},
    )
    assert response.status_code == 200, response.text
    assert "Approved by Ana Lopez; the stored call ran once." in response.text
    assert dash.env.spies["send_email"].calls == [EXTERNAL_MAIL]
    again = dash.client.post(
        f"/dashboard/approvals/{approval_id}",
        json={"decision": "approve"},
        headers={"X-CSRF-Token": csrf},
    )
    assert again.status_code == 409
    assert dash.env.spies["send_email"].calls == [EXTERNAL_MAIL]  # still once
    approved = [e for e in dash.env.entries() if e["decision"] == "approved"]
    assert len(approved) == 1
    assert approved[0]["approver"] == "Ana Lopez"
    assert approved[0]["tool"] == "send_email"
    assert dash.pending_ids() == []
    assert verify(dash.env.audit_path).ok
    feed = dash.client.get("/dashboard/fragment/feed").text
    assert "by Ana Lopez" in feed


def test_reject_through_the_dashboard_runs_nothing(dash: Dash) -> None:
    csrf = dash.login()
    approval_id = dash.park()
    response = dash.client.post(
        f"/dashboard/approvals/{approval_id}",
        json={"decision": "reject"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 200 and "Rejected by ana" in response.text
    assert dash.env.spies["send_email"].calls == []
    rejected = [e for e in dash.env.entries() if e["decision"] == "rejected"]
    assert [e["approver"] for e in rejected] == ["ana"]
    for bad in ({"decision": "maybe"}, {"decision": "approve", "approver": "eve"}, {}):
        response = dash.client.post(
            f"/dashboard/approvals/{approval_id}", json=bad, headers={"X-CSRF-Token": csrf}
        )
        assert response.status_code == 422
    missing = dash.client.post(
        "/dashboard/approvals/nope", json={"decision": "approve"}, headers={"X-CSRF-Token": csrf}
    )
    assert missing.status_code == 404


# -------------------------------------------------------------- tamper demo


def fill_log(dash: Dash) -> None:
    """A few entries of every kind: allow, deny, approve, approved, rejected."""
    gw, token = dash.env.gateway, dash.token
    gw.handle_call(token, "read_file", {"path": "reports/q3.txt"})
    gw.handle_call(token, "delete_file", {"path": "x"})
    first = dash.park()
    gw.resolve_approval(first, "approve", "ana")
    second = dash.park({"to": "sam@other.org", "body": "hi"})
    gw.resolve_approval(second, "reject", "ben")
    gw.handle_call(token, "read_file", {"path": "reports/q4.txt"})


@pytest.mark.parametrize("field", FIELDS)
def test_tamper_demo_reports_the_edited_entry_and_leaves_the_real_log_alone(
    dash: Dash, field: str
) -> None:
    fill_log(dash)
    csrf = dash.login()
    total = len(dash.env.entries())
    for seq in sorted({0, total // 2, total - 1}):
        before = sha256_file(dash.env.audit_path)
        response = dash.client.post(
            "/dashboard/tamper", json={"seq": seq, "field": field}, headers={"X-CSRF-Token": csrf}
        )
        assert response.status_code == 200, response.text
        assert sha256_file(dash.env.audit_path) == before  # byte-identical
        assert f"verify on the copy: FAILED at entry {seq}" in response.text
        assert "Real log" in response.text and "untouched" in response.text
        assert f"verify: ok, {total} entries" in response.text
        assert "Demo copy" in response.text
        assert response.text.count('class="block bad"') == 1
        assert verify(dash.env.audit_path, dash.env.gateway.audit.head()).ok
        # The same function the route uses, asked directly, names the same entry.
        demo = tamper_demo(dash.env.audit_path, seq, field)
        assert demo.result.first_bad_index == seq
        assert demo.old != demo.new
    # The gateway still appends to the real log, and it still verifies.
    outcome = dash.env.gateway.handle_call(dash.token, "read_file", {"path": "reports/z"})
    assert outcome.audit_seq == total
    assert verify(dash.env.audit_path, dash.env.gateway.audit.head()).ok


def test_tamper_demo_refuses_bad_input_and_leaves_no_copy_behind(
    dash: Dash, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fill_log(dash)
    csrf = dash.login()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr("tempfile.tempdir", str(scratch))
    before = sha256_file(dash.env.audit_path)
    for body in (
        {"seq": -1, "field": "decision"},
        {"seq": 10_000, "field": "decision"},
        {"seq": 0, "field": "nope"},
        {"seq": "0", "field": "decision"},
        {"seq": 0},
    ):
        response = dash.client.post("/dashboard/tamper", json=body, headers={"X-CSRF-Token": csrf})
        assert response.status_code == 422, body
    ok = dash.client.post(
        "/dashboard/tamper", json={"seq": 1, "field": "rule"}, headers={"X-CSRF-Token": csrf}
    )
    assert ok.status_code == 200
    assert list(scratch.iterdir()) == []  # the copy was deleted
    assert sha256_file(dash.env.audit_path) == before


# --------------------------------------------------------------- escaping


MARKUP = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(2)>",
    '"><svg onload=alert(3)>',
]


def assert_inert(text: str) -> None:
    lowered = text.lower()
    for raw in ("<script", "<img", "<svg", "onerror=alert", "onload=alert"):
        if raw.startswith("<"):
            assert raw not in lowered, raw
    assert "&lt;script&gt;" in text


def test_markup_in_tool_names_rules_actors_and_arguments_renders_inert(dash: Dash) -> None:
    # Written straight to the log: the gateway itself refuses such tool names,
    # but the dashboard must not trust that a log only holds what the gateway wrote.
    dash.env.audit.append(
        jti=MARKUP[2],
        actors=[MARKUP[1], "agent:<b>bold</b>"],
        tool=MARKUP[0],
        args={},
        decision="deny",
        rule=MARKUP[1] + " " + MARKUP[0],
    )
    dash.env.audit.append(
        jti="t",
        actors=[],
        tool="send_email",
        args={},
        decision="approved",
        rule=MARKUP[2],
        approver=MARKUP[0],
    )
    dash.park({"to": MARKUP[0], "body": MARKUP[1] + MARKUP[2]})
    csrf = dash.login()
    for path in ("/dashboard/fragment/feed", "/dashboard/fragment/chain"):
        assert_inert(dash.client.get(path).text)
    queue = dash.client.get("/dashboard/fragment/approvals").text
    assert_inert(queue)
    assert "&lt;img src=x onerror=alert(2)&gt;" in queue
    tamper = dash.client.post(
        "/dashboard/tamper", json={"seq": 0, "field": "tool"}, headers={"X-CSRF-Token": csrf}
    )
    assert_inert(tamper.text)
    # The approver name shown in the page header comes from the session.
    dash.client.cookies.clear()
    dash.client.post("/dashboard/login", json={"key": dash.key, "approver": "<i>ana</i>"})
    page = dash.client.get("/dashboard").text
    assert "<i>ana</i>" not in page and "&lt;i&gt;ana&lt;/i&gt;" in page


# ---------------------------------------------------------------- headers


def test_security_headers_are_on_every_dashboard_response(dash: Dash) -> None:
    responses = [
        dash.client.get("/dashboard", follow_redirects=False),  # 303
        dash.client.get("/dashboard/login"),
        dash.client.get("/dashboard/static/dashboard.css"),
        dash.client.get("/dashboard/static/dashboard.js"),
        dash.client.get("/dashboard/static/secret.py"),  # 404 from the route
        dash.client.get("/dashboard/nothing-here"),  # 404 from the router
        dash.client.get("/dashboard/fragment/feed"),  # 401
        dash.client.post("/dashboard/login", json={"key": "x", "approver": "a"}),  # 401
        dash.client.post("/dashboard/login", content=b"k=v"),  # 415 from the app's guard
    ]
    csrf = dash.login()
    approval_id = dash.park()
    responses += [dash.client.get("/dashboard")]
    responses += [dash.client.get(path) for path in GET_ROUTES]
    responses += [
        dash.client.post(path, json=body, headers={"X-CSRF-Token": csrf})
        for path, body in post_routes(approval_id)
    ]
    assert len({r.status_code for r in responses}) >= 5
    for response in responses:
        headers = response.headers
        assert headers["content-security-policy"] == CSP, response.request.url
        assert "default-src 'self'" in CSP and "unsafe-inline" not in CSP
        assert "frame-ancestors 'none'" in CSP
        assert headers["x-frame-options"] == "DENY"
        assert "no-store" in headers["cache-control"]
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["referrer-policy"] == "no-referrer"
        assert len(headers.get_list("content-security-policy")) == 1
    # The API outside /dashboard is not changed by mounting the dashboard.
    assert "content-security-policy" not in dash.client.get("/healthz").headers


def test_pages_hold_no_inline_script_or_style(dash: Dash) -> None:
    login = dash.client.get("/dashboard/login").text
    dash.login()
    page = dash.client.get("/dashboard").text
    for text in (login, page):
        assert re.findall(r"<script(?![^>]*\bsrc=)", text) == []
        assert " style=" not in text and "<style" not in text
        assert not re.search(r"\son[a-z]+\s*=", text)  # no inline event handlers
        assert "http://" not in text and "https://" not in text  # nothing third-party
    js = dash.client.get("/dashboard/static/dashboard.js").text
    assert "http" not in js and "eval(" not in js


# ------------------------------------------------------------ enabled flag


def example_config(tmp_path: Path) -> dict[str, Any]:
    for name in ("gateway.example.yaml", "policy.example.yaml"):
        shutil.copy(ROOT / "config" / name, tmp_path / name)
    return load_config(tmp_path / "gateway.example.yaml")


def environ_for(config: dict[str, Any], admin_key: str) -> dict[str, str]:
    return {
        config["signing_key_env"]: base64.b64encode(secrets.token_bytes(32)).decode(),
        config["admin_key_hash_env"]: hash_admin_key(admin_key),
    }


def test_dashboard_is_off_by_default(tmp_path: Path) -> None:
    env = Env(tmp_path)
    try:
        plain = TestClient(create_app(env.gateway, hash_admin_key("k" * 40)))
        for path in ["/dashboard", "/dashboard/login", *GET_ROUTES]:
            assert plain.get(path).status_code == 404
        assert plain.post("/dashboard/login", json={"key": "k", "approver": "a"}).status_code == 404
        plain.close()
    finally:
        env.audit.close()

    base = tmp_path / "configured"
    base.mkdir()
    config = example_config(base)
    assert config["dashboard"]["enabled"] is False  # the example ships it off
    key = secrets.token_urlsafe(32)
    for dashboard_section, expected in [(None, 404), ({}, 404), ({"enabled": False}, 404)]:
        cfg = {k: v for k, v in config.items() if k != "dashboard"}
        if dashboard_section is not None:
            cfg["dashboard"] = dashboard_section
        app, gateway, _ = build(cfg, environ_for(config, key), base)
        try:
            with TestClient(app) as client:
                assert client.get("/dashboard", follow_redirects=False).status_code == expected
                assert client.get("/dashboard/login").status_code == expected
        finally:
            gateway.audit.close()

    app, gateway, _ = build(
        {**config, "dashboard": {"enabled": True}}, environ_for(config, key), base
    )
    try:
        with TestClient(app) as client:
            assert client.get("/dashboard", follow_redirects=False).status_code == 303
            login = client.post("/dashboard/login", json={"key": key, "approver": "ana"})
            assert login.status_code == 200
            assert client.get("/dashboard/fragment/feed").status_code == 200
            # The admin API is unchanged and still wants its bearer key, not the cookie.
            assert client.get("/approvals").status_code == 401
    finally:
        gateway.audit.close()


def test_bad_dashboard_settings_fail_closed(tmp_path: Path) -> None:
    config = example_config(tmp_path)
    environ = environ_for(config, "k" * 40)
    for section in [
        {"enabled": "yes"},
        {"enabled": True, "session_ttl_seconds": 0},
        {"enabled": True, "session_ttl_seconds": float("inf")},
        {"enabled": True, "secure_cookie": "sometimes"},
        {"enabled": True, "secure_cookie": False},
        {"enabled": True, "feed_entries": 0},
        {"enabled": True, "max_sessions": 1.5},
        {"enabled": True, "surprise": 1},
        "on",
    ]:
        with pytest.raises(ConfigError):
            build({**config, "dashboard": section}, environ, tmp_path)
