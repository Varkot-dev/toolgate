"""Operator dashboard: a live decision feed, the approval queue and the audit chain.

Mounted on the HTTP app by `mount_dashboard` only when the config says
`dashboard.enabled: true`; off by default, and then none of these routes
exist (404).

    GET  /dashboard                      page          session (else 303 to login)
    GET  /dashboard/login                login page    none
    POST /dashboard/login                admin key -> session cookie
    POST /dashboard/logout               session + CSRF
    GET  /dashboard/static/{name}        CSS, JS, fonts, icons: none (fixed files, no data)
    GET  /dashboard/fragment/feed        HTML          session
    GET  /dashboard/fragment/approvals   HTML          session
    GET  /dashboard/fragment/chain       HTML          session
    GET  /dashboard/fragment/verify      HTML          session
    POST /dashboard/approvals/{id}       approve or reject: session + CSRF
    POST /dashboard/tamper               tamper demo on a copy: session + CSRF

How a browser carries the admin credential. The admin API takes the admin key
in an `Authorization` header, which a browser cannot attach to page loads. So
the login form sends the same admin key once (checked exactly as the API checks
it: SHA-256, constant-time compare with the configured hash) and gets back a
session cookie:

  * the cookie value is 32 random bytes; the server keeps only a SHA-256 of
    it, so a dump of server memory or a debugger does not yield live cookies
  * HttpOnly, SameSite=Strict, Path=/dashboard, Max-Age = the session TTL;
    Secure when the request arrived over TLS (or always, `secure_cookie: true`,
    which is what a deployment behind a TLS proxy should set because the app
    itself only sees plain HTTP there)
  * an absolute expiry (`session_ttl_seconds`, default 15 minutes), checked
    on every request; at most `max_sessions` live at once, oldest dropped
  * the approver name is entered at login, validated like every name the
    audit log records, and bound to the session, so each approval made in
    that session is logged with it. Like `POST /approvals/{id}` it is
    declared, not authenticated: there is still one shared admin key.

CSRF. Every state-changing request (logout, approve, reject, tamper demo)
needs, besides the SameSite=Strict cookie, the session's random CSRF token in
an `X-CSRF-Token` header, compared in constant time. Requests carrying an
`Origin` that is not this host, or `Sec-Fetch-Site` other than same-origin,
are refused too. The app's own guard accepts only `application/json` bodies,
which a cross-site HTML form cannot send without a CORS preflight that this
app never answers.

Headers on every response under /dashboard, errors included:
`Content-Security-Policy: default-src 'self'` (no inline script or style, no
framing), `X-Frame-Options: DENY`, `Cache-Control: no-store`, nosniff, no
referrer. All HTML is built here, on the server, and every value that comes
from the audit log or the approval queue is escaped as untrusted text: tool
names, rule strings, actor names and argument values can contain markup.

The tamper demo never touches the real log. It copies the file to a private
temporary directory, changes one field of one entry IN THE COPY (re-encoded
canonically, stored hash left alone), runs the real `verify` on the copy,
deletes the copy, and shows the result next to the real log verifying.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import math
import os
import re
import secrets
import shutil
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import anyio
import anyio.to_thread
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from caveat.approvals import Approval, ApprovalError, valid_name
from caveat.audit import FIELDS, GENESIS, Head, VerifyResult, canonical_json, verify
from caveat.gateway import ALLOWED, ERROR, Gateway, plain_args
from caveat.server import safe_text, strict_json

PREFIX = "/dashboard"
COOKIE = "caveat_dashboard"
CSRF_HEADER = "x-csrf-token"
STATIC = Path(__file__).resolve().parent / "static"
ASSETS = {
    "dashboard.css": "text/css; charset=utf-8",
    "dashboard.js": "text/javascript",
    # Vendored fonts (SIL OFL) and Lucide icons (ISC); licenses sit next to them.
    "plus-jakarta-sans-latin-500-normal.woff2": "font/woff2",
    "plus-jakarta-sans-latin-700-normal.woff2": "font/woff2",
    "jetbrains-mono-latin-500-normal.woff2": "font/woff2",
    "icon-check.svg": "image/svg+xml",
    "icon-x.svg": "image/svg+xml",
    "icon-clock.svg": "image/svg+xml",
    "icon-link.svg": "image/svg+xml",
}
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)
SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"content-security-policy", CSP.encode("ascii")),
    (b"x-frame-options", b"DENY"),
    (b"cache-control", b"no-store, max-age=0"),
    (b"pragma", b"no-cache"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
)
DEFAULT_SESSION_TTL = 900
DEFAULT_FEED_ENTRIES = 40
DEFAULT_MAX_SESSIONS = 16
CHAIN_BLOCKS = 7  # blocks in the chain view and on each side of the tamper demo
MAX_DEMO_COPY_BYTES = 64 * 1024 * 1024
MAX_KEY_CHARS = 4096
MAX_ARG_CHARS = 300
_HEX64 = re.compile(r"[0-9a-f]{64}")
_APPROVAL_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_SESSION_ID = re.compile(r"[A-Za-z0-9_-]{20,128}")
_DECISION_CLASS = {
    "allow": "allow",
    "approved": "allow",
    "deny": "deny",
    "rejected": "deny",
    "approve": "approve",
}


def esc(value: Any) -> str:
    """`value` as HTML text: escaped, quotes included, and always encodable."""
    return html.escape(safe_text(value), quote=True)


def short(value: Any, n: int = 8) -> str:
    text = value if type(value) is str else safe_text(value)
    return text[:n]


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------


def _under_dashboard(path: str) -> bool:
    return path == PREFIX or path.startswith(PREFIX + "/")


class _SecurityHeaders:
    """ASGI middleware: the dashboard's headers on every response under /dashboard.

    It is the outermost layer, so it also covers refusals made before a route
    runs (the body guard's 413 and 415, a 404 for an unknown path).
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or not _under_dashboard(scope.get("path", "")):
            await self.app(scope, receive, send)
            return
        names = {name for name, _ in SECURITY_HEADERS}

        async def send_with_headers(message: Any) -> None:
            if message["type"] == "http.response.start":
                kept = [(k, v) for k, v in message.get("headers", []) if k.lower() not in names]
                message = {**message, "headers": kept + list(SECURITY_HEADERS)}
            await send(message)

        await self.app(scope, receive, send_with_headers)


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


@dataclass
class Session:
    approver: str
    csrf: str
    created_at: float
    expires_at: float


def _session_key(session_id: str) -> str:
    """What the server stores instead of the session id."""
    return hashlib.sha256(b"caveat dashboard session\x00" + session_id.encode()).hexdigest()


class Sessions:
    """Live dashboard sessions, keyed by a hash of the cookie value. In memory only."""

    def __init__(self, ttl: float, max_sessions: int, clock: Callable[[], float]) -> None:
        self.ttl = ttl
        self.max_sessions = max_sessions
        self.clock = clock
        self._by_key: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, approver: str) -> tuple[str, Session]:
        session_id = secrets.token_urlsafe(32)
        now = self.clock()
        session = Session(approver, secrets.token_urlsafe(32), now, now + self.ttl)
        with self._lock:
            self._prune(now)
            while len(self._by_key) >= self.max_sessions:
                oldest = min(self._by_key, key=lambda k: self._by_key[k].created_at)
                del self._by_key[oldest]
            self._by_key[_session_key(session_id)] = session
        return session_id, session

    def get(self, session_id: str | None) -> Session | None:
        if type(session_id) is not str or not _SESSION_ID.fullmatch(session_id):
            return None
        key = _session_key(session_id)
        with self._lock:
            session = self._by_key.get(key)
            if session is None:
                return None
            if not self.clock() < session.expires_at:
                del self._by_key[key]
                return None
            return session

    def drop(self, session_id: str | None) -> None:
        if type(session_id) is str:
            with self._lock:
                self._by_key.pop(_session_key(session_id), None)

    def stored_keys(self) -> list[str]:
        """For tests: what is held server-side (hashes, never the cookie values)."""
        with self._lock:
            return list(self._by_key)

    def _prune(self, now: float) -> None:
        for key in [k for k, s in self._by_key.items() if not now < s.expires_at]:
            del self._by_key[key]


# ---------------------------------------------------------------------------
# Reading the log
# ---------------------------------------------------------------------------


def tail_lines(path: Path, count: int, chunk: int = 65_536) -> list[bytes]:
    """The last `count` complete lines of a file, without reading all of it.

    A last line with no newline yet (an append in progress) is left out.
    """
    with open(path, "rb") as stream:
        stream.seek(0, os.SEEK_END)
        pos = stream.tell()
        data = b""
        while pos > 0 and data.count(b"\n") <= count + 1:
            step = min(chunk, pos)
            pos -= step
            stream.seek(pos)
            data = stream.read(step) + data
    data = data[: data.rfind(b"\n") + 1]  # drop an incomplete last line
    lines = data.split(b"\n")[:-1]
    if pos > 0 and lines:
        lines = lines[1:]  # the first piece may start mid-line
    return lines[-count:] if count else []


def parse_line(raw: bytes) -> dict[str, Any] | None:
    """One log line as a dict, or None if it is not a JSON object. Not verified."""
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return value if type(value) is dict else None


def verify_live(gateway: Gateway) -> tuple[VerifyResult, Head]:
    """The real verify of the real log against the head this process holds.

    Same procedure as GET /audit/verify: if entries were appended while the
    file was being read, read it again.
    """
    for _ in range(3):
        head = gateway.audit.head()
        result = verify(gateway.audit.path, head)
        if result.ok or gateway.audit.head() == head:
            return result, head
    return verify(gateway.audit.path), gateway.audit.head()


# ---------------------------------------------------------------------------
# The tamper demo
# ---------------------------------------------------------------------------


def _flip_hex(value: Any) -> Any:
    if type(value) is not str or not value:
        return "0" * 64
    return value[:-1] + ("1" if value[-1] == "0" else "0")


_OTHER_DECISION = {
    "allow": "deny",
    "deny": "allow",
    "approve": "allow",
    "approved": "rejected",
    "rejected": "approved",
}


def edited_value(field: str, old: Any) -> Any:
    """A different value of the same kind for `field`; the edit the demo makes."""
    if field in ("seq", "time"):
        base = old if type(old) is int else 0
        return base + (1 if field == "seq" else 1_000_000_000)
    if field == "jti":
        return f"{old}-forged"
    if field == "actors":
        return [*(old if type(old) is list else []), "agent:intruder"]
    if field == "tool":
        return "read_file" if old == "delete_file" else "delete_file"
    if field == "decision":
        return _OTHER_DECISION.get(old, "allow") if type(old) is str else "allow"
    if field == "rule":
        return f"{old} (edited)"
    if field == "approver":
        return "eve" if old == "mallory" else "mallory"
    if field in ("args_hash", "prev", "hash"):
        return _flip_hex(old)
    raise ValueError(f"unknown field {field!r}")


@dataclass(frozen=True)
class TamperResult:
    seq: int
    field: str
    old: Any
    new: Any
    result: VerifyResult  # the real verify, run on the copy
    window: list[tuple[int, dict[str, Any] | None]]  # (index, entry) of the copy around seq
    total: int


def tamper_demo(source: Path, seq: int, field: str) -> TamperResult:
    """Copy the log, edit one field of entry `seq` in the copy, verify the copy.

    The real file is opened read-only, once. The copy lives in a fresh
    private directory that is removed before this returns.
    """
    if field not in FIELDS:
        raise ValueError("unknown field")
    with open(source, "rb") as stream:
        data = stream.read(MAX_DEMO_COPY_BYTES + 1)
    if len(data) > MAX_DEMO_COPY_BYTES:
        raise ValueError("the log is too large for the demo copy")
    data = data[: data.rfind(b"\n") + 1]  # an append in progress is not copied
    lines = data.split(b"\n")[:-1]
    if not 0 <= seq < len(lines):
        raise ValueError(f"entry must be between 0 and {len(lines) - 1}")
    entry = parse_line(lines[seq])
    if entry is None or field not in entry:
        raise ValueError("that entry cannot be parsed, so there is nothing to edit")
    old = entry[field]
    new = edited_value(field, old)
    entry[field] = new
    lines[seq] = canonical_json(entry)
    folder = tempfile.mkdtemp(prefix="caveat-demo-copy-")
    try:
        copy = Path(folder) / "audit-demo-copy.jsonl"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(copy, flags, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(b"".join(line + b"\n" for line in lines))
        result = verify(copy)
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    start = max(0, min(seq - CHAIN_BLOCKS // 2, len(lines) - CHAIN_BLOCKS))
    window = [
        (i, parse_line(lines[i])) for i in range(start, min(len(lines), start + CHAIN_BLOCKS))
    ]
    return TamperResult(seq, field, old, new, result, window, len(lines))


# ---------------------------------------------------------------------------
# Rendering. Every value from the log or the queue goes through esc().
# ---------------------------------------------------------------------------


def _clock_text(ns: Any) -> tuple[str, str]:
    """(HH:MM:SS, full UTC timestamp) for integer nanoseconds."""
    if type(ns) is not int or ns < 0:
        return "?", "not a valid time"
    seconds = ns // 1_000_000_000
    try:
        stamp = time.gmtime(seconds)
    except (OverflowError, OSError, ValueError):
        return "?", "out of range"
    return time.strftime("%H:%M:%S", stamp), time.strftime("%Y-%m-%d %H:%M:%S UTC", stamp)


def _duration(seconds: float) -> str:
    if type(seconds) not in (int, float) or not math.isfinite(seconds):
        return "?"
    s = max(0, int(seconds))
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min {s % 60:02d} s"
    return f"{s // 3600} h {s % 3600 // 60:02d} min"


def _decision_badge(decision: Any, approver: Any = None) -> str:
    kind = _DECISION_CLASS.get(decision, "unknown") if type(decision) is str else "unknown"
    label = esc(decision)
    by = f' <span class="by">by {esc(approver)}</span>' if approver else ""
    return f'<span class="badge {kind}"><i></i>{label}</span>{by}'


def _actors(value: Any) -> str:
    if type(value) is list:
        return " &gt; ".join(esc(a) for a in value) or '<span class="muted">none</span>'
    return esc(value)


def render_feed(entries: list[dict[str, Any] | None]) -> str:
    """Newest first. Shows what the file holds; the Verify button checks it."""
    if not entries:
        return '<p class="empty">No decisions yet.</p>'
    rows = []
    for entry in reversed(entries):
        if entry is None:
            rows.append('<tr><td colspan="7" class="muted">unreadable line</td></tr>')
            continue
        clock, full = _clock_text(entry.get("time"))
        badge = _decision_badge(entry.get("decision"), entry.get("approver"))
        rows.append(
            "<tr>"
            f'<td class="num">{esc(entry.get("seq"))}</td>'
            f'<td class="mono" title="{esc(full)}">{esc(clock)}</td>'
            f'<td class="mono tool">{esc(entry.get("tool"))}</td>'
            f'<td class="nowrap">{badge}</td>'
            f'<td class="rule">{esc(entry.get("rule"))}</td>'
            f'<td class="actors">{_actors(entry.get("actors"))}</td>'
            f'<td class="mono hash">{esc(short(entry.get("hash")))}</td>'
            "</tr>"
        )
    return (
        '<table class="feed"><thead><tr><th class="num">seq</th><th>time</th><th>tool</th>'
        "<th>decision</th><th>rule</th><th>actors</th><th>hash</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _arg_value(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if len(text) > MAX_ARG_CHARS:
        text = text[:MAX_ARG_CHARS] + " ...[truncated]"
    return esc(text)


def render_queue(records: list[Approval], now: float) -> str:
    if not records:
        return '<p class="empty">Nothing is waiting for a decision.</p>'
    cards = []
    for record in records:
        args = plain_args(record.call.args)
        arg_rows = (
            "".join(
                f'<tr><th class="mono">{esc(k)}</th><td class="mono">{_arg_value(v)}</td></tr>'
                for k, v in sorted(args.items())
            )
            or '<tr><td class="muted">no arguments</td></tr>'
        )
        rid = esc(record.id)
        cards.append(
            f'<article class="approval" data-id="{rid}">'
            "<header>"
            f'<span class="mono tool">{esc(record.call.tool)}</span>'
            f'<span class="times">waiting {esc(_duration(now - record.created_at))}'
            f" &middot; expires in {esc(_duration(record.expires_at - now))}</span>"
            "</header>"
            f'<p class="who"><span class="label">for</span> {esc(record.sub)} '
            f'<span class="label">via</span> {_actors(list(record.actors))}</p>'
            f'<table class="args">{arg_rows}</table>'
            f'<p class="why"><span class="label">rule</span> '
            f'<span class="mono">{esc(record.rule)}</span> {esc(record.reason)}</p>'
            '<div class="actions">'
            f'<button class="approve" data-id="{rid}" data-decision="approve">Approve</button>'
            f'<button class="reject" data-id="{rid}" data-decision="reject">Reject</button>'
            "</div></article>"
        )
    return "".join(cards)


def _block(
    index: int,
    entry: dict[str, Any] | None,
    state: str,
    edited: str | None = None,
    link: str = "",
) -> str:
    """One chain block. state: plain, ok, bad, after. link: ok, broken or ''."""
    arrow = f'<span class="link {link}" aria-hidden="true"></span>' if link else ""
    if entry is None:
        return f'{arrow}<div class="block {state}"><b>entry {index}</b><p>unreadable</p></div>'

    def row(name: str, text: str) -> str:
        mark = " edited" if name == edited else ""
        return f'<p class="f-{name}{mark}">{text}</p>'

    tag = ' <span class="tag">first bad</span>' if state == "bad" else ""
    prev_text = esc(short(entry.get("prev")))
    if entry.get("prev") == GENESIS:
        prev_text = "genesis"
    return (
        f'{arrow}<button type="button" class="block {state}" data-seq="{index}" '
        f'title="Choose entry {index} for the tamper demo">'
        f"<b>entry {esc(entry.get('seq'))}{tag}</b>"
        + row("tool", esc(entry.get("tool")))
        + row("decision", _decision_badge(entry.get("decision")))
        + row("prev", f'<span class="k">prev</span> {prev_text}')
        + row("hash", f'<span class="k">hash</span> {esc(short(entry.get("hash")))}')
        + "</button>"
    )


def render_chain(
    entries: list[dict[str, Any] | None], first_index: int, *, count_earlier: bool = True
) -> str:
    if not entries:
        return '<p class="empty">The log is empty.</p>'
    parts = []
    previous: dict[str, Any] | None = None
    for offset, entry in enumerate(entries):
        link = ""
        if offset:
            same = previous is not None and entry is not None
            link = "ok" if same and entry.get("prev") == previous.get("hash") else "broken"
        parts.append(_block(first_index + offset, entry, "plain", link=link))
        previous = entry
    more = ""
    if first_index and count_earlier:
        more = f'<span class="more">{first_index} earlier</span>'
    return f'<div class="chain">{more}{"".join(parts)}</div>'


def render_verify(result: VerifyResult, head: Head) -> str:
    if result.ok:
        return (
            '<p class="verdict ok"><i></i>verify: ok, '
            f"{result.entries} entries, head {esc(short(head.hash, 12))}</p>"
        )
    where = "" if result.first_bad_index is None else f" at entry {result.first_bad_index}"
    return f'<p class="verdict bad"><i></i>verify: FAILED{where}: {esc(result.problem)}</p>'


def render_tamper(demo: TamperResult, real: VerifyResult, real_head: Head, real_window: str) -> str:
    bad = demo.result.first_bad_index
    blocks = []
    for offset, (index, entry) in enumerate(demo.window):
        if bad is None or demo.result.ok or index < bad:
            state = "ok"
        elif index == bad:
            state = "bad"
        else:
            state = "after"
        link = ""
        if offset:
            link = "ok" if state == "ok" else ("broken" if state == "bad" else "after")
        blocks.append(_block(index, entry, state, demo.field if index == demo.seq else None, link))
    old = esc(json.dumps(demo.old, ensure_ascii=False))
    new = esc(json.dumps(demo.new, ensure_ascii=False))
    if demo.result.ok:
        verdict = (
            '<p class="verdict ok"><i></i>verify on the copy: ok (the edit was not caught)</p>'
        )
    else:
        where = "" if bad is None else f" at entry {bad}"
        verdict = (
            f'<p class="verdict bad"><i></i>verify on the copy: FAILED{where}</p>'
            f'<p class="says"><span class="label">The verifier says:</span> '
            f"{esc(demo.result.problem)}</p>"
        )
    return (
        '<div class="demo-bar"><span class="label">Tamper demo</span>'
        '<button type="button" id="close-demo" class="quiet">Close demo</button></div>'
        '<section class="side real">'
        '<h3>Real log <span class="pill">untouched</span></h3>'
        f"{render_verify(real, real_head)}{real_window}"
        "</section>"
        '<section class="side copy">'
        '<h3>Demo copy <span class="pill warn">temporary file, deleted after the check</span></h3>'
        f'<p class="edit">Changed entry {demo.seq}, field '
        f'<span class="mono">{esc(demo.field)}</span>: '
        f'<span class="mono">{old}</span> to <span class="mono">{new}</span></p>'
        f"{verdict}"
        f'<div class="chain">{"".join(blocks)}</div>'
        '<p class="legend"><span class="l-ok">verified</span>'
        '<span class="l-bad">first bad entry</span>'
        '<span class="l-after">not verified: checking stops at the break</span></p>'
        "</section>"
    )


def _window_of(lines: list[bytes], first: int, *, count_earlier: bool = True) -> str:
    return render_chain([parse_line(x) for x in lines], first, count_earlier=count_earlier)


LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>caveat dashboard: sign in</title>
<link rel="stylesheet" href="/dashboard/static/dashboard.css">
<script src="/dashboard/static/dashboard.js" defer></script>
</head><body class="login-page">
<main class="login">
<h1>caveat</h1>
<p class="sub">Operator dashboard. Sign in with the gateway's admin key.</p>
<form id="login" autocomplete="off">
<label>Admin key<input id="key" name="key" type="password" required></label>
<label>Your name, recorded on every approval you make
<input id="approver" name="approver" type="text" required maxlength="256"></label>
<button type="submit">Sign in</button>
<p id="login-error" class="error" role="alert"></p>
</form>
<p class="note">The key is exchanged for a session cookie that expires; it is not stored
in the browser.</p>
</main></body></html>
"""


# ---------------------------------------------------------------------------
# Mounting
# ---------------------------------------------------------------------------


def _check_options(ttl: Any, secure_cookie: Any, feed_entries: Any, max_sessions: Any) -> None:
    if type(ttl) not in (int, float) or not math.isfinite(ttl) or not 0 < ttl <= 86_400:
        raise ValueError("dashboard.session_ttl_seconds must be a number in (0, 86400]")
    if secure_cookie != "auto" and secure_cookie is not True:
        raise ValueError("dashboard.secure_cookie must be auto or true")
    if type(feed_entries) is not int or not 1 <= feed_entries <= 500:
        raise ValueError("dashboard.feed_entries must be an integer from 1 to 500")
    if type(max_sessions) is not int or not 1 <= max_sessions <= 1000:
        raise ValueError("dashboard.max_sessions must be an integer from 1 to 1000")


def mount_dashboard(
    app: FastAPI,
    gateway: Gateway,
    admin_key_hash: str,
    *,
    admin_threads: int = 4,
    session_ttl_seconds: int | float = DEFAULT_SESSION_TTL,
    secure_cookie: str | bool = "auto",
    feed_entries: int = DEFAULT_FEED_ENTRIES,
    max_sessions: int = DEFAULT_MAX_SESSIONS,
    clock: Callable[[], float] = time.time,
) -> Sessions:
    """Add the dashboard routes to `app`. Returns the session table (for tests).

    `admin_key_hash` is the same SHA-256 the admin API checks. Dashboard work
    runs on a worker pool of its own (`admin_threads` threads), so neither
    slow tool calls nor a busy dashboard delay the other admin endpoints.
    """
    if type(admin_key_hash) is not str or not _HEX64.fullmatch(admin_key_hash):
        raise ValueError("admin_key_hash must be 64 lowercase hex characters (a SHA-256)")
    if type(admin_threads) is not int or admin_threads < 1:
        raise ValueError("admin_threads must be a positive integer")
    _check_options(session_ttl_seconds, secure_cookie, feed_entries, max_sessions)
    stored = admin_key_hash.encode("ascii")
    sessions = Sessions(session_ttl_seconds, max_sessions, clock)
    assets = {name: (STATIC / name).read_bytes() for name in ASSETS}
    page = (STATIC / "dashboard.html").read_text("utf-8")
    field_options = "".join(
        f'<option value="{f}"{" selected" if f == "decision" else ""}>{f}</option>' for f in FIELDS
    )
    limiters: list[anyio.CapacityLimiter] = []

    async def on_thread(work: Callable[[], Any]) -> Any:
        if not limiters:
            limiters.append(anyio.CapacityLimiter(admin_threads))
        return await anyio.to_thread.run_sync(work, limiter=limiters[0])

    app.add_middleware(_SecurityHeaders)

    # -- helpers ------------------------------------------------------------

    def html_response(body: str, status: int = 200) -> HTMLResponse:
        return HTMLResponse(body, status_code=status)

    def refused(status: int, text: str) -> HTMLResponse:
        return html_response(f'<p class="error">{esc(text)}</p>', status)

    def current(request: Request) -> Session | None:
        return sessions.get(request.cookies.get(COOKIE))

    def same_origin(request: Request) -> bool:
        site = request.headers.get("sec-fetch-site")
        if site is not None and site != "same-origin":
            return False
        origin = request.headers.get("origin")
        if origin is None:
            return True
        host = request.headers.get("host", "")
        return origin != "null" and urlsplit(origin).netloc == host and bool(host)

    def checked(request: Request) -> Session | HTMLResponse:
        """The session of a state-changing request, or the refusal to send."""
        session = current(request)
        if session is None:
            return refused(401, "not signed in")
        if not same_origin(request):
            return refused(403, "cross-site request refused")
        values = request.headers.getlist(CSRF_HEADER)
        presented = values[0] if len(values) == 1 else ""
        if not hmac.compare_digest(
            presented.encode("utf-8", "backslashreplace"), session.csrf.encode("ascii")
        ):
            return refused(403, "missing or wrong CSRF token")
        return session

    async def json_body(request: Request) -> dict[str, Any]:
        data = strict_json(await request.body())  # ApiError(400) on anything odd
        return data if type(data) is dict else {}

    # -- pages and login ----------------------------------------------------

    @app.get(PREFIX, include_in_schema=False)
    async def dashboard_page(request: Request) -> Response:
        session = current(request)
        if session is None:
            return RedirectResponse(f"{PREFIX}/login", status_code=303)
        body = (
            page.replace("{{csrf}}", esc(session.csrf))
            .replace("{{approver}}", esc(session.approver))
            .replace("{{field_options}}", field_options)
        )
        return html_response(body)

    @app.get(f"{PREFIX}/login", include_in_schema=False)
    async def login_page() -> Response:
        return html_response(LOGIN_PAGE)

    @app.get(f"{PREFIX}/static/{{name}}", include_in_schema=False)
    async def static_file(name: str) -> Response:
        if name not in assets:
            return refused(404, "not found")
        return Response(assets[name], media_type=ASSETS[name])

    @app.post(f"{PREFIX}/login", include_in_schema=False)
    async def login(request: Request) -> Response:
        if not same_origin(request):
            return JSONResponse({"error": "cross_site"}, status_code=403)
        data = await json_body(request)
        key, approver = data.get("key"), data.get("approver")
        if set(data) != {"key", "approver"} or type(key) is not str or len(key) > MAX_KEY_CHARS:
            return JSONResponse({"error": "invalid_request"}, status_code=422)
        presented = hashlib.sha256(key.encode("utf-8", "backslashreplace")).hexdigest()
        if not hmac.compare_digest(presented.encode("ascii"), stored):
            return JSONResponse({"error": "wrong_key"}, status_code=401)
        if not valid_name(approver):
            return JSONResponse(
                {
                    "error": "invalid_approver",
                    "reason": "1 to 256 printable characters, no surrounding spaces",
                },
                status_code=422,
            )
        session_id, _ = sessions.create(approver)
        response = JSONResponse({"ok": True})
        response.set_cookie(
            COOKIE,
            session_id,
            max_age=int(math.ceil(session_ttl_seconds)),
            path=PREFIX,
            secure=secure_cookie is True or request.url.scheme == "https",
            httponly=True,
            samesite="strict",
        )
        return response

    @app.post(f"{PREFIX}/logout", include_in_schema=False)
    async def logout(request: Request) -> Response:
        session = checked(request)
        if isinstance(session, Response):
            return session
        sessions.drop(request.cookies.get(COOKIE))
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE, path=PREFIX, httponly=True, samesite="strict")
        return response

    # -- fragments ----------------------------------------------------------

    @app.get(f"{PREFIX}/fragment/feed", include_in_schema=False)
    async def feed(request: Request) -> Response:
        if current(request) is None:
            return refused(401, "not signed in")

        def work() -> str:
            lines = tail_lines(gateway.audit.path, feed_entries)
            return render_feed([parse_line(x) for x in lines])

        return html_response(await on_thread(work))

    @app.get(f"{PREFIX}/fragment/approvals", include_in_schema=False)
    async def approvals(request: Request) -> Response:
        if current(request) is None:
            return refused(401, "not signed in")

        def work() -> str:
            return render_queue(gateway.list_pending(), gateway.now())

        return html_response(await on_thread(work))

    @app.get(f"{PREFIX}/fragment/chain", include_in_schema=False)
    async def chain(request: Request) -> Response:
        if current(request) is None:
            return refused(401, "not signed in")

        def work() -> str:
            head = gateway.audit.head()
            lines = tail_lines(gateway.audit.path, CHAIN_BLOCKS)
            return _window_of(lines, max(0, head.seq + 1 - len(lines)))

        return html_response(await on_thread(work))

    @app.get(f"{PREFIX}/fragment/verify", include_in_schema=False)
    async def verify_fragment(request: Request) -> Response:
        if current(request) is None:
            return refused(401, "not signed in")

        def work() -> str:
            return render_verify(*verify_live(gateway))

        return html_response(await on_thread(work))

    # -- state-changing -----------------------------------------------------

    @app.post(f"{PREFIX}/approvals/{{approval_id}}", include_in_schema=False)
    async def decide(approval_id: str, request: Request) -> Response:
        session = checked(request)
        if isinstance(session, Response):
            return session
        data = await json_body(request)
        decision = data.get("decision")
        if set(data) != {"decision"} or decision not in ("approve", "reject"):
            return refused(422, "decision must be approve or reject")
        if not _APPROVAL_ID.fullmatch(approval_id):
            return refused(404, "no such approval")
        approver = session.approver

        def work() -> Response:
            try:
                outcome = gateway.resolve_approval(approval_id, decision, approver)
            except ApprovalError as exc:
                status = {"not_found": 404, "not_pending": 409, "expired": 410}.get(exc.code, 409)
                return refused(status, f"not decided: {exc.code}")
            if decision == "reject":
                text = f"Rejected by {approver}."
            elif outcome.status == ALLOWED:
                text = f"Approved by {approver}; the stored call ran once."
            elif outcome.status == ERROR:
                text = f"Approved by {approver}; the tool failed: {outcome.reason}"
            else:
                text = f"Approved by {approver}, but the re-check refused it: {outcome.reason}"
            seq = "" if outcome.audit_seq is None else f" Audit entry {outcome.audit_seq}."
            return html_response(f'<p class="notice">{esc(text + seq)}</p>')

        return await on_thread(work)

    @app.post(f"{PREFIX}/tamper", include_in_schema=False)
    async def tamper(request: Request) -> Response:
        session = checked(request)
        if isinstance(session, Response):
            return session
        data = await json_body(request)
        seq, field = data.get("seq"), data.get("field")
        if set(data) != {"seq", "field"} or type(seq) is not int or field not in FIELDS:
            return refused(422, "choose an entry number and one of the fields")

        def work() -> Response:
            try:
                demo = tamper_demo(gateway.audit.path, seq, field)
            except ValueError as exc:
                return refused(422, str(exc))
            real, head = verify_live(gateway)
            lines = tail_lines_range(gateway.audit.path, demo.window[0][0], len(demo.window))
            body = render_tamper(
                demo, real, head, _window_of(lines, demo.window[0][0], count_earlier=False)
            )
            return html_response(body)

        return await on_thread(work)

    return sessions


def tail_lines_range(path: Path, start: int, count: int) -> list[bytes]:
    """Lines start .. start+count-1 of the file (fewer if it is shorter)."""
    out: list[bytes] = []
    with open(path, "rb") as stream:
        for index, line in enumerate(stream):
            if index >= start + count:
                break
            if index >= start and line.endswith(b"\n"):
                out.append(line[:-1])
    return out
