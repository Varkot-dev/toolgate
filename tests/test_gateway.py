"""The gateway pipeline, through real components: Authority, Policy, AuditLog, ApprovalQueue.

Rule for every refusal test here: assert that the side effect did NOT happen
(the tool spy was not called, the budget counter did not move), not only that
a status came back.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st
from jwt import PyJWS

from toolgate.approvals import ApprovalQueue
from toolgate.audit import AuditError, AuditLog, hash_args, verify
from toolgate.capability import Capability, Grant
from toolgate.gateway import (
    INVALID_TOOL,
    MAX_REASON_CHARS,
    TRUNCATED,
    AuditUnavailable,
    CallOutcome,
    Gateway,
    bounded,
    loggable_tool,
    token_fingerprint,
)
from toolgate.policy import Policy
from toolgate.store import MemoryStore
from toolgate.tokens import Authority, EscalationError, TokenError

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
T0 = 1_800_000_000

POLICY = """
version: 1
rules:
  - id: deny-delete
    effect: deny
    tools: ["delete_file"]
    reason: Agents never delete files.
  - id: approve-external-email
    effect: approve
    tools: ["send_email"]
    unless:
      to: {glob: "*@example.com"}
    reason: External mail needs a person.
  - id: allow-email
    effect: allow
    tools: ["send_email"]
  - id: allow-plain
    effect: allow
    tools: ["read_file", "big", "boom", "aecho", "weird", "ghost", "nan"]
"""

# Capability indices in the root grant, used to read the budget ledger.
READ, SEND, DELETE = 0, 1, 2
CAPS: list[dict[str, Any]] = [
    {"tool": "read_file", "args": {"path": {"glob": "reports/*"}}, "max_calls": 2},
    {"tool": "send_email", "args": {"to": {"any": True}, "body": {"any": True}}, "max_calls": 1},
    {"tool": "delete_file", "args": {"path": {"any": True}}, "max_calls": 5},
    {"tool": "big", "args": {}},
    {"tool": "boom", "args": {}},
    {"tool": "aecho", "args": {"x": {"any": True}}},
    {"tool": "weird", "args": {}},
    {"tool": "ghost", "args": {}},
    {"tool": "nan", "args": {}},
]


class Clock:
    def __init__(self, now: float = T0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class Spy:
    """A tool that records every call it receives."""

    def __init__(self, result: Any = "done") -> None:
        self.calls: list[dict[str, Any]] = []
        self.result = result
        self._lock = threading.Lock()

    def __call__(self, **kwargs: Any) -> Any:
        with self._lock:
            self.calls.append(kwargs)
        return self.result


class FlakyAudit(AuditLog):
    """A real AuditLog whose append can be made to fail."""

    fail = False

    def append(self, **fields: Any) -> Any:
        if self.fail:
            raise AuditError("disk full (injected)")
        return super().append(**fields)


class Env:
    def __init__(self, tmp_path: Path, **queue_options: Any) -> None:
        self.clock = Clock()
        self.store = MemoryStore()
        self.authority = Authority(
            KEY, "https://gw.test", "gw", self.store, clock=self.clock, max_ttl=900
        )
        self.audit_path = tmp_path / "audit.jsonl"
        self.audit = FlakyAudit(self.audit_path)
        self.queue = ApprovalQueue(**queue_options)
        self.spies = {
            name: Spy() for name in ("read_file", "send_email", "delete_file", "aecho_sync")
        }

        def boom() -> None:
            self.spies["read_file"].calls.append({"boom": True})
            raise RuntimeError("x" * 10_000)

        async def aecho(x: Any) -> Any:
            await asyncio.sleep(0)
            self.spies["aecho_sync"].calls.append({"x": x})
            return {"x": x}

        self.tools = {
            "read_file": self.spies["read_file"],
            "send_email": self.spies["send_email"],
            "delete_file": self.spies["delete_file"],
            "big": lambda: "A" * 70_000,
            "boom": boom,
            "aecho": aecho,
            "weird": lambda: object(),
            "nan": lambda: float("nan"),
        }
        self.gateway = Gateway(
            self.authority,
            Policy.from_yaml(POLICY),
            self.audit,
            self.queue,
            self.tools,
            clock=self.clock,
        )

    def mint(self, caps: list[dict[str, Any]] | None = None, ttl: float = 600) -> str:
        grant = Grant(tuple(Capability.from_dict(c) for c in (caps or CAPS)), self.clock.now + ttl)
        return self.authority.mint("user:alice", grant, "agent:orchestrator", ttl)

    def jti(self, token: str) -> str:
        return json.loads(_b64(token.split(".")[1]))["jti"]

    def used(self, token: str, index: int) -> int:
        usage = self.store.usage(self.jti(token), index)
        assert usage is not None
        return usage[0]

    def entries(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.audit_path.read_text().splitlines()]

    def total_tool_calls(self) -> int:
        return sum(len(s.calls) for s in self.spies.values())

    def rebuild(self, tools: dict[str, Any] | None = None, **options: Any) -> Gateway:
        """Replace the gateway with one over the same parts, with other tools or limits."""
        self.tools = {**self.tools, **(tools or {})}
        self.gateway = Gateway(
            self.authority,
            self.gateway.policy,
            self.audit,
            self.queue,
            self.tools,
            clock=self.clock,
            **options,
        )
        return self.gateway

    def child(self, parent: str, caps: list[dict[str, Any]], actor: str = "agent:sub") -> str:
        return self.authority.exchange(parent, caps, actor, 300)


class Blocker:
    """A tool that waits until the test lets it go, and counts who is inside."""

    def __init__(self) -> None:
        self.started = threading.Semaphore(0)
        self.release = threading.Event()
        self.calls = 0
        self._lock = threading.Lock()

    def __call__(self, **kwargs: Any) -> str:
        with self._lock:
            self.calls += 1
        self.started.release()
        assert self.release.wait(30), "the test never released the tool"
        return "finished"

    def wait_started(self, count: int = 1) -> None:
        for _ in range(count):
            assert self.started.acquire(timeout=10), "the tool did not start"


def wait_until(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + 10
    while not condition():
        assert time.monotonic() < deadline, "condition never became true"
        time.sleep(0.001)


def _b64(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


# --------------------------------------------------------------------------- allow


def test_allowed_call_runs_once_charges_once_and_logs_once(env: Env) -> None:
    token = env.mint()
    outcome = env.gateway.handle_call(token, "read_file", {"path": "reports/q3.txt"})
    assert outcome == CallOutcome(
        "allowed", "ok", rule="allow-plain", result="done", audit_seq=0, stage="policy"
    )
    assert env.spies["read_file"].calls == [{"path": "reports/q3.txt"}]
    assert env.used(token, READ) == 1
    (entry,) = env.entries()
    assert entry["decision"] == "allow"
    assert entry["rule"] == "allow-plain"
    assert entry["jti"] == env.jti(token)
    assert entry["actors"] == ["agent:orchestrator"]
    assert entry["tool"] == "read_file"
    assert entry["args_hash"] == hash_args({"path": "reports/q3.txt"})
    assert entry["approver"] is None
    assert verify(env.audit_path).ok


def test_arguments_never_reach_the_audit_log(env: Env) -> None:
    token = env.mint()
    env.gateway.handle_call(token, "send_email", {"to": "a@example.com", "body": "SECRET-BODY-1"})
    env.gateway.handle_call(token, "send_email", {"to": "x@evil.test", "body": "SECRET-BODY-2"})
    raw = env.audit_path.read_text()
    assert "SECRET-BODY" not in raw
    assert "evil.test" not in raw
    assert token not in raw and token.split(".")[2] not in raw


def test_async_tool_is_awaited(env: Env) -> None:
    token = env.mint()
    outcome = env.gateway.handle_call(token, "aecho", {"x": [1, {"k": "v"}]})
    assert outcome.status == "allowed"
    assert outcome.result == {"x": [1, {"k": "v"}]}
    assert env.spies["aecho_sync"].calls == [{"x": [1, {"k": "v"}]}]


def test_async_tool_also_works_when_called_from_a_running_event_loop(env: Env) -> None:
    token = env.mint()

    async def main() -> CallOutcome:
        return env.gateway.handle_call(token, "aecho", {"x": 7})

    assert asyncio.run(main()).result == {"x": 7}


# --------------------------------------------------- what was checked is what runs


def test_tool_receives_a_private_copy_of_the_canonical_arguments(env: Env) -> None:
    token = env.mint()
    nested = {"k": [1, 2]}
    args = {"x": nested}
    outcome = env.gateway.handle_call(token, "aecho", args)
    (received,) = env.spies["aecho_sync"].calls
    assert received == {"x": {"k": [1, 2]}}
    assert received["x"] is not nested
    assert received["x"]["k"] is not nested["k"]
    # The tool can scribble on what it was given without touching the caller's data
    # or the result that was already taken.
    received["x"]["k"].append(99)
    assert nested == {"k": [1, 2]}
    assert outcome.result == {"x": {"k": [1, 2]}}
    assert env.entries()[0]["args_hash"] == hash_args({"x": {"k": [1, 2]}})


def test_dict_subclass_arguments_are_refused_not_trusted(env: Env) -> None:
    class Liar(dict):  # shows no keys to a checker that iterates, all keys to **
        def __iter__(self) -> Any:
            return iter(())

    token = env.mint()
    outcome = env.gateway.handle_call(token, "read_file", Liar(path="reports/x"))
    assert (outcome.status, outcome.stage) == ("denied", "call")
    assert env.total_tool_calls() == 0


# ----------------------------------------------------------------------- malformed


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("read_file", ["reports/x"]),
        ("read_file", None),
        ("read_file", {"path": {1, 2}}),
        ("read_file", {"path": b"reports/x"}),
        ("read_file", {1: "reports/x"}),
        ("read_file", {"path": float("nan")}),
        ("read_file", {"path": object()}),
        ("read_file", {"path": "reports/\ud800"}),
        ("", {}),
        (None, {}),
        (["read_file"], {}),
    ],
)
def test_malformed_call_is_denied_and_nothing_runs(env: Env, tool: Any, args: Any) -> None:
    token = env.mint()
    outcome = env.gateway.handle_call(token, tool, args)
    assert (outcome.status, outcome.stage, outcome.reason) == ("denied", "call", "malformed call")
    assert env.total_tool_calls() == 0
    assert env.used(token, READ) == 0
    (entry,) = env.entries()
    assert entry["decision"] == "deny"
    assert entry["rule"] == "call: malformed call"
    assert entry["jti"] == env.jti(token)  # the token did verify, so the sender is named
    assert entry["tool"] == ("read_file" if tool == "read_file" else INVALID_TOOL)
    assert entry["args_hash"] == hash_args({})


def test_deeply_nested_arguments_are_malformed(env: Env) -> None:
    token = env.mint()
    deep: Any = "x"
    for _ in range(40):
        deep = [deep]
    outcome = env.gateway.handle_call(token, "aecho", {"x": deep})
    assert (outcome.status, outcome.stage) == ("denied", "call")
    assert env.total_tool_calls() == 0


# -------------------------------------------------------------------------- tokens


def _forged(payload: dict[str, Any]) -> str:
    return PyJWS().encode(
        json.dumps(payload).encode(), OTHER_KEY, algorithm="EdDSA", headers={"typ": "JWT"}
    )


def test_token_errors_deny_with_the_code_and_run_nothing(env: Env) -> None:
    good = env.mint()
    head, payload, signature = good.split(".")
    # Change the FIRST character of the signature: every one of its six bits is
    # signature data, so the result is still canonical base64url and can only
    # fail as a bad signature. (Changing the last two characters, as this test
    # once did, sometimes left stray padding bits, which is "malformed".)
    flipped = ("B" if signature[0] == "A" else "A") + signature[1:]
    other = Authority(OTHER_KEY, "https://gw.test", "gw", MemoryStore(), clock=env.clock)
    foreign = other.mint("user:alice", Grant((), T0 + 60), "a", 60)
    expired = env.mint(ttl=10)
    revoked = env.mint()
    env.authority.revoke(env.jti(revoked))
    cases = {
        "not a token": "malformed",
        "": "malformed",
        f"{head}.{payload}.{flipped}": "bad_signature",
        foreign: "bad_signature",
        revoked: "revoked",
    }
    for token, code in cases.items():
        outcome = env.gateway.handle_call(token, "read_file", {"path": "reports/x"})
        assert (outcome.status, outcome.stage, outcome.reason) == ("denied", "token", code)
    env.clock.now += 11
    outcome = env.gateway.handle_call(expired, "read_file", {"path": "reports/x"})
    assert (outcome.status, outcome.stage, outcome.reason) == ("denied", "token", "expired")
    outcome = env.gateway.handle_call(12345, "read_file", {"path": "reports/x"})  # type: ignore[arg-type]
    assert (outcome.stage, outcome.reason) == ("token", "malformed")

    assert env.total_tool_calls() == 0
    entries = env.entries()
    assert len(entries) == len(cases) + 2
    for entry in entries:
        assert entry["decision"] == "deny"
        assert entry["rule"].startswith("token: ")
        assert entry["jti"].startswith("unverified")
        assert entry["actors"] == []
    assert verify(env.audit_path).ok


def test_unverifiable_token_cannot_write_its_own_text_into_the_log(env: Env) -> None:
    marker = "EVIL-MARKER"
    forged = _forged(
        {
            "iss": "https://gw.test",
            "aud": "gw",
            "sub": marker,
            "act": {"sub": marker},
            "iat": T0 - 1,
            "exp": T0 + 600,
            "jti": marker,
            "caps": CAPS,
            "chain": [],
            "der": [[] for _ in CAPS],
        }
    )
    tool = marker + '\n{"seq":0}' + "x" * 100
    outcome = env.gateway.handle_call(forged, tool, {marker: marker})
    assert (outcome.status, outcome.stage, outcome.reason) == ("denied", "token", "bad_signature")
    raw = env.audit_path.read_text()
    assert marker not in raw
    (entry,) = env.entries()
    assert entry["jti"] == token_fingerprint(forged)
    assert len(entry["jti"]) == len("unverified:") + 16
    assert entry["tool"] == INVALID_TOOL
    assert entry["rule"] == "token: bad_signature"
    assert len(raw) < 600
    # A name too long to be a Call at all is refused one step earlier, and
    # leaves the same kind of entry: fingerprint, placeholder, fixed text.
    outcome = env.gateway.handle_call(forged, marker * 100, {marker: marker})
    assert (outcome.status, outcome.stage) == ("denied", "call")
    raw = env.audit_path.read_text()
    assert marker not in raw and len(raw) < 1200
    last = env.entries()[1]
    assert (last["jti"], last["tool"]) == (token_fingerprint(forged), INVALID_TOOL)
    assert last["rule"] == "call: malformed call"
    assert env.total_tool_calls() == 0


def test_fingerprint_is_stable_bounded_and_not_a_plain_hash_prefix() -> None:
    assert token_fingerprint("abc") == token_fingerprint("abc")
    assert token_fingerprint("abc") != token_fingerprint("abd")
    assert token_fingerprint("abc") != "unverified:" + hashlib.sha256(b"abc").hexdigest()[:16]
    assert token_fingerprint(None) == "unverified"
    assert token_fingerprint("") == "unverified"
    assert token_fingerprint("x" * 100_000) == "unverified"
    assert token_fingerprint("\ud800").startswith("unverified:")


def test_loggable_tool_and_bounded() -> None:
    assert loggable_tool("files/read_file.v2:x-y") == "files/read_file.v2:x-y"
    for bad in ("", "a b", "a\nb", "x" * 129, "café", None, 3, "<invalid>"):
        assert loggable_tool(bad) == INVALID_TOOL
    assert bounded("abc", 3) == "abc"
    assert bounded("abcd", 3) == "abc" + TRUNCATED


# --------------------------------------------------------------------------- grant


@pytest.mark.parametrize(
    ("tool", "args", "fragment"),
    [
        ("read_file", {"path": "secrets/key"}, "fails glob"),
        ("read_file", {"path": "reports/x", "mode": "w"}, "not permitted"),
        ("read_file", {}, "missing"),
        ("write_file", {"path": "reports/x"}, "no capability"),
    ],
)
def test_grant_denial_runs_nothing_and_charges_nothing(
    env: Env, tool: str, args: dict[str, Any], fragment: str
) -> None:
    token = env.mint()
    outcome = env.gateway.handle_call(token, tool, args)
    assert (outcome.status, outcome.stage) == ("denied", "grant")
    assert fragment in outcome.reason
    assert outcome.rule is None
    assert env.total_tool_calls() == 0
    assert env.used(token, READ) == 0
    (entry,) = env.entries()
    assert entry["decision"] == "deny" and entry["rule"].startswith("grant: ")
    assert entry["jti"] == env.jti(token)


def test_long_attacker_chosen_names_are_bounded_in_reason_and_log(env: Env) -> None:
    token = env.mint()
    outcome = env.gateway.handle_call(token, "read_file", {"A" * 250: 1, "path": "reports/x"})
    assert outcome.status == "denied"
    assert len(outcome.reason) == MAX_REASON_CHARS + len(TRUNCATED)
    assert outcome.reason.endswith(TRUNCATED)
    (entry,) = env.entries()
    assert len(entry["rule"]) < MAX_REASON_CHARS + 40
    outcome = env.gateway.handle_call(token, "T" * 250, {})
    assert outcome.status == "denied"
    assert env.entries()[1]["tool"] == INVALID_TOOL
    assert env.audit_path.stat().st_size < 2000


def test_granted_but_unregistered_tool_is_denied(env: Env) -> None:
    token = env.mint()
    outcome = env.gateway.handle_call(token, "ghost", {})
    assert (outcome.status, outcome.stage, outcome.reason) == ("denied", "tool", "unknown tool")
    assert env.used(token, 7) == 0
    assert env.entries()[0]["rule"] == "tool: unknown tool"


# -------------------------------------------------------------------------- policy


def test_policy_deny_runs_nothing_and_charges_nothing(env: Env) -> None:
    token = env.mint()
    outcome = env.gateway.handle_call(token, "delete_file", {"path": "reports/x"})
    assert (outcome.status, outcome.stage, outcome.rule) == ("denied", "policy", "deny-delete")
    assert outcome.reason == "Agents never delete files."
    assert env.spies["delete_file"].calls == []
    assert env.used(token, DELETE) == 0
    (entry,) = env.entries()
    assert (entry["decision"], entry["rule"]) == ("deny", "deny-delete")


def test_default_deny_when_no_rule_matches(env: Env) -> None:
    env.gateway.set_policy(Policy.from_yaml("version: 1\nrules: []\n"))
    token = env.mint()
    outcome = env.gateway.handle_call(token, "read_file", {"path": "reports/x"})
    assert (outcome.status, outcome.stage, outcome.rule) == ("denied", "policy", None)
    assert env.total_tool_calls() == 0
    assert env.used(token, READ) == 0
    assert env.entries()[0]["rule"].startswith("policy: no rule matched")


def test_pending_call_runs_nothing_and_charges_nothing(env: Env) -> None:
    token = env.mint()
    outcome = env.gateway.handle_call(token, "send_email", {"to": "x@evil.test", "body": "hi"})
    assert (outcome.status, outcome.rule) == ("pending", "approve-external-email")
    assert outcome.approval_id and outcome.result is None
    assert env.spies["send_email"].calls == []
    assert env.used(token, SEND) == 0
    (entry,) = env.entries()
    assert (entry["decision"], entry["rule"]) == ("approve", "approve-external-email")
    assert entry["approver"] is None
    assert outcome.audit_seq == 0
    assert len(env.queue.pending(env.clock.now)) == 1


def test_policy_reload_takes_effect_on_the_next_call(env: Env) -> None:
    token = env.mint()
    assert env.gateway.handle_call(token, "read_file", {"path": "reports/a"}).status == "allowed"
    env.gateway.set_policy(
        Policy.from_yaml('version: 1\nrules:\n  - {id: stop, effect: deny, tools: ["*"]}\n')
    )
    outcome = env.gateway.handle_call(token, "read_file", {"path": "reports/b"})
    assert (outcome.status, outcome.rule) == ("denied", "stop")
    assert len(env.spies["read_file"].calls) == 1
    assert env.used(token, READ) == 1
    with pytest.raises(ValueError):
        env.gateway.set_policy("version: 1")  # type: ignore[arg-type]


# -------------------------------------------------------------------------- budget


def test_budget_is_charged_per_allowed_call_and_then_refuses(env: Env) -> None:
    token = env.mint()
    for name in ("a", "b"):
        assert (
            env.gateway.handle_call(token, "read_file", {"path": f"reports/{name}"}).status
            == "allowed"
        )
    outcome = env.gateway.handle_call(token, "read_file", {"path": "reports/c"})
    assert (outcome.status, outcome.stage, outcome.reason) == (
        "denied",
        "budget",
        "budget exhausted",
    )
    assert len(env.spies["read_file"].calls) == 2
    assert env.used(token, READ) == 2
    assert [e["decision"] for e in env.entries()] == ["allow", "allow", "deny"]


def test_child_token_calls_charge_the_parent_too(env: Env) -> None:
    parent = env.mint()
    child = env.authority.exchange(
        parent,
        [{"tool": "read_file", "args": {"path": {"glob": "reports/q3/*"}}, "max_calls": 2}],
        "agent:sub",
        60,
    )
    assert env.gateway.handle_call(child, "read_file", {"path": "reports/q3/a"}).status == "allowed"
    assert env.gateway.handle_call(child, "read_file", {"path": "reports/x"}).status == "denied"
    assert env.used(parent, READ) == 1 and env.used(child, 0) == 1
    assert env.entries()[0]["actors"] == ["agent:sub", "agent:orchestrator"]


def test_concurrent_calls_cannot_overspend_the_budget(env: Env) -> None:
    token = env.mint()
    barrier = threading.Barrier(16)
    outcomes: list[CallOutcome] = []

    def work(i: int) -> None:
        barrier.wait()
        outcomes.append(env.gateway.handle_call(token, "read_file", {"path": f"reports/{i}"}))

    threads = [threading.Thread(target=work, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(o.status for o in outcomes).count("allowed") == 2
    assert len(env.spies["read_file"].calls) == 2
    assert env.used(token, READ) == 2
    result = verify(env.audit_path)
    assert result.ok and result.entries == 16


# --------------------------------------------------------------------------- audit


def test_audit_failure_blocks_execution(env: Env) -> None:
    token = env.mint()
    env.audit.fail = True
    outcome = env.gateway.handle_call(token, "read_file", {"path": "reports/x"})
    assert (outcome.status, outcome.stage) == ("denied", "audit")
    assert outcome.audit_seq is None
    assert env.spies["read_file"].calls == []  # the point: no entry, no execution
    # The budget was charged in step d and is given back: nothing ran.
    assert env.used(token, READ) == 0
    assert env.entries() == []


def test_audit_failure_queues_nothing(env: Env) -> None:
    token = env.mint()
    env.audit.fail = True
    outcome = env.gateway.handle_call(token, "send_email", {"to": "x@evil.test", "body": "hi"})
    assert (outcome.status, outcome.stage) == ("denied", "audit")
    assert outcome.approval_id is None
    assert env.queue.pending(env.clock.now) == []
    assert env.total_tool_calls() == 0


def test_audit_failure_on_a_denial_still_denies(env: Env) -> None:
    token = env.mint()
    env.audit.fail = True
    outcome = env.gateway.handle_call(token, "delete_file", {"path": "x"})
    assert (outcome.status, outcome.audit_seq) == ("denied", None)
    assert env.total_tool_calls() == 0


# --------------------------------------------------------------------- tool output


def test_tool_exception_is_an_error_with_a_bounded_message(env: Env) -> None:
    token = env.mint()
    outcome = env.gateway.handle_call(token, "boom", {})
    assert (outcome.status, outcome.stage) == ("error", "tool")
    assert outcome.reason.startswith("tool raised RuntimeError: xxx")
    assert outcome.reason.endswith(TRUNCATED)
    assert len(outcome.reason) == env.gateway.max_error_chars + len(TRUNCATED)
    assert outcome.result is None
    # It ran (once), was allowed and logged before it ran; the failure adds no entry.
    assert env.spies["read_file"].calls == [{"boom": True}]
    assert [e["decision"] for e in env.entries()] == ["allow"]
    assert outcome.audit_seq == 0


def test_oversized_tool_output_is_withheld_not_truncated(env: Env) -> None:
    token = env.mint()
    outcome = env.gateway.handle_call(token, "big", {})
    assert (outcome.status, outcome.stage) == ("error", "tool")
    assert "over the limit of 65536" in outcome.reason and "withheld" in outcome.reason
    assert outcome.result is None
    assert [e["decision"] for e in env.entries()] == ["allow"]


@pytest.mark.parametrize("tool", ["weird", "nan"])
def test_non_json_tool_output_is_an_error(env: Env, tool: str) -> None:
    token = env.mint()
    outcome = env.gateway.handle_call(token, tool, {})
    assert (outcome.status, outcome.stage) == ("error", "tool")
    assert "not plain JSON" in outcome.reason
    assert outcome.result is None


def test_output_exactly_at_the_limit_passes(tmp_path: Path) -> None:
    env = Env(tmp_path)
    gateway = Gateway(
        env.authority,
        env.gateway.policy,
        env.audit,
        env.queue,
        {"big": lambda: "A" * 98, "read_file": lambda path: "A" * 99},
        clock=env.clock,
        max_output_bytes=100,
    )
    token = env.mint()
    assert gateway.handle_call(token, "big", {}).result == "A" * 98  # 98 + two quotes
    assert gateway.handle_call(token, "read_file", {"path": "reports/x"}).status == "error"


# -------------------------------------------------------------------- construction


def test_registry_is_validated(env: Env) -> None:
    def build(tools: dict[str, Any], **options: Any) -> Gateway:
        return Gateway(
            env.authority,
            env.gateway.policy,
            env.audit,
            env.queue,
            tools,
            clock=env.clock,
            **options,
        )

    for name in ("", "bad name", "x" * 129, "<invalid>", "new\nline"):
        with pytest.raises(ValueError):
            build({name: lambda: 1})
    with pytest.raises(ValueError):
        build({"ok": "not callable"})
    with pytest.raises(ValueError):
        build({}, max_output_bytes=0)
    with pytest.raises(ValueError):
        Gateway(env.authority, object(), env.audit, env.queue, {})  # type: ignore[arg-type]
    assert env.gateway.tool_names == tuple(sorted(env.tools))


# ------------------------------------------------------ one entry per outcome, always


def test_every_outcome_writes_exactly_one_entry_and_the_log_verifies(env: Env) -> None:
    token = env.mint()
    script: list[tuple[Any, str, Any, str, str]] = [
        (token, "read_file", {"path": "reports/a"}, "allowed", "allow"),
        (token, "read_file", {"path": "nope"}, "denied", "deny"),
        (token, "delete_file", {"path": "x"}, "denied", "deny"),
        (token, "send_email", {"to": "x@evil.test", "body": "b"}, "pending", "approve"),
        (token, "send_email", {"to": "x@evil.test", "body": "b"}, "pending", "approve"),
        (token, "send_email", {"to": "a@example.com", "body": "b"}, "allowed", "allow"),
        (token, "send_email", {"to": "b@example.com", "body": "b"}, "denied", "deny"),
        (token, "boom", {}, "error", "allow"),
        (token, "big", {}, "error", "allow"),
        (token, "ghost", {}, "denied", "deny"),
        (token, "read_file", "not a dict", "denied", "deny"),
        ("garbage", "read_file", {"path": "reports/a"}, "denied", "deny"),
        ("garbage", "", None, "denied", "deny"),
    ]
    for count, (tok, tool, args, status, decision) in enumerate(script, start=1):
        outcome = env.gateway.handle_call(tok, tool, args)
        entries = env.entries()
        assert outcome.status == status, (tool, args, outcome)
        assert len(entries) == count
        assert entries[-1]["decision"] == decision
        assert outcome.audit_seq == count - 1
    result = verify(env.audit_path, env.audit.head())
    assert result.ok and result.entries == len(script)
    # The two identical pending requests share one approval record.
    assert len(env.queue.pending(env.clock.now)) == 1


# ====================================================================================
# Findings from the security reviews. Each test below failed before its fix.
# ====================================================================================

# ------------------------------------------- 1. no caller-chosen text in the audit log

HOSTILE_TOOL = '<img src=x onerror=alert(1)>","decision":"allow'
HOSTILE_ARG = "password=hunter2&token=s3cr3t-value"


def test_grant_denial_logs_a_code_and_never_the_callers_names(env: Env) -> None:
    token = env.mint()
    cases = [
        (HOSTILE_TOOL, {}, "no_capability", "grant: no_capability"),
        ("read_file", {"path": "reports/x", HOSTILE_ARG: 1}, "argument_not_permitted", None),
        ("read_file", {}, "argument_missing", "grant: argument_missing"),
        (
            "read_file",
            {"path": HOSTILE_ARG},
            "constraint_failed",
            "grant: constraint_failed (glob)",
        ),
    ]
    for tool, args, code, rule in cases:
        outcome = env.gateway.handle_call(token, tool, args)
        assert (outcome.status, outcome.stage, outcome.code) == ("denied", "grant", code)
        assert env.entries()[-1]["rule"] == (rule or f"grant: {code}")
    # The caller still gets the readable reason: it is their own input.
    assert (
        "password=hunter2" in env.gateway.handle_call(token, "read_file", {HOSTILE_ARG: 1}).reason
    )
    raw = env.audit_path.read_text()
    for needle in (HOSTILE_ARG, "hunter2", "onerror", "<img"):
        assert needle not in raw
    assert all(e["tool"] in ("read_file", INVALID_TOOL) for e in env.entries())
    assert env.total_tool_calls() == 0 and env.used(token, READ) == 0


_SAFE_LOOKING = st.text(alphabet="abcdef0189_.:/-=<>\"' &", min_size=9, max_size=40)
_ANY_TEXT = st.text(min_size=9, max_size=40)
_NAMES = st.one_of(_SAFE_LOOKING, _ANY_TEXT)
_TOOLS = st.one_of(st.sampled_from(["read_file", "send_email", "delete_file", "ghost"]), _NAMES)
_VALUES = st.one_of(_NAMES, st.integers(-5, 5), st.booleans(), st.lists(_NAMES, max_size=2))
_ARGS = st.dictionaries(
    st.one_of(st.sampled_from(["path", "to", "body"]), _NAMES), _VALUES, max_size=4
)


_REPO = Path(__file__).resolve().parent.parent
_OWN_TEXT = "\n".join(
    p.read_text(encoding="utf-8")
    for p in [
        *sorted((_REPO / "src" / "toolgate").rglob("*.py")),
        Path(__file__),
        *sorted((_REPO / "config").glob("*.yaml")),
    ]
)


def _strings(value: Any) -> list[str]:
    if type(value) is str:
        return [value]
    if type(value) is dict:
        return [s for k, v in value.items() for s in (k, *_strings(v))]
    if type(value) is list:
        return [s for v in value for s in _strings(v)]
    return []


@settings(max_examples=80, deadline=None)
@given(tool=_TOOLS, args=_ARGS, junk_token=st.one_of(st.none(), _NAMES), via_child=st.booleans())
def test_no_caller_supplied_string_reaches_the_audit_log(
    tool: str, args: dict[str, Any], junk_token: str | None, via_child: bool
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        env = Env(Path(directory))
        try:
            token = env.mint()
            if via_child:
                token = env.child(token, CAPS[:3])
            env.gateway.handle_call(token if junk_token is None else junk_token, tool, args)
            # An exchange is caller input too: requested tool and argument names.
            requested = [{"tool": tool, "args": {name: {"any": True} for name in args}}]
            with contextlib.suppress(TokenError, EscalationError, ValueError, TypeError):
                env.gateway.exchange_token(token, requested, "agent:x", 60)
            supplied = {s for s in [tool, junk_token or "", *_strings(args)] if len(s) > 8}
            if loggable_tool(tool) == tool:
                supplied.discard(tool)  # the one thing a caller may put in the log
            raw = env.audit_path.read_text()
            assert raw.count("\n") >= 2  # every attempt above left its entry
            entries = env.entries()
            # Text the code base and its configuration already contain (field names,
            # reason codes, the "unverified:" prefix, rule ids, test actor names) is
            # written by the gateway itself. A caller who happens to send "args_hash"
            # has not smuggled anything in. Hypothesis draws such literals from the
            # source on purpose, so they must be excluded, not avoided.
            supplied = {s for s in supplied if s not in _OWN_TEXT}
            logged = [s for entry in entries for value in entry.values() for s in _strings(value)]
            for text in supplied:
                assert text not in raw, text
                assert not any(text in field for field in logged), text
        finally:
            env.audit.close()


def test_token_lifecycle_is_audited_without_capability_contents(env: Env) -> None:
    grant = Grant(tuple(Capability.from_dict(c) for c in CAPS[:2]), T0 + 600)
    token, minted = env.gateway.mint_token("user:alice", grant, "agent:orchestrator", 600)
    narrower = [{"tool": "read_file", "args": {"path": {"glob": "reports/q3/*"}}, "max_calls": 1}]
    child, exchanged = env.gateway.exchange_token(token, narrower, "agent:sub", 60)
    wider = [{"tool": "read_file", "args": {"path": {"glob": "*"}}}]
    with pytest.raises(EscalationError):
        env.gateway.exchange_token(token, wider, "agent:sub", 60)
    with pytest.raises(TokenError):
        env.gateway.exchange_token("junk-token-" + "z" * 20, narrower, "agent:sub", 60)
    with pytest.raises(ValueError):
        env.gateway.exchange_token(token, [{"tool": "read_file", "surprise": 1}], "agent:sub", 60)
    assert env.gateway.revoke_token(minted.jti) is not None
    assert env.gateway.revoke_token("line\nbreak") is not None  # logged as a hash of itself

    rows = [(e["tool"], e["decision"], e["rule"], e["jti"]) for e in env.entries()]
    assert rows[:5] == [
        ("token:mint", "allow", "token: minted by admin", minted.jti),
        ("token:exchange", "allow", f"token: exchanged from {minted.jti}", exchanged.jti),
        ("token:exchange", "deny", "exchange: escalation", minted.jti),
        ("token:exchange", "deny", "exchange: malformed", rows[3][3]),
        ("token:exchange", "deny", "exchange: invalid_request", minted.jti),
    ]
    assert rows[3][3].startswith("unverified:")
    assert rows[5] == ("token:revoke", "allow", "token: revoked by admin", minted.jti)
    assert rows[6][3].startswith("sha256:") and "\n" not in rows[6][3]
    entries = env.entries()
    assert entries[1]["actors"] == ["agent:sub", "agent:orchestrator"]
    # Only a hash of the capabilities is written, and it can be recomputed from the token.
    assert entries[0]["args_hash"] == hash_args(
        {"capabilities": [c.to_dict() for c in minted.grant.capabilities]}
    )
    assert entries[1]["args_hash"] != entries[0]["args_hash"]
    raw = env.audit_path.read_text()
    for content in ("reports/", "glob", "max_calls", "surprise", "junk-token"):
        assert content not in raw
    with pytest.raises(TokenError):  # the revocation was real
        env.authority.verify(child)
    assert verify(env.audit_path).ok


def test_a_token_that_cannot_be_audited_is_not_issued(env: Env) -> None:
    grant = Grant(tuple(Capability.from_dict(c) for c in CAPS[:2]), T0 + 600)
    parent, _ = env.gateway.mint_token("user:alice", grant, "agent:orchestrator", 600)
    issued: list[str] = []
    real_mint, real_exchange = env.authority.mint, env.authority.exchange

    def spy_mint(*a: Any, **k: Any) -> str:
        issued.append(real_mint(*a, **k))
        return issued[-1]

    def spy_exchange(*a: Any, **k: Any) -> str:
        issued.append(real_exchange(*a, **k))
        return issued[-1]

    env.authority.mint, env.authority.exchange = spy_mint, spy_exchange  # type: ignore[method-assign]
    env.audit.fail = True
    with pytest.raises(AuditUnavailable):
        env.gateway.mint_token("user:alice", grant, "agent:orchestrator", 600)
    with pytest.raises(AuditUnavailable):
        env.gateway.exchange_token(parent, [CAPS[0]], "agent:sub", 60)
    # Revocation is never held back by the log; the caller is told it was not recorded.
    assert env.gateway.revoke_token("some-other-token") is None
    env.audit.fail = False
    assert len(issued) == 2
    for token in issued:  # signed, but revoked again before anyone could hold it
        with pytest.raises(TokenError) as info:
            env.authority.verify(token)
        assert info.value.code == "revoked"
    assert env.store.any_revoked(["some-other-token"])
    assert [e["tool"] for e in env.entries()] == ["token:mint"]


# ---------------------------------------------- 3. budget and the order of operations


def test_a_charged_call_that_never_ran_is_refunded(env: Env) -> None:
    token = env.mint()
    env.audit.fail = True
    for _ in range(5):  # an audit outage must not drain the budget of 2
        outcome = env.gateway.handle_call(token, "read_file", {"path": "reports/x"})
        assert (outcome.status, outcome.stage) == ("denied", "audit")
        assert env.used(token, READ) == 0
    env.audit.fail = False
    assert env.gateway.handle_call(token, "read_file", {"path": "reports/x"}).status == "allowed"
    assert env.gateway.handle_call(token, "read_file", {"path": "reports/x"}).status == "allowed"
    assert env.used(token, READ) == 2
    assert len(env.spies["read_file"].calls) == 2


def test_an_audit_clock_fault_after_the_charge_is_refunded(tmp_path: Path) -> None:
    env = Env(tmp_path)
    ticks = iter([10, 5, 30])  # the second reading goes backwards: that append is refused
    env.audit.close()
    env.audit = FlakyAudit(env.audit_path, clock=lambda: next(ticks))
    env.rebuild()
    parent = env.mint()
    child = env.child(parent, [CAPS[READ]])
    assert env.gateway.handle_call(child, "read_file", {"path": "reports/a"}).status == "allowed"
    refused = env.gateway.handle_call(child, "read_file", {"path": "reports/b"})
    assert (refused.status, refused.stage, refused.audit_seq) == ("denied", "audit", None)
    assert env.spies["read_file"].calls == [{"path": "reports/a"}]
    # The charge for the call that did not run came back on both levels of the chain.
    assert (env.used(child, 0), env.used(parent, READ)) == (1, 1)
    assert env.gateway.handle_call(child, "read_file", {"path": "reports/c"}).status == "allowed"
    assert (env.used(child, 0), env.used(parent, READ)) == (2, 2)
    assert [e["decision"] for e in env.entries()] == ["allow", "allow"]


def test_refund_reaches_every_level_of_a_delegation_chain(env: Env) -> None:
    parent = env.mint()
    child = env.child(parent, [CAPS[READ]])
    env.audit.fail = True
    outcome = env.gateway.handle_call(child, "read_file", {"path": "reports/x"})
    assert (outcome.status, outcome.stage) == ("denied", "audit")
    assert (env.used(child, 0), env.used(parent, READ)) == (0, 0)
    assert env.total_tool_calls() == 0


def test_a_call_that_cannot_be_logged_is_refused_before_any_charge(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    charges: list[Any] = []
    real_charge = env.store.charge

    def counting(path: Any) -> Any:
        charges.append(path)
        return real_charge(path)

    monkeypatch.setattr(env.store, "charge", counting)
    seen: list[tuple[Any, ...]] = []

    def never(tool: Any, args: Any, actors: Any) -> str:
        seen.append((tool, tuple(actors)))
        return "actors take too many bytes"

    monkeypatch.setattr("toolgate.gateway.loggable", never)
    token = env.mint()
    outcome = env.gateway.handle_call(token, "read_file", {"path": "reports/x"})
    assert (outcome.status, outcome.stage) == ("denied", "audit")
    assert seen == [("read_file", ("agent:orchestrator",))]
    assert charges == []  # not charged and refunded: never charged
    assert env.used(token, READ) == 0 and env.total_tool_calls() == 0
    assert env.entries()[-1]["rule"] == "audit: unloggable"


def test_a_call_whose_tool_started_is_never_refunded(env: Env) -> None:
    token = env.mint([{"tool": "boom", "args": {}, "max_calls": 3}])
    outcome = env.gateway.handle_call(token, "boom", {})
    assert outcome.status == "error"
    assert env.spies["read_file"].calls == [{"boom": True}]  # it ran, so it stays charged
    assert env.used(token, 0) == 1


def test_a_refund_that_fails_leaves_the_budget_spent(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(path: Any) -> bool:
        raise OSError("store down")

    monkeypatch.setattr(env.store, "refund", broken)
    token = env.mint()
    env.audit.fail = True
    outcome = env.gateway.handle_call(token, "read_file", {"path": "reports/x"})
    assert (outcome.status, outcome.stage) == ("denied", "audit")  # still an outcome, no raise
    assert env.used(token, READ) == 1 and env.total_tool_calls() == 0


@pytest.mark.parametrize(
    ("after_charge", "stage", "code"),
    [(float("nan"), "unavailable", ""), (T0 + 10_000, "grant", "expired_during_authorization")],
)
def test_a_clock_fault_or_expiry_right_after_the_charge_is_refunded(
    env: Env, monkeypatch: pytest.MonkeyPatch, after_charge: float, stage: str, code: str
) -> None:
    token = env.mint()
    real_charge = env.store.charge

    def charge_then_move_clock(path: Any) -> Any:
        result = real_charge(path)
        env.clock.now = after_charge
        return result

    monkeypatch.setattr(env.store, "charge", charge_then_move_clock)
    outcome = env.gateway.handle_call(token, "read_file", {"path": "reports/x"})
    env.clock.now = T0
    assert (outcome.status, outcome.stage, outcome.code) == ("denied", stage, code)
    assert env.spies["read_file"].calls == []
    assert env.used(token, READ) == 0  # charged, not run, given back
    (entry,) = env.entries()
    assert entry["decision"] == "deny"


# ----------------------------------- 4. revocation or expiry between charge and start


class HookedAudit(FlakyAudit):
    """Runs `after_allow` once, right after an allow or approved entry was written."""

    after_allow: Callable[[], None] | None = None

    def append(self, **fields: Any) -> Any:
        entry = super().append(**fields)
        if fields["decision"] in ("allow", "approved") and self.after_allow is not None:
            hook, self.after_allow = self.after_allow, None
            hook()
        return entry


def hooked(tmp_path: Path) -> Env:
    env = Env(tmp_path)
    env.audit.close()
    env.audit = HookedAudit(env.audit_path)
    env.rebuild()
    return env


def test_revocation_landing_during_the_audit_write_stops_the_tool(tmp_path: Path) -> None:
    env = hooked(tmp_path)
    parent = env.mint()
    child = env.child(parent, [CAPS[READ]])
    env.audit.after_allow = lambda: env.authority.revoke(env.jti(parent))
    outcome = env.gateway.handle_call(child, "read_file", {"path": "reports/x"})
    assert (outcome.status, outcome.stage, outcome.reason) == ("denied", "token", "revoked")
    assert env.spies["read_file"].calls == []  # the point
    assert (env.used(child, 0), env.used(parent, READ)) == (0, 0)  # and it was refunded
    allow, deny = env.entries()
    assert (allow["decision"], deny["decision"]) == ("allow", "deny")
    assert deny["rule"] == "token: revoked; allowed at seq 0 but not run"
    assert deny["jti"] == allow["jti"] == env.jti(child)
    assert outcome.audit_seq == 1


def test_expiry_landing_during_the_audit_write_stops_the_tool(tmp_path: Path) -> None:
    env = hooked(tmp_path)
    token = env.mint(ttl=10)

    def expire() -> None:
        env.clock.now += 11

    env.audit.after_allow = expire
    outcome = env.gateway.handle_call(token, "read_file", {"path": "reports/x"})
    assert (outcome.status, outcome.stage, outcome.reason) == ("denied", "token", "expired")
    assert env.spies["read_file"].calls == []
    assert env.used(token, READ) == 0
    assert env.entries()[-1]["rule"] == "token: expired; allowed at seq 0 but not run"


# ------------------------------------------------ 5. every path returns a CallOutcome


class Hostile(dict):  # type: ignore[type-arg]
    """A mapping whose every access blows up with something that is not a ValueError."""

    def keys(self) -> Any:
        raise RuntimeError("boom from keys")

    def __iter__(self) -> Any:
        raise KeyError("boom from iter")

    def __getitem__(self, key: Any) -> Any:
        raise RuntimeError("boom from getitem")

    def __len__(self) -> int:
        return 1


@pytest.mark.parametrize("valid_token", [True, False])
def test_a_hostile_mapping_is_a_denied_call_not_an_exception(env: Env, valid_token: bool) -> None:
    token = env.mint() if valid_token else "junk"
    outcome = env.gateway.handle_call(token, "read_file", MappingProxyType(Hostile()))
    assert type(outcome) is CallOutcome
    assert (outcome.status, outcome.stage, outcome.reason) == ("denied", "call", "malformed call")
    assert outcome.authenticated is valid_token
    (entry,) = env.entries()
    assert (entry["decision"], entry["rule"]) == ("deny", "call: malformed call")
    assert env.total_tool_calls() == 0
    if valid_token:
        assert env.used(token, READ) == 0


def test_a_tool_removed_from_the_registry_mid_call_cannot_raise_after_the_charge(
    tmp_path: Path,
) -> None:
    env = hooked(tmp_path)
    token = env.mint()
    env.audit.after_allow = lambda: env.gateway._tools.pop("read_file")
    outcome = env.gateway.handle_call(token, "read_file", {"path": "reports/x"})
    # The callable was taken before the charge, so the call that was checked, charged
    # and logged is the call that ran.
    assert type(outcome) is CallOutcome and outcome.status == "allowed"
    assert env.spies["read_file"].calls == [{"path": "reports/x"}]
    assert env.used(token, READ) == 1
    assert [e["decision"] for e in env.entries()] == ["allow"]
    later = env.gateway.handle_call(token, "read_file", {"path": "reports/x"})
    assert (later.status, later.stage) == ("denied", "tool")
    assert env.used(token, READ) == 1


def test_an_unexpected_failure_inside_the_pipeline_is_a_refusal_with_an_entry(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = env.mint()

    def broken(*a: Any, **k: Any) -> Any:
        raise RuntimeError("bug in the queue lookup")

    monkeypatch.setattr(env.gateway, "_park", broken)
    outcome = env.gateway.handle_call(token, "send_email", {"to": "x@evil.test", "body": "b"})
    assert (outcome.status, outcome.stage) == ("denied", "unavailable")
    assert env.entries()[-1]["rule"] == "unavailable: internal error"
    assert env.total_tool_calls() == 0 and env.used(token, SEND) == 0


# ------------------------------------------------------ 8. in-flight cap and timeouts


def test_in_flight_calls_are_capped_per_root_token(env: Env) -> None:
    blocker = Blocker()
    env.rebuild({"ghost": blocker}, max_in_flight_per_root=2)
    ghost = {"tool": "ghost", "args": {}, "max_calls": 10}
    root = env.mint([ghost, CAPS[READ]])
    children = [env.child(root, [ghost], f"agent:{i}") for i in range(3)]
    other_root = env.mint([ghost, CAPS[READ]])
    results: list[CallOutcome] = []
    threads = [
        threading.Thread(target=lambda t=t: results.append(env.gateway.handle_call(t, "ghost", {})))
        for t in children[:2]
    ]
    try:
        for thread in threads:
            thread.start()
        blocker.wait_started(2)
        assert env.gateway.in_flight(env.jti(root)) == 2
        # A third child of the same root, and the root itself, are over the cap.
        for token in (children[2], root):
            refused = env.gateway.handle_call(token, "ghost", {})
            assert (refused.status, refused.stage, refused.code) == (
                "denied",
                "limit",
                "in_flight_limit",
            )
        assert blocker.calls == 2  # the refused calls never reached the tool
        assert env.used(children[2], 0) == 0 and env.used(root, 0) == 2  # nor the budget
        assert env.entries()[-1]["rule"] == "limit: in_flight"
        # A different root is not affected.
        assert env.gateway.handle_call(other_root, "read_file", {"path": "reports/x"}).allowed
    finally:
        blocker.release.set()
        for thread in threads:
            thread.join(10)
    assert [r.status for r in results] == ["allowed", "allowed"]
    assert env.gateway.in_flight(env.jti(root)) == 0
    assert env.gateway.handle_call(children[2], "ghost", {}).status == "allowed"


def test_a_refused_call_gives_its_in_flight_slot_back(env: Env) -> None:
    env.rebuild(max_in_flight_per_root=1)
    token = env.mint()
    env.audit.fail = True
    assert env.gateway.handle_call(token, "read_file", {"path": "reports/x"}).stage == "audit"
    env.audit.fail = False
    for _ in range(2):
        assert env.gateway.handle_call(token, "read_file", {"path": "reports/x"}).allowed
    assert env.gateway.handle_call(token, "read_file", {"path": "reports/x"}).stage == "budget"
    assert env.gateway.handle_call(token, "boom", {}).status == "error"
    assert env.gateway.in_flight(env.jti(token)) == 0


def test_a_tool_that_does_not_finish_in_time_is_an_error_and_stays_charged(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    blocker = Blocker()
    env.rebuild({"ghost": blocker}, tool_timeout=0.05, max_in_flight_per_root=1)
    token = env.mint([{"tool": "ghost", "args": {}, "max_calls": 5}])
    try:
        with caplog.at_level(logging.ERROR, logger="toolgate.gateway"):
            outcome = env.gateway.handle_call(token, "ghost", {})
        assert (outcome.status, outcome.stage, outcome.code) == ("error", "tool", "tool_timeout")
        assert "may still complete in the background" in outcome.reason
        assert outcome.result is None
        assert blocker.calls == 1
        # Honest accounting: it started, so it is charged, and it still holds its slot.
        assert env.used(token, 0) == 1
        assert env.gateway.in_flight(env.jti(token)) == 1
        assert env.gateway.handle_call(token, "ghost", {}).code == "in_flight_limit"
        assert [e["decision"] for e in env.entries()] == ["allow", "deny"]
        assert any("did not finish" in r.getMessage() for r in caplog.records)
    finally:
        blocker.release.set()
    wait_until(lambda: env.gateway.in_flight(env.jti(token)) == 0)
    assert blocker.calls == 1


def test_tools_run_normally_under_a_timeout(env: Env) -> None:
    env.rebuild(tool_timeout=30)
    token = env.mint()
    assert env.gateway.handle_call(token, "read_file", {"path": "reports/x"}).result == "done"
    assert env.gateway.handle_call(token, "aecho", {"x": 3}).result == {"x": 3}
    assert env.gateway.handle_call(token, "boom", {}).status == "error"
    assert env.gateway.handle_call(token, "big", {}).status == "error"
    assert env.gateway.in_flight(env.jti(token)) == 0


def test_limits_are_validated(env: Env) -> None:
    for options in (
        {"max_in_flight_per_root": 0},
        {"max_in_flight_per_root": 1.5},
        {"tool_timeout": 0},
        {"tool_timeout": float("inf")},
        {"tool_error_detail": "no"},
        {"unverified_audit_rate": 0},
        {"unverified_audit_burst": 0},
    ):
        with pytest.raises(ValueError):
            env.rebuild(**options)


# ------------------------------------------------- 9. unverified tokens and the log


def test_audit_entries_for_unverified_tokens_are_rate_limited_and_summarised(env: Env) -> None:
    env.rebuild(unverified_audit_rate=2, unverified_audit_burst=3)
    good = env.mint()

    def junk(i: int) -> CallOutcome:
        outcome = env.gateway.handle_call(f"junk-{i}", "read_file", {"path": "reports/x"})
        assert (outcome.status, outcome.stage, outcome.reason) == ("denied", "token", "malformed")
        assert outcome.authenticated is False
        return outcome

    assert [junk(i).audit_seq for i in range(3)] == [0, 1, 2]  # the burst is logged
    assert [junk(i).audit_seq for i in range(3, 10)] == [None] * 7  # refused, not logged
    assert len(env.entries()) == 3 and env.gateway.suppressed_unverified() == 7
    # A verified token is never limited: its decisions are all on record.
    for path in ("reports/a", "secrets/b"):
        assert env.gateway.handle_call(good, "read_file", {"path": path}).audit_seq is not None
    assert len(env.entries()) == 5 and env.gateway.suppressed_unverified() == 7

    env.clock.now += 1  # two entries' worth of room: the summary, then one attempt
    assert junk(10).audit_seq == 6
    assert junk(11).audit_seq is None
    summary = env.entries()[5]
    assert (summary["tool"], summary["jti"], summary["decision"]) == (
        "audit:summary",
        "unverified",
        "deny",
    )
    assert summary["rule"] == "unverified: 7 attempts suppressed"
    assert env.gateway.suppressed_unverified() == 1

    # With no clock movement nothing more is written, however many attempts arrive.
    for i in range(50):
        junk(100 + i)
    assert len(env.entries()) == 7 and env.gateway.suppressed_unverified() == 51
    # A summary that cannot be written keeps its count; shutdown writes it.
    env.audit.fail = True
    env.gateway.flush()
    assert env.gateway.suppressed_unverified() == 51
    env.audit.fail = False
    env.gateway.flush()
    assert env.entries()[-1]["rule"] == "unverified: 51 attempts suppressed"
    assert env.gateway.suppressed_unverified() == 0
    env.gateway.flush()  # nothing pending: writes nothing
    assert len(env.entries()) == 8
    assert verify(env.audit_path).ok and env.total_tool_calls() == 1


def test_a_verified_call_writes_the_pending_summary_once_there_is_room(env: Env) -> None:
    env.rebuild(unverified_audit_rate=1, unverified_audit_burst=1)
    good = env.mint()
    for i in range(4):
        env.gateway.handle_call(f"junk-{i}", "read_file", {})
    assert env.gateway.suppressed_unverified() == 3
    env.clock.now += 5
    assert env.gateway.handle_call(good, "read_file", {"path": "reports/x"}).allowed
    rules = [e["rule"] for e in env.entries()]
    assert rules == ["token: malformed", "unverified: 3 attempts suppressed", "allow-plain"]


def test_the_limit_can_be_turned_off(env: Env) -> None:
    env.rebuild(unverified_audit_rate=None)
    for i in range(150):
        assert env.gateway.handle_call(f"junk-{i}", "read_file", {}).audit_seq == i


# --------------------------------------------------- 13. tool exception text withheld


def test_tool_exception_text_can_be_withheld_from_the_caller(env: Env) -> None:
    def leaky() -> None:
        raise ConnectionError("postgres://svc:hunter2@10.0.0.7/prod: refused, see /srv/app/db.py")

    env.rebuild({"ghost": leaky}, tool_error_detail=False)
    token = env.mint()
    outcome = env.gateway.handle_call(token, "ghost", {})
    assert (outcome.status, outcome.stage) == ("error", "tool")
    assert outcome.reason == "tool raised ConnectionError; details are withheld"
    for secret in ("hunter2", "postgres", "/srv/app"):
        assert secret not in outcome.reason
        assert secret not in env.audit_path.read_text()
    assert [e["decision"] for e in env.entries()] == ["allow"]
