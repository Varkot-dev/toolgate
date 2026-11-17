"""The gateway pipeline, through real components: Authority, Policy, AuditLog, ApprovalQueue.

Rule for every refusal test here: assert that the side effect did NOT happen
(the tool spy was not called, the budget counter did not move), not only that
a status came back.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwt import PyJWS

from toolgate.approvals import ApprovalQueue
from toolgate.audit import AuditError, AuditLog, hash_args, verify
from toolgate.capability import Capability, Grant
from toolgate.gateway import (
    INVALID_TOOL,
    MAX_REASON_CHARS,
    TRUNCATED,
    CallOutcome,
    Gateway,
    bounded,
    loggable_tool,
    token_fingerprint,
)
from toolgate.policy import Policy
from toolgate.store import MemoryStore
from toolgate.tokens import Authority

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
    flipped = signature[:-2] + ("AA" if signature[-2:] != "AA" else "BB")
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
    # Stated honestly: the budget was already spent in step d and is not refunded.
    assert env.used(token, READ) == 1
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
