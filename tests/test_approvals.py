"""The approval queue on its own, then approvals through the real gateway.

As in test_gateway.py, a refusal is only accepted as tested when the tool spy
shows no call and the budget ledger shows no charge.
"""

from __future__ import annotations

import dataclasses
import hashlib
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from caveat.approvals import (  # noqa: E402
    APPROVED,
    DENIED,
    EXPIRED,
    PENDING,
    REJECTED,
    Approval,
    ApprovalError,
    ApprovalQueue,
    QueueFull,
    request_hash,
    valid_name,
)
from caveat.audit import canonical_json, hash_args, verify  # noqa: E402
from caveat.capability import Call, Capability, Grant  # noqa: E402
from caveat.gateway import CallOutcome  # noqa: E402
from caveat.policy import Policy  # noqa: E402
from caveat.tokens import TokenError  # noqa: E402
from test_gateway import READ, SEND, T0, Env  # noqa: E402

EXTERNAL = {"to": "x@evil.test", "body": "hello"}
INTERNAL = {"to": "bob@example.com", "body": "hello"}
MAIL_CAP = {
    "tool": "send_email",
    "args": {"to": {"any": True}, "body": {"any": True}},
    "max_calls": 1,
}


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


def park(env: Env, token: str, args: dict[str, Any] | None = None) -> str:
    outcome = env.gateway.handle_call(token, "send_email", dict(args or EXTERNAL))
    assert outcome.status == "pending", outcome
    assert outcome.approval_id is not None
    return outcome.approval_id


def create(queue: ApprovalQueue, jti: str = "tok-1", n: int = 0, now: float = T0) -> Approval:
    record, created = queue.create(
        token=f"token-of-{jti}",
        jti=jti,
        sub="user:alice",
        actors=("agent:a",),
        call=Call("send_email", {"to": f"x{n}@evil.test"}),
        rule="approve-external-email",
        reason="needs a person",
        now=now,
    )
    assert created
    return record


# ============================================================ the queue on its own


def test_create_binds_the_exact_request() -> None:
    queue = ApprovalQueue()
    record = create(queue)
    args_hash = hash_args({"to": "x0@evil.test"})
    expected = hashlib.sha256(
        canonical_json({"jti": "tok-1", "tool": "send_email", "args_hash": args_hash})
    ).hexdigest()
    assert record.request_hash == expected == request_hash("tok-1", "send_email", args_hash)
    assert record.args_hash == args_hash
    assert (record.state, record.created_at, record.expires_at) == (PENDING, T0, T0 + 300)
    assert queue.get(record.id) == record
    assert queue.pending(T0) == [record]
    # A different token id, tool or argument gives a different binding.
    assert request_hash("tok-2", "send_email", args_hash) != expected
    assert request_hash("tok-1", "send_mail", args_hash) != expected
    assert request_hash("tok-1", "send_email", hash_args({"to": "x1@evil.test"})) != expected


def test_ids_are_long_random_and_unique() -> None:
    queue = ApprovalQueue(max_pending=500, max_pending_per_token=500)
    ids = [create(queue, n=i).id for i in range(200)]
    assert len(set(ids)) == 200
    assert all(len(i) >= 43 for i in ids)  # 32 random bytes, base64url
    # No shared prefix structure such as a counter.
    assert len({i[:6] for i in ids}) == 200


def test_records_are_immutable_and_the_queue_has_no_edit_operation() -> None:
    queue = ApprovalQueue()
    record = create(queue)
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.call = Call("delete_file", {})  # type: ignore[misc]
    with pytest.raises(TypeError):
        record.call.args["to"] = "other@evil.test"  # type: ignore[index]
    public = {name for name in dir(ApprovalQueue) if not name.startswith("_")}
    assert public == {
        "create",
        "resolve",
        "finish",
        "discard",
        "expire",
        "get",
        "pending",
        "pending_count",
    }
    # A snapshot someone altered by force does not alter the stored record.
    for snapshot in (record, queue.get(record.id), queue.pending(T0)[0]):
        object.__setattr__(snapshot, "call", Call("delete_file", {}))
    assert queue.get(record.id).call.tool == "send_email"  # type: ignore[union-attr]
    assert queue.resolve(record.id, APPROVED, "alice", T0).call.tool == "send_email"


def test_a_stored_call_altered_in_memory_is_caught_by_the_request_binding(env: Env) -> None:
    token = env.mint()
    approval_id = park(env, token)
    stored = env.queue._records[approval_id]  # reach past the interface, as a bug might
    object.__setattr__(stored, "call", Call("send_email", {"to": "other@evil.test", "body": "x"}))
    outcome = env.gateway.resolve_approval(approval_id, "approve", "alice")
    assert (outcome.status, outcome.stage) == ("denied", "approval")
    assert env.spies["send_email"].calls == []
    assert env.used(token, SEND) == 0


def test_identical_pending_request_is_not_queued_twice() -> None:
    queue = ApprovalQueue()
    first = create(queue)
    again, created = queue.create(
        token="token-of-tok-1",
        jti="tok-1",
        sub="user:alice",
        actors=("agent:a",),
        call=Call("send_email", {"to": "x0@evil.test"}),
        rule="r",
        reason="",
        now=T0 + 5,
    )
    assert not created and again.id == first.id
    assert queue.pending_count(T0 + 5) == 1
    # Once resolved, the same request may be parked again as a new record.
    queue.resolve(first.id, REJECTED, "alice", T0 + 6)
    assert create(queue, now=T0 + 7).id != first.id


def test_caps_per_token_and_global() -> None:
    queue = ApprovalQueue(max_pending_per_token=2, max_pending=3)
    create(queue, "tok-1", 0)
    create(queue, "tok-1", 1)
    with pytest.raises(QueueFull) as info:
        create(queue, "tok-1", 2)
    assert info.value.scope == "token"
    create(queue, "tok-2", 0)
    with pytest.raises(QueueFull) as info:
        create(queue, "tok-3", 0)
    assert info.value.scope == "global"
    assert queue.pending_count(T0) == 3 and queue.pending_count(T0, "tok-1") == 2
    # Expired records stop counting, even before a sweep.
    assert queue.pending_count(T0 + 300) == 0
    create(queue, "tok-3", 0, now=T0 + 300)


def test_resolve_is_single_use() -> None:
    queue = ApprovalQueue()
    record = create(queue)
    resolved = queue.resolve(record.id, APPROVED, "alice", T0 + 1)
    assert (resolved.state, resolved.approver, resolved.resolved_at) == (APPROVED, "alice", T0 + 1)
    for state in (APPROVED, REJECTED):
        with pytest.raises(ApprovalError) as info:
            queue.resolve(record.id, state, "mallory", T0 + 2)
        assert info.value.code == "not_pending"
    assert queue.get(record.id).approver == "alice"  # type: ignore[union-attr]
    assert queue.pending(T0 + 2) == []


def test_resolve_refuses_unknown_ids_bad_states_and_bad_names() -> None:
    queue = ApprovalQueue()
    record = create(queue)
    for bad in ("", "nope", record.id[:-1], record.id + "x", None, 7):
        with pytest.raises(ApprovalError) as info:
            queue.resolve(bad, APPROVED, "alice", T0)  # type: ignore[arg-type]
        assert info.value.code == "not_found"
    for state in (PENDING, EXPIRED, DENIED, "anything"):
        with pytest.raises(ValueError):
            queue.resolve(record.id, state, "alice", T0)
    for approver in ("", " alice", "al\nice", "a" * 257, None, b"alice"):
        with pytest.raises(ValueError):
            queue.resolve(record.id, APPROVED, approver, T0)  # type: ignore[arg-type]
    assert queue.get(record.id).state == PENDING  # type: ignore[union-attr]


def test_expiry_boundary_and_sweep() -> None:
    queue = ApprovalQueue(ttl=300, retention=100)
    late, live = create(queue, n=0), create(queue, n=1, now=T0 + 10)
    queue.resolve(live.id, REJECTED, "alice", T0 + 299.9)  # just inside its own ttl
    with pytest.raises(ApprovalError) as info:
        queue.resolve(late.id, APPROVED, "alice", T0 + 300)  # at the boundary: expired
    assert info.value.code == "expired"
    assert [r.id for r in queue.expire(T0 + 300)] == [late.id]
    assert queue.expire(T0 + 300) == []  # reported exactly once
    assert queue.get(late.id).state == EXPIRED  # type: ignore[union-attr]
    with pytest.raises(ApprovalError) as info:
        queue.resolve(late.id, APPROVED, "alice", T0 + 301)
    assert info.value.code == "expired"
    queue.expire(T0 + 400)  # retention over for both
    assert queue.get(late.id) is None and queue.get(live.id) is None


def test_finish_and_discard() -> None:
    queue = ApprovalQueue()
    a, b, c = create(queue, n=0), create(queue, n=1), create(queue, n=2)
    with pytest.raises(ApprovalError):
        queue.finish(a.id, "outcome")  # still pending
    queue.resolve(a.id, APPROVED, "alice", T0)
    assert queue.finish(a.id, "outcome", denied=True).state == DENIED
    with pytest.raises(ApprovalError):
        queue.finish(a.id, "second outcome")
    queue.resolve(b.id, REJECTED, "alice", T0)
    assert queue.finish(b.id, "outcome", denied=True).state == REJECTED
    queue.discard(c.id)
    assert queue.get(c.id) is None
    queue.discard(a.id)  # only pending records can be discarded
    assert queue.get(a.id) is not None
    # An approved record whose call has not finished survives the retention sweep.
    d = create(queue, n=3)
    queue.resolve(d.id, APPROVED, "alice", T0)
    queue.expire(T0 + 10_000)
    assert queue.get(d.id) is not None and queue.get(a.id) is None


def test_constructor_validation() -> None:
    for options in (
        {"ttl": 0},
        {"ttl": float("inf")},
        {"ttl": True},
        {"max_pending": 0},
        {"max_pending_per_token": 1.5},
        {"retention": -1},
    ):
        with pytest.raises(ValueError):
            ApprovalQueue(**options)  # type: ignore[arg-type]
    queue = ApprovalQueue(new_id=lambda: "same")
    create(queue, n=0)
    with pytest.raises(ValueError):
        create(queue, n=1)  # a repeating id generator is refused, not overwritten


def test_valid_name() -> None:
    for good in ("alice", "alice@example.com", "user:alice smith", "Zoë", "a" * 256):
        assert valid_name(good)
    for bad in ("", " ", " a", "a ", "a\tb", "a\nb", "a\x00b", "a​b", "\ud800", "a" * 257):
        assert not valid_name(bad)
    for bad in (None, 1, b"alice", ["alice"]):
        assert not valid_name(bad)


def test_racing_resolvers_get_exactly_one_winner() -> None:
    queue = ApprovalQueue()
    record = create(queue)
    barrier = threading.Barrier(24)
    wins: list[str] = []
    losses: list[str] = []

    def work(i: int) -> None:
        barrier.wait()
        try:
            queue.resolve(record.id, APPROVED if i % 2 else REJECTED, f"approver-{i}", T0 + 1)
            wins.append(f"approver-{i}")
        except ApprovalError as exc:
            losses.append(exc.code)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(wins) == 1 and losses == ["not_pending"] * 23
    assert queue.get(record.id).approver == wins[0]  # type: ignore[union-attr]


# ====================================================== approvals through the gateway


def test_approve_runs_the_stored_call_once_and_charges_once(env: Env) -> None:
    token = env.mint()
    approval_id = park(env, token)
    assert env.spies["send_email"].calls == [] and env.used(token, SEND) == 0

    outcome = env.gateway.resolve_approval(approval_id, "approve", "alice@example.com")
    assert outcome == CallOutcome(
        "allowed",
        "ok",
        rule="approve-external-email",
        approval_id=approval_id,
        result="done",
        audit_seq=1,
        stage="policy",
    )
    assert env.spies["send_email"].calls == [EXTERNAL]
    assert env.used(token, SEND) == 1
    first, second = env.entries()
    assert (first["decision"], first["approver"]) == ("approve", None)
    assert (second["decision"], second["approver"]) == ("approved", "alice@example.com")
    assert second["rule"] == "approve-external-email"
    assert second["jti"] == first["jti"] == env.jti(token)
    assert second["args_hash"] == first["args_hash"] == hash_args(EXTERNAL)
    record = env.gateway.get_approval(approval_id, token)
    assert (record.state, record.approver, record.outcome) == (
        APPROVED,
        "alice@example.com",
        outcome,
    )
    assert verify(env.audit_path, env.audit.head()).ok


def test_mutating_the_submitted_arguments_after_submission_changes_nothing(env: Env) -> None:
    token = env.mint()
    body = ["original"]
    args = {"to": "x@evil.test", "body": body}
    outcome = env.gateway.handle_call(token, "send_email", args)
    assert outcome.status == "pending"
    # The agent now tries to swap what the approver is about to release.
    args["to"] = "attacker@evil.test"
    args["bcc"] = "attacker@evil.test"
    body.append("and wire the money")
    (shown,) = env.gateway.list_pending()
    assert dict(shown.call.args) == {"to": "x@evil.test", "body": ("original",)}
    env.gateway.resolve_approval(outcome.approval_id, "approve", "alice")
    assert env.spies["send_email"].calls == [{"to": "x@evil.test", "body": ["original"]}]
    assert env.entries()[1]["args_hash"] == hash_args({"to": "x@evil.test", "body": ["original"]})


def test_reject_runs_nothing_and_logs_who(env: Env) -> None:
    token = env.mint()
    approval_id = park(env, token)
    outcome = env.gateway.resolve_approval(approval_id, "reject", "alice")
    assert (outcome.status, outcome.stage, outcome.reason) == (
        "denied",
        "approval",
        "rejected by alice",
    )
    assert env.spies["send_email"].calls == []
    assert env.used(token, SEND) == 0
    entry = env.entries()[1]
    assert (entry["decision"], entry["approver"], entry["rule"]) == (
        "rejected",
        "alice",
        "approve-external-email",
    )
    assert env.gateway.get_approval(approval_id, token).state == REJECTED


def test_double_approve_executes_once(env: Env) -> None:
    token = env.mint()
    approval_id = park(env, token)
    assert env.gateway.resolve_approval(approval_id, "approve", "alice").status == "allowed"
    for decision in ("approve", "reject"):
        with pytest.raises(ApprovalError) as info:
            env.gateway.resolve_approval(approval_id, decision, "alice")
        assert info.value.code == "not_pending"
    assert len(env.spies["send_email"].calls) == 1
    assert env.used(token, SEND) == 1
    assert [e["decision"] for e in env.entries()] == ["approve", "approved"]


def test_approve_after_reject_executes_nothing(env: Env) -> None:
    token = env.mint()
    approval_id = park(env, token)
    env.gateway.resolve_approval(approval_id, "reject", "alice")
    with pytest.raises(ApprovalError) as info:
        env.gateway.resolve_approval(approval_id, "approve", "mallory")
    assert info.value.code == "not_pending"
    assert env.spies["send_email"].calls == []
    assert env.used(token, SEND) == 0
    assert env.gateway.get_approval(approval_id, token).approver == "alice"


def test_expired_approval_cannot_be_approved_and_is_logged_once(env: Env) -> None:
    token = env.mint(ttl=900)
    approval_id = park(env, token)
    env.clock.now += 300
    with pytest.raises(ApprovalError) as info:
        env.gateway.resolve_approval(approval_id, "approve", "alice")
    assert info.value.code == "expired"
    assert env.spies["send_email"].calls == []
    assert env.used(token, SEND) == 0
    assert env.gateway.list_pending() == []
    assert env.gateway.get_approval(approval_id, token).state == EXPIRED
    env.gateway.handle_call(token, "read_file", {"path": "reports/x"})  # more sweeps
    expiries = [e for e in env.entries() if e["rule"] == "approval: expired"]
    assert len(expiries) == 1
    assert (expiries[0]["decision"], expiries[0]["jti"]) == ("deny", env.jti(token))
    assert verify(env.audit_path).ok


def assert_denied_after_approval(
    env: Env, token: str, approval_id: str, stage: str, reason: str, calls_before: int = 0
) -> None:
    outcome = env.gateway.resolve_approval(approval_id, "approve", "alice")
    assert (outcome.status, outcome.stage, outcome.reason) == ("denied", stage, reason)
    assert outcome.approval_id == approval_id and outcome.result is None
    assert len(env.spies["send_email"].calls) == calls_before  # the stored call did not run
    entry = env.entries()[-1]
    assert entry["decision"] == "deny"
    assert entry["approver"] is None
    assert entry["rule"].startswith("approved by alice, then denied: ")
    assert entry["jti"] == env.jti(token)
    assert entry["args_hash"] == hash_args(EXTERNAL)
    record = env.gateway.approvals.get(approval_id)
    assert record is not None
    assert (record.state, record.approver, record.outcome) == (DENIED, "alice", outcome)
    # Used up: a second approval of the same id releases nothing either.
    with pytest.raises(ApprovalError):
        env.gateway.resolve_approval(approval_id, "approve", "alice")
    assert len(env.spies["send_email"].calls) == calls_before
    assert verify(env.audit_path).ok


def test_approval_after_token_expiry_is_denied(env: Env) -> None:
    token = env.mint(ttl=100)
    approval_id = park(env, token)
    env.clock.now += 150  # token gone, approval (300 s) still open
    assert_denied_after_approval(env, token, approval_id, "token", "expired")
    assert env.used(token, SEND) == 0
    assert env.entries()[-1]["rule"] == "approved by alice, then denied: token: expired"


def test_approval_after_revocation_is_denied(env: Env) -> None:
    token = env.mint()
    approval_id = park(env, token)
    env.authority.revoke(env.jti(token))
    assert_denied_after_approval(env, token, approval_id, "token", "revoked")
    assert env.used(token, SEND) == 0


def test_approval_after_parent_revocation_is_denied(env: Env) -> None:
    parent = env.mint()
    child = env.authority.exchange(
        parent,
        [MAIL_CAP],
        "agent:mailer",
        300,
    )
    approval_id = park(env, child)
    env.authority.revoke(env.jti(parent))
    assert_denied_after_approval(env, child, approval_id, "token", "revoked")
    assert env.used(parent, SEND) == 0 and env.used(child, 0) == 0


def test_approval_after_policy_reload_to_deny_is_denied(env: Env) -> None:
    token = env.mint()
    approval_id = park(env, token)
    env.gateway.set_policy(
        Policy.from_yaml(
            "version: 1\nrules:\n"
            '  - {id: no-mail, effect: deny, tools: ["send_*"], reason: Frozen.}\n'
        )
    )
    assert_denied_after_approval(env, token, approval_id, "policy", "Frozen.")
    assert env.used(token, SEND) == 0
    assert env.entries()[-1]["rule"] == "approved by alice, then denied: no-mail"


def test_approval_after_budget_exhaustion_is_denied(env: Env) -> None:
    token = env.mint()  # send_email has max_calls 1
    approval_id = park(env, token)
    assert env.gateway.handle_call(token, "send_email", INTERNAL).status == "allowed"
    assert env.used(token, SEND) == 1
    assert_denied_after_approval(
        env, token, approval_id, "budget", "budget exhausted", calls_before=1
    )
    assert env.spies["send_email"].calls == [INTERNAL]
    assert env.used(token, SEND) == 1


def test_approval_when_the_grant_no_longer_covers_the_call(env: Env) -> None:
    # The approval ttl is longer than the grant: the token verifies only until 100 s.
    token = env.mint(ttl=100)
    approval_id = park(env, token)
    env.clock.now += 99.5
    assert env.gateway.resolve_approval(approval_id, "approve", "alice").status == "allowed"
    assert len(env.spies["send_email"].calls) == 1


def test_audit_failure_at_approval_time_blocks_execution(env: Env) -> None:
    token = env.mint()
    approval_id = park(env, token)
    env.audit.fail = True
    outcome = env.gateway.resolve_approval(approval_id, "approve", "alice")
    assert (outcome.status, outcome.stage) == ("denied", "audit")
    assert env.spies["send_email"].calls == []
    assert env.gateway.approvals.get(approval_id).state == DENIED  # type: ignore[union-attr]
    env.audit.fail = False
    with pytest.raises(ApprovalError):
        env.gateway.resolve_approval(approval_id, "approve", "alice")
    assert env.spies["send_email"].calls == []


def test_tool_error_during_an_approved_call(tmp_path: Path) -> None:
    env = Env(tmp_path)

    def failing(**kwargs: Any) -> None:
        raise OSError("smtp down")

    env.gateway._tools["send_email"] = failing  # test seam: swap the registered tool
    token = env.mint()
    approval_id = park(env, token)
    outcome = env.gateway.resolve_approval(approval_id, "approve", "alice")
    assert (outcome.status, outcome.reason) == ("error", "tool raised OSError: smtp down")
    record = env.gateway.get_approval(approval_id, token)
    assert (record.state, record.outcome.status) == (APPROVED, "error")
    assert env.used(token, SEND) == 1
    assert [e["decision"] for e in env.entries()] == ["approve", "approved"]


# ------------------------------------------------------------ ids, readers, approvers


def test_approval_ids_cannot_be_guessed_or_derived(env: Env) -> None:
    token = env.mint()
    approval_id = park(env, token)
    record = env.gateway.approvals.get(approval_id)
    assert record is not None
    guesses = [
        "0",
        "1",
        "approval-1",
        approval_id[:-1],
        approval_id.lower(),
        approval_id + "=",
        record.request_hash,
        record.args_hash,
        record.jti,
        "../" + approval_id,
        "",
    ]
    for guess in guesses:
        if guess == approval_id:
            continue
        with pytest.raises(ApprovalError) as info:
            env.gateway.resolve_approval(guess, "approve", "alice")
        assert info.value.code == "not_found"
        with pytest.raises(ApprovalError) as info:
            env.gateway.get_approval(guess, token)
        assert info.value.code == "not_found"
    assert env.spies["send_email"].calls == []
    assert env.gateway.approvals.get(approval_id).state == PENDING  # type: ignore[union-attr]
    assert len(env.entries()) == 1  # guessing wrote nothing


def test_only_the_creating_token_can_read_an_approval(env: Env) -> None:
    owner = env.mint()
    sibling = env.mint()  # same user, same capabilities, different token
    child = env.authority.exchange(
        owner,
        [MAIL_CAP],
        "agent:sub",
        60,
    )
    approval_id = park(env, owner)
    env.gateway.resolve_approval(approval_id, "approve", "alice")
    assert env.gateway.get_approval(approval_id, owner).outcome.result == "done"
    for other in (sibling, child):
        with pytest.raises(ApprovalError) as info:
            env.gateway.get_approval(approval_id, other)
        assert info.value.code == "not_found"  # same answer as an id that does not exist
    for bad in ("garbage", owner + "x", ""):
        with pytest.raises(TokenError):
            env.gateway.get_approval(approval_id, bad)
    env.authority.revoke(env.jti(owner))
    with pytest.raises(TokenError) as info:
        env.gateway.get_approval(approval_id, owner)
    assert info.value.code == "revoked"


@pytest.mark.parametrize(
    "approver", ["", " alice", "alice ", "al\nice", "a\x00", "‮alice", "a" * 257, None, 5]
)
def test_invalid_approver_changes_nothing(env: Env, approver: Any) -> None:
    token = env.mint()
    approval_id = park(env, token)
    for decision in ("approve", "reject"):
        with pytest.raises(ValueError):
            env.gateway.resolve_approval(approval_id, decision, approver)
    assert env.gateway.approvals.get(approval_id).state == PENDING  # type: ignore[union-attr]
    assert env.spies["send_email"].calls == []
    assert len(env.entries()) == 1


@pytest.mark.parametrize("decision", ["", "APPROVE", "approved", "yes", None, True])
def test_invalid_decision_changes_nothing(env: Env, decision: Any) -> None:
    token = env.mint()
    approval_id = park(env, token)
    with pytest.raises(ValueError):
        env.gateway.resolve_approval(approval_id, decision, "alice")
    assert env.gateway.approvals.get(approval_id).state == PENDING  # type: ignore[union-attr]
    assert env.spies["send_email"].calls == []


# ------------------------------------------------------------------------- flooding


def test_pending_approvals_are_capped_per_token_and_globally(tmp_path: Path) -> None:
    env = Env(tmp_path, max_pending_per_token=2, max_pending=3)
    first, second = env.mint(), env.mint()
    ids = [park(env, first, {"to": f"x{i}@evil.test", "body": "b"}) for i in range(2)]
    outcome = env.gateway.handle_call(first, "send_email", {"to": "x9@evil.test", "body": "b"})
    assert (outcome.status, outcome.stage) == ("denied", "approvals")
    assert "token limit" in outcome.reason and outcome.approval_id is None
    park(env, second, {"to": "y0@evil.test", "body": "b"})
    outcome = env.gateway.handle_call(second, "send_email", {"to": "y1@evil.test", "body": "b"})
    assert (outcome.status, outcome.stage) == ("denied", "approvals")
    assert "global limit" in outcome.reason
    assert len(env.gateway.list_pending()) == 3
    assert env.spies["send_email"].calls == []
    assert [e["decision"] for e in env.entries()] == [
        "approve",
        "approve",
        "deny",
        "approve",
        "deny",
    ]
    assert env.entries()[2]["rule"].startswith("approvals: too many pending approvals")
    # Resolving one frees a slot; replaying the same pending request does not use one.
    env.gateway.resolve_approval(ids[0], "reject", "alice")
    assert park(env, first, {"to": "x1@evil.test", "body": "b"}) == ids[1]
    park(env, first, {"to": "x7@evil.test", "body": "b"})
    assert len(env.gateway.list_pending()) == 3


def test_replaying_a_pending_request_gives_one_approval_and_one_execution(env: Env) -> None:
    token = env.mint()
    ids = {park(env, token) for _ in range(10)}
    assert len(ids) == 1
    assert len(env.gateway.list_pending()) == 1
    assert len(env.entries()) == 10  # each attempt is logged
    env.gateway.resolve_approval(ids.pop(), "approve", "alice")
    assert len(env.spies["send_email"].calls) == 1
    assert env.used(token, SEND) == 1


# ---------------------------------------------------------------------------- races


def test_racing_approvals_of_one_id_execute_exactly_once(tmp_path: Path) -> None:
    env = Env(tmp_path)
    for _round in range(10):
        token = env.mint()
        approval_id = park(env, token)
        before = len(env.spies["send_email"].calls)
        barrier = threading.Barrier(12)
        allowed: list[CallOutcome] = []
        refused: list[str] = []

        def work(
            i: int,
            approval_id: str = approval_id,
            barrier: Any = barrier,
            allowed: Any = allowed,
            refused: Any = refused,
        ) -> None:
            barrier.wait()
            try:
                decision = "approve" if i % 3 else "reject"
                outcome = env.gateway.resolve_approval(approval_id, decision, f"approver-{i}")
                if outcome.status == "allowed":
                    allowed.append(outcome)
            except ApprovalError as exc:
                refused.append(exc.code)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(refused) == 11 and set(refused) == {"not_pending"}
        executed = len(env.spies["send_email"].calls) - before
        assert executed == len(allowed) <= 1
        assert env.used(token, SEND) == executed
    result = verify(env.audit_path, env.audit.head())
    assert result.ok and result.entries == 20  # one "approve" and one resolution per round


def test_racing_approve_against_revoke_is_consistent(tmp_path: Path) -> None:
    env = Env(tmp_path)
    ran = denied = 0
    for _round in range(60):
        token = env.mint()
        approval_id = park(env, token)
        before = len(env.spies["send_email"].calls)
        barrier = threading.Barrier(2)
        box: dict[str, CallOutcome] = {}

        def approve(approval_id: str = approval_id, barrier: Any = barrier, box: Any = box) -> None:
            barrier.wait()
            box["outcome"] = env.gateway.resolve_approval(approval_id, "approve", "alice")

        def revoke(token: str = token, barrier: Any = barrier) -> None:
            barrier.wait()
            env.authority.revoke(env.jti(token))

        threads = [threading.Thread(target=approve), threading.Thread(target=revoke)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        outcome = box["outcome"]
        executed = len(env.spies["send_email"].calls) - before
        entry = env.entries()[-1]
        if outcome.status == "allowed":
            # The charge (with its revocation check) came first: ran once, logged approved.
            assert executed == 1 and env.used(token, SEND) == 1
            assert entry["decision"] == "approved"
            ran += 1
        else:
            assert (outcome.stage, outcome.reason) == ("token", "revoked")
            assert executed == 0 and env.used(token, SEND) == 0
            assert entry["decision"] == "deny"
            denied += 1
        # Either way the token is dead afterwards.
        after = env.gateway.handle_call(token, "send_email", INTERNAL)
        assert (after.status, after.reason) == ("denied", "revoked")
        assert len(env.spies["send_email"].calls) - before == executed
    assert ran + denied == 60
    assert verify(env.audit_path, env.audit.head()).ok


def test_read_budget_untouched_by_the_whole_approval_story(env: Env) -> None:
    token = env.mint()
    approval_id = park(env, token)
    env.gateway.resolve_approval(approval_id, "reject", "alice")
    assert env.used(token, READ) == 0 and env.used(token, SEND) == 0
    assert env.total_tool_calls() == 0


# ====================================================================================
# Findings from the security reviews. Each test below failed before its fix.
# ====================================================================================

# --------------------------------------- 2. an expiry entry survives an audit outage


def test_expiry_entry_lost_to_an_audit_outage_is_written_by_a_later_sweep(env: Env) -> None:
    token = env.mint(ttl=900)
    first = park(env, token)
    second = park(env, token, {"to": "y@evil.test", "body": "b"})
    env.clock.now += 300
    env.audit.fail = True
    assert env.gateway.list_pending() == []  # this sweep expires both and cannot log either
    assert env.gateway.approvals.get(first).state == EXPIRED  # type: ignore[union-attr]
    assert [e["decision"] for e in env.entries()] == ["approve", "approve"]
    env.gateway.list_pending()  # still failing: nothing is dropped in the meantime
    env.audit.fail = False
    env.gateway.list_pending()
    expiries = [e for e in env.entries() if e["rule"] == "approval: expired"]
    assert len(expiries) == 2
    assert {e["args_hash"] for e in expiries} == {
        env.gateway.approvals.get(i).args_hash  # type: ignore[union-attr]
        for i in (first, second)
    }
    for _ in range(3):  # and each is written exactly once
        env.gateway.list_pending()
        env.gateway.handle_call(token, "read_file", {"path": "nope"})
    assert len([e for e in env.entries() if e["rule"] == "approval: expired"]) == 2
    assert env.spies["send_email"].calls == [] and env.used(token, SEND) == 0
    assert verify(env.audit_path).ok


# ----------------------------------------------------- 5. strict decisions, finish


class Chameleon:
    """Compares equal to everything, like a decision that is whatever you want it to be."""

    def __eq__(self, other: object) -> bool:
        return True

    def __hash__(self) -> int:
        return hash("approve")


class LoudStr(str):
    """A str subclass: still not the exact string."""

    def __eq__(self, other: object) -> bool:
        return True

    __hash__ = str.__hash__


@pytest.mark.parametrize(
    "decision", [Chameleon(), LoudStr("reject"), LoudStr("anything"), b"approve", ["approve"], 1]
)
def test_resolve_takes_only_the_exact_strings_approve_and_reject(env: Env, decision: Any) -> None:
    token = env.mint()
    approval_id = park(env, token)
    with pytest.raises(ValueError):
        env.gateway.resolve_approval(approval_id, decision, "alice")
    assert env.gateway.approvals.get(approval_id).state == PENDING  # type: ignore[union-attr]
    assert env.spies["send_email"].calls == [] and env.used(token, SEND) == 0
    assert len(env.entries()) == 1


class FlakyQueue(ApprovalQueue):
    """A real queue whose `finish` can be made to fail, as a persistent one could."""

    failures = 0

    def finish(self, approval_id: str, outcome: Any, *, denied: bool = False) -> Approval:
        if self.failures:
            self.failures -= 1
            raise OSError("queue storage is down (injected)")
        return super().finish(approval_id, outcome, denied=denied)


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_finish_failing_after_the_decision_leaves_no_stuck_record(
    tmp_path: Path, decision: str
) -> None:
    env = Env(tmp_path, retention=100)
    env.queue = FlakyQueue(retention=100)
    env.rebuild()
    token = env.mint()
    approval_id = park(env, token)
    env.queue.failures = 2
    outcome = env.gateway.resolve_approval(approval_id, decision, "alice")  # must not raise
    expected = "allowed" if decision == "approve" else "denied"
    assert outcome.status == expected
    assert len(env.spies["send_email"].calls) == (1 if decision == "approve" else 0)
    assert env.queue.get(approval_id).outcome is None  # type: ignore[union-attr]
    env.gateway.list_pending()  # one more failure: the outcome is kept, not dropped
    assert env.queue.get(approval_id).outcome is None  # type: ignore[union-attr]
    env.gateway.list_pending()  # the queue is back: the outcome is stored
    record = env.queue.get(approval_id)
    assert record is not None and record.outcome.status == expected
    # So the record can be evicted once its retention is over, and the call ran once at most.
    env.clock.now += 101
    env.gateway.list_pending()
    assert env.queue.get(approval_id) is None
    assert len(env.spies["send_email"].calls) == (1 if decision == "approve" else 0)
    assert env.used(token, SEND) == (1 if decision == "approve" else 0)


# ------------------------------------- 6. snapshots do not share the stored call


def test_a_snapshot_altered_by_force_cannot_change_what_is_released(env: Env) -> None:
    token = env.mint()
    approval_id = park(env, token)
    snapshots = [
        env.queue.get(approval_id),
        env.queue.pending(env.clock.now)[0],
        env.gateway.list_pending()[0],
        env.gateway.get_approval(approval_id, token),
    ]
    for snapshot in snapshots:
        assert snapshot is not None
        assert snapshot.call.args == EXTERNAL and snapshot.call.tool == "send_email"
        # The Call object itself is attacked, not the snapshot's reference to it.
        object.__setattr__(snapshot.call, "tool", "delete_file")
        object.__setattr__(snapshot.call, "args", {"to": "attacker@evil.test", "body": "x"})
    stored = env.queue.get(approval_id)
    assert stored is not None
    assert (stored.call.tool, dict(stored.call.args)) == ("send_email", EXTERNAL)
    assert len({id(s.call) for s in snapshots if s is not None}) == 4  # each its own copy
    outcome = env.gateway.resolve_approval(approval_id, "approve", "alice")
    assert outcome.status == "allowed"
    assert env.spies["send_email"].calls == [EXTERNAL]
    assert env.spies["delete_file"].calls == []


def test_the_call_handed_to_create_is_not_the_one_the_queue_keeps() -> None:
    queue = ApprovalQueue()
    call = Call("send_email", {"to": "x0@evil.test", "cc": ["a", {"b": 1}]})
    record, _ = queue.create(
        token="t", jti="tok", sub="s", actors=("a",), call=call, rule="r", reason="", now=T0
    )
    object.__setattr__(call, "tool", "delete_file")
    object.__setattr__(record.call, "tool", "delete_file")
    kept = queue.get(record.id)
    assert kept is not None and kept.call == Call(
        "send_email", {"to": "x0@evil.test", "cc": ["a", {"b": 1}]}
    )
    assert kept.args_hash == hash_args(kept.call.args)
    with pytest.raises(TypeError):
        kept.call.args["cc"][1]["b"] = 2  # copies are as read-only as the original


# ------------------------------------------ 7. one agent cannot fill the whole queue


def test_children_of_one_root_cannot_block_another_roots_request(tmp_path: Path) -> None:
    env = Env(tmp_path, max_pending_per_token=5, max_pending_per_root=10, max_pending=30)
    mail = {"tool": "send_email", "args": {"to": {"any": True}, "body": {"any": True}}}
    greedy = env.authority.mint(
        "user:mallory", Grant((Capability.from_dict(mail),), T0 + 600), "a", 600
    )
    children = [env.child(greedy, [mail], f"agent:child-{i}") for i in range(20)]
    outcomes = [
        env.gateway.handle_call(child, "send_email", {"to": f"v{i}-{n}@evil.test", "body": "b"})
        for i, child in enumerate(children)
        for n in range(5)
    ]
    parked = [o for o in outcomes if o.status == "pending"]
    refused = [o for o in outcomes if o.status == "denied"]
    assert len(parked) == 10 and len(refused) == 90  # 100 attempts, the root's 10 slots
    assert {o.stage for o in refused} == {"approvals"}
    assert all("root limit" in o.reason for o in refused)
    assert env.entries()[-1]["rule"] == "approvals: too many pending approvals (root limit)"
    assert env.queue.pending_count(env.clock.now) == 10  # 20 left of the global 30
    # A different user's root token still gets its request parked.
    victim = env.mint()
    assert env.gateway.handle_call(victim, "send_email", EXTERNAL).status == "pending"
    assert env.spies["send_email"].calls == []
    stored = env.gateway.list_pending()
    assert {r.root for r in stored} == {env.jti(greedy), env.jti(victim)}


def test_caps_per_root_and_per_principal() -> None:
    queue = ApprovalQueue(
        max_pending_per_token=2, max_pending_per_root=3, max_pending_per_sub=5, max_pending=100
    )

    def add(jti: str, root: str, sub: str, n: int, now: float = T0) -> Approval:
        return queue.create(
            token=f"token-of-{jti}",
            jti=jti,
            sub=sub,
            actors=("agent:a",),
            call=Call("send_email", {"to": f"x{n}@evil.test"}),
            rule="r",
            reason="",
            now=now,
            root=root,
        )[0]

    add("c1", "root-a", "user:alice", 0)
    add("c1", "root-a", "user:alice", 1)
    with pytest.raises(QueueFull) as info:
        add("c1", "root-a", "user:alice", 2)
    assert info.value.scope == "token"
    assert add("c2", "root-a", "user:alice", 0).root == "root-a"
    with pytest.raises(QueueFull) as info:
        add("c3", "root-a", "user:alice", 0)  # a fresh child of the same root
    assert info.value.scope == "root"
    add("d1", "root-b", "user:alice", 0)  # the same person's second root token
    add("d1", "root-b", "user:alice", 1)
    with pytest.raises(QueueFull) as info:
        add("d2", "root-b", "user:alice", 0)
    assert info.value.scope == "sub"
    add("e1", "root-c", "user:bob", 0)  # somebody else is unaffected
    assert queue.pending_count(T0) == 6
    # Expired records stop counting, and a root token counts under its own id by default.
    assert add("c3", "root-a", "user:alice", 0, now=T0 + 300).state == PENDING
    record, _ = queue.create(
        token="t", jti="lone", sub="s", actors=(), call=Call("x", {}), rule="r", reason="", now=T0
    )
    assert record.root == "lone"
    for options in ({"max_pending_per_root": 0}, {"max_pending_per_sub": 1.5}):
        with pytest.raises(ValueError):
            ApprovalQueue(**options)  # type: ignore[arg-type]
    # Left unset, the wider caps are never tighter than the cap inside them.
    wide = ApprovalQueue(max_pending_per_token=50)
    assert (wide.max_pending_per_root, wide.max_pending_per_sub) == (50, 50)
    assert (ApprovalQueue().max_pending_per_root, ApprovalQueue().max_pending_per_sub) == (10, 20)
