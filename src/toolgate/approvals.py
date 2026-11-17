"""Pending human approvals: calls that policy parked until a person decides.

An approval record binds a decision to one EXACT request. It stores the token
string the call was made with, the canonical `Call` (the read-only copy the
checks ran on) and

    request_hash = SHA-256 of canonical JSON {"args_hash", "jti", "tool"}

There is no operation that changes the call or the token of a record. The
only things that ever change are the state and, at the end, the outcome:

    pending --> approved --> (outcome recorded: allowed | error)
            |            \\-> denied   (approved, but the re-check refused it)
            |-> rejected
            \\-> expired

`resolve` is the single-use step. It moves a record out of `pending` under a
lock, so of two threads approving the same id exactly one gets the record and
the other gets `ApprovalError("not_pending")`. Whoever gets the record is the
only one who may execute the call.

`denied` is one state more than "pending, approved, rejected, expired": it is
what an approval becomes when the approver said yes but the token had expired
or been revoked, policy had changed to deny, or the budget was gone. Keeping
it separate means a polling agent never reads "approved" for a call that did
not run.

Limits that stop an agent flooding the queue: at most `max_pending_per_token`
pending records per token id and `max_pending` in total. A request identical
to one that is already pending (same request_hash) does not create a second
record; it returns the existing one.

Time is passed in by the caller (seconds since the epoch), never read here,
so the queue is deterministic under test. State is in memory and is lost on
restart, which fails closed: a lost approval can release nothing. The public
methods are the whole interface a persistent (SQLite) version would need.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from toolgate.audit import canonical_json, hash_args
from toolgate.capability import Call

PENDING, APPROVED, REJECTED, EXPIRED, DENIED = (
    "pending",
    "approved",
    "rejected",
    "expired",
    "denied",
)
STATES: frozenset[str] = frozenset({PENDING, APPROVED, REJECTED, EXPIRED, DENIED})
MAX_NAME_CHARS = 256


class ApprovalError(Exception):
    """An approval could not be found or acted on.

    Codes: not_found, not_pending, expired.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class QueueFull(Exception):
    """A cap on pending approvals was reached. `scope` is "token" or "global"."""

    def __init__(self, scope: str) -> None:
        super().__init__(f"too many pending approvals ({scope} limit)")
        self.scope = scope


@dataclass(frozen=True)
class Approval:
    """A snapshot of one approval record.

    The queue hands out copies, so a snapshot altered by force (frozen
    dataclasses do not stop `object.__setattr__`) never changes the record
    the queue holds.
    """

    id: str
    token: str  # the bearer token the call was made with; never shown to anyone
    jti: str
    sub: str
    actors: tuple[str, ...]
    call: Call
    args_hash: str
    request_hash: str
    rule: str  # the policy rule that asked for approval
    reason: str
    created_at: float
    expires_at: float
    state: str = PENDING
    approver: str | None = None
    resolved_at: float | None = None
    outcome: Any = None  # the gateway's CallOutcome once the story has ended


def request_hash(jti: str, tool: str, args_hash: str) -> str:
    """SHA-256 (hex) binding a token id to one tool call."""
    return hashlib.sha256(
        canonical_json({"jti": jti, "tool": tool, "args_hash": args_hash})
    ).hexdigest()


def valid_name(value: Any) -> bool:
    """A name fit for the audit log's actor and approver fields.

    The audit log itself accepts any UTF-8 string. Names typed by a person at
    the approval endpoint are held to more: non-empty, at most 256 characters,
    encodable, printable, and no leading or trailing whitespace. That keeps
    control characters, newlines and invisible padding out of the record of
    who approved what.
    """
    if type(value) is not str or not 0 < len(value) <= MAX_NAME_CHARS:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return value.isprintable() and value == value.strip()


def _is_time(value: Any) -> bool:
    return type(value) is int or (type(value) is float and math.isfinite(value))


def _positive_int(value: Any, what: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{what} must be a positive integer")
    return value


class ApprovalQueue:
    """In-memory approval store. Every method is thread safe."""

    def __init__(
        self,
        *,
        ttl: int | float = 300,
        max_pending_per_token: int = 5,
        max_pending: int = 100,
        retention: int | float = 3600,
        new_id: Callable[[], str] | None = None,
    ) -> None:
        if not _is_time(ttl) or ttl <= 0:
            raise ValueError("ttl must be a positive number of seconds")
        if not _is_time(retention) or retention < 0:
            raise ValueError("retention must be a non-negative number of seconds")
        self.ttl = ttl
        self.retention = retention
        self.max_pending_per_token = _positive_int(max_pending_per_token, "max_pending_per_token")
        self.max_pending = _positive_int(max_pending, "max_pending")
        # 32 random bytes: an id cannot be guessed, and knowing one tells
        # nothing about the next.
        self._new_id = new_id if new_id is not None else (lambda: secrets.token_urlsafe(32))
        self._lock = threading.Lock()
        self._records: dict[str, Approval] = {}

    # -- writing ------------------------------------------------------------

    def create(
        self,
        *,
        token: str,
        jti: str,
        sub: str,
        actors: tuple[str, ...],
        call: Call,
        rule: str,
        reason: str,
        now: float,
    ) -> tuple[Approval, bool]:
        """Park one call. Returns (record, created).

        `created` is False when an identical request (same token id, tool and
        arguments) was already pending; the existing record is returned and
        nothing is added. Raises QueueFull over either cap.
        """
        if type(call) is not Call:
            raise ValueError("call must be a Call")
        if type(token) is not str or not token:
            raise ValueError("token must be a non-empty string")
        if not _is_time(now):
            raise ValueError("invalid time")
        args_hash = hash_args(call.args)
        digest = request_hash(jti, call.tool, args_hash)
        with self._lock:
            pending = [r for r in self._records.values() if self._live(r, now)]
            for record in pending:
                if record.request_hash == digest and hmac.compare_digest(
                    record.token.encode(), token.encode()
                ):
                    return replace(record), False
            if sum(1 for r in pending if r.jti == jti) >= self.max_pending_per_token:
                raise QueueFull("token")
            if len(pending) >= self.max_pending:
                raise QueueFull("global")
            approval_id = self._new_id()
            if type(approval_id) is not str or not approval_id or approval_id in self._records:
                raise ValueError("approval id generator returned an unusable id")
            record = Approval(
                id=approval_id,
                token=token,
                jti=jti,
                sub=sub,
                actors=tuple(actors),
                call=call,
                args_hash=args_hash,
                request_hash=digest,
                rule=rule,
                reason=reason,
                created_at=now,
                expires_at=now + self.ttl,
            )
            self._records[approval_id] = record
            return replace(record), True

    def resolve(self, approval_id: str, state: str, approver: str, now: float) -> Approval:
        """Move a pending record to `approved` or `rejected`. Single use.

        Raises ApprovalError: not_found, expired (the ttl ran out, whether or
        not `expire` has swept the record yet) or not_pending (already
        resolved by somebody, including a concurrent caller).
        """
        if state not in (APPROVED, REJECTED):
            raise ValueError("an approval is resolved as approved or rejected")
        if not valid_name(approver):
            raise ValueError("approver is not a valid name")
        if not _is_time(now):
            raise ValueError("invalid time")
        with self._lock:
            record = self._records.get(approval_id) if type(approval_id) is str else None
            if record is None:
                raise ApprovalError("not_found")
            if record.state == EXPIRED or (record.state == PENDING and now >= record.expires_at):
                raise ApprovalError("expired")
            if record.state != PENDING:
                raise ApprovalError("not_pending", f"the approval is already {record.state}")
            record = replace(record, state=state, approver=approver, resolved_at=now)
            self._records[approval_id] = record
            return replace(record)

    def finish(self, approval_id: str, outcome: Any, *, denied: bool = False) -> Approval:
        """Record how a resolved approval ended. `denied` moves approved -> denied."""
        with self._lock:
            record = self._records.get(approval_id)
            if record is None:
                raise ApprovalError("not_found")
            if record.state not in (APPROVED, REJECTED) or record.outcome is not None:
                raise ApprovalError("not_pending", "only a freshly resolved approval can finish")
            state = DENIED if denied and record.state == APPROVED else record.state
            record = replace(record, state=state, outcome=outcome)
            self._records[approval_id] = record
            return replace(record)

    def discard(self, approval_id: str) -> None:
        """Forget a record that is still pending (used when it could not be audited)."""
        with self._lock:
            record = self._records.get(approval_id)
            if record is not None and record.state == PENDING:
                del self._records[approval_id]

    def expire(self, now: float) -> list[Approval]:
        """Expire overdue pending records and drop old finished ones.

        Returns the records that became `expired` in THIS call, each exactly
        once, so the caller can log them.
        """
        if not _is_time(now):
            raise ValueError("invalid time")
        newly: list[Approval] = []
        with self._lock:
            for approval_id, record in list(self._records.items()):
                if record.state == PENDING:
                    if now >= record.expires_at:
                        record = replace(record, state=EXPIRED, resolved_at=now)
                        self._records[approval_id] = record
                        newly.append(replace(record))
                elif (
                    record.resolved_at is not None
                    and now >= record.resolved_at + self.retention
                    # A resolved record whose call is still running has no
                    # outcome yet and is kept until it has one.
                    and (record.state != APPROVED or record.outcome is not None)
                ):
                    del self._records[approval_id]
        return newly

    # -- reading ------------------------------------------------------------

    def get(self, approval_id: str) -> Approval | None:
        with self._lock:
            record = self._records.get(approval_id) if type(approval_id) is str else None
            return None if record is None else replace(record)

    def pending(self, now: float) -> list[Approval]:
        """Records a person can still decide, oldest first."""
        with self._lock:
            live = [replace(r) for r in self._records.values() if self._live(r, now)]
        return sorted(live, key=lambda r: (r.created_at, r.id))

    def pending_count(self, now: float, jti: str | None = None) -> int:
        with self._lock:
            return sum(
                1
                for r in self._records.values()
                if self._live(r, now) and (jti is None or r.jti == jti)
            )

    @staticmethod
    def _live(record: Approval, now: float) -> bool:
        return record.state == PENDING and now < record.expires_at
