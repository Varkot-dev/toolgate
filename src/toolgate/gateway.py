"""The gateway's decision pipeline, with no web framework in it.

`Gateway.handle_call(token, tool, args)` is the only way a tool runs. The
steps, in this order, each failing closed:

  a. Build `Call(tool, args)`. From here on only the Call's own read-only
     copy of the arguments exists: it is what is checked, hashed, stored for
     approval and finally passed to the tool. What was checked is what runs.
  b. Verify the token and ask its grant, WITHOUT spending budget.
  c. Ask operator policy. deny ends the call. approve parks it in the
     approval queue and returns "pending"; nothing runs. allow continues.
  d. `authority.authorize`: verify again and charge the budget, atomically
     with the revocation check. Only calls that are about to run are charged.
  e. Write the audit entry, THEN run the tool. If the entry cannot be
     written the tool does not run: an unaudited action is worse than a
     refused one.

`Gateway.resolve_approval` runs b to e again on the STORED call when a person
approves it, with the clock read afresh, because the token may have expired
or been revoked, policy may have changed and the budget may be gone.

What goes in the audit log
--------------------------

Every decision writes exactly one entry at the moment it is made:

    outcome                          decision   rule field
    allowed                          allow      the policy rule id
    denied by policy                 deny       the policy rule id
    denied anywhere else             deny       "<stage>: <reason>"
    parked for approval              approve    the policy rule id
    approved and released            approved   the policy rule id (+ approver)
    approved, then refused           deny       "approved by <who>, then denied: ..."
    rejected by a person             rejected   the policy rule id (+ approver)
    approval ran out of time         deny       "approval: expired"

A tool that raises does not add an entry: the "allow" entry was written
before it ran, and the log records decisions, not tool results.

Arguments never go in the log, only their hash. Everything written is
bounded and none of it is free text chosen by an unauthenticated caller:

  * Token that does not verify: jti is "unverified:" plus the first 16 hex
    digits of the SHA-256 of the presented string, actors is empty, and the
    rule is "token: <code>" with the code from a fixed list. No claim of an
    unverified token is ever copied into the log, not even its jti: until
    the signature and every claim check out, they are the attacker's text.
    The fingerprint lets an operator see that the same bad token came back.
  * Tool name: logged as given only if it is at most 128 characters from
    [A-Za-z0-9_.:/-]; otherwise the placeholder "<invalid>". Registered
    tools must have names of that form, so every tool that can run is
    logged under its real name.
  * Malformed call: tool as above and the hash of the empty argument set.
  * Reasons are cut to 200 characters with a visible "...[truncated]" mark.

Not in the log: minting, exchanging and revoking tokens (the entry format
describes tool calls), and requests that never present a token.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import json
import math
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from toolgate.approvals import (
    APPROVED,
    REJECTED,
    Approval,
    ApprovalError,
    ApprovalQueue,
    QueueFull,
    request_hash,
    valid_name,
)
from toolgate.audit import AuditEntry, AuditLog, hash_args
from toolgate.capability import Call
from toolgate.policy import ALLOW, APPROVE, DENY, Policy
from toolgate.tokens import Authority, TokenError, Verified

ALLOWED, DENIED, PENDING, ERROR = "allowed", "denied", "pending", "error"

MAX_OUTPUT_BYTES = 64 * 1024
MAX_ERROR_CHARS = 2048
MAX_REASON_CHARS = 200
INVALID_TOOL = "<invalid>"
UNVERIFIED = "unverified"
TRUNCATED = "...[truncated]"

_TOOL_NAME = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")
_MAX_FINGERPRINT_INPUT = 64 * 1024


@dataclass(frozen=True)
class CallOutcome:
    """What happened to one call.

    status       allowed | denied | pending | error
    stage        which step decided: call, token, grant, tool, policy,
                 approvals, budget, audit, approval, unavailable
    reason       short text; for stage "token" it is the TokenError code
    rule         the policy rule id, when policy was the one that decided
    approval_id  set when status is pending
    result       the tool's return value (plain JSON data) when allowed
    audit_seq    seq of the audit entry written for this decision, if any
    """

    status: str
    reason: str
    rule: str | None = None
    approval_id: str | None = None
    result: Any = None
    audit_seq: int | None = None
    stage: str = ""

    @property
    def allowed(self) -> bool:
        return self.status == ALLOWED


def bounded(text: str, limit: int) -> str:
    """Cut `text` to `limit` characters, saying so when anything was cut."""
    return text if len(text) <= limit else text[:limit] + TRUNCATED


def loggable_tool(tool: Any) -> str:
    """The tool name if it is safe to write to the log, else a placeholder."""
    return tool if type(tool) is str and _TOOL_NAME.fullmatch(tool) else INVALID_TOOL


def token_fingerprint(token: Any) -> str:
    """The audit `jti` for a token that did not verify. See the module docstring."""
    if type(token) is not str or not token or len(token) > _MAX_FINGERPRINT_INPUT:
        return UNVERIFIED
    # Domain separated, so the fingerprint of a string is never a prefix of
    # its plain SHA-256 (which is how the admin key is stored).
    digest = hashlib.sha256(
        b"toolgate token fingerprint\x00" + token.encode("utf-8", "backslashreplace")
    ).hexdigest()
    return f"{UNVERIFIED}:{digest[:16]}"


def plain_args(value: Any) -> Any:
    """A fresh mutable copy (dicts and lists) of a Call's read-only arguments."""
    if type(value) is MappingProxyType:
        return {k: plain_args(v) for k, v in value.items()}
    if type(value) is tuple:
        return [plain_args(v) for v in value]
    return value


def _run_awaitable(awaitable: Any) -> Any:
    """Drive an async tool to completion from synchronous code."""

    async def main() -> Any:
        return await awaitable

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(main())
    # Called on a thread that is running an event loop: blocking it with a
    # nested loop is not possible, so the tool gets a thread of its own.
    box: dict[str, Any] = {}

    def work() -> None:
        try:
            box["value"] = asyncio.run(main())
        except BaseException as exc:  # handed to the caller below
            box["error"] = exc

    thread = threading.Thread(target=work, name="toolgate-async-tool")
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box["value"]


@dataclass(frozen=True)
class _Who:
    """Attribution for an audit entry."""

    jti: str
    actors: tuple[str, ...]


class Gateway:
    """Owns the whole pipeline. Thread safe; tools may run concurrently."""

    def __init__(
        self,
        authority: Authority,
        policy: Policy,
        audit: AuditLog,
        approvals: ApprovalQueue,
        tools: Mapping[str, Callable[..., Any]],
        *,
        clock: Callable[[], float] = time.time,
        max_output_bytes: int = MAX_OUTPUT_BYTES,
        max_error_chars: int = MAX_ERROR_CHARS,
    ) -> None:
        if type(policy) is not Policy:
            raise ValueError("policy must be a Policy")
        if type(max_output_bytes) is not int or max_output_bytes < 1:
            raise ValueError("max_output_bytes must be a positive integer")
        if type(max_error_chars) is not int or max_error_chars < 1:
            raise ValueError("max_error_chars must be a positive integer")
        registry: dict[str, Callable[..., Any]] = {}
        for name, function in dict(tools).items():
            if loggable_tool(name) == INVALID_TOOL:
                raise ValueError(f"tool name {name!r} must match {_TOOL_NAME.pattern}")
            if not callable(function):
                raise ValueError(f"tool {name!r} is not callable")
            registry[name] = function
        self.authority = authority
        self.audit = audit
        self.approvals = approvals
        self._policy = policy
        self._tools = registry
        self._clock = clock
        self.max_output_bytes = max_output_bytes
        self.max_error_chars = max_error_chars

    # -- configuration ------------------------------------------------------

    @property
    def policy(self) -> Policy:
        return self._policy

    def set_policy(self, policy: Policy) -> None:
        """Swap the policy (a reload). Calls already past step c are not revisited."""
        if type(policy) is not Policy:
            raise ValueError("policy must be a Policy")
        self._policy = policy

    @property
    def tool_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def now(self) -> float:
        """The gateway's clock, in seconds since the epoch."""
        return self._clock()

    # -- the one way a tool runs --------------------------------------------

    def handle_call(self, token: str, tool: str, args: Any) -> CallOutcome:
        """Decide one tool call and, if everything agrees, run it."""
        self._sweep()
        try:
            call = Call(tool, args)
            hash_args(call.args)  # also refuses strings that cannot be encoded
        except (ValueError, TypeError, RecursionError):
            # The token is looked at only to say who sent the bad call.
            try:
                verified = self.authority.verify(token)
                who = _Who(verified.jti, verified.actors)
            except Exception:  # attribution only, never a decision
                who = _Who(token_fingerprint(token), ())
            return self._deny(who, loggable_tool(tool), {}, "call", "malformed call")
        return self._decide(token, call)

    def resolve_approval(self, approval_id: str, decision: str, approver: str) -> CallOutcome:
        """A person approves or rejects a pending call. Single use.

        Raises ValueError for a bad decision or approver name and
        ApprovalError (not_found, not_pending, expired) when there is nothing
        to decide. Approving releases only the stored call, after re-running
        every check; a refusal there ends the approval as denied.
        """
        if decision not in ("approve", "reject"):
            raise ValueError("decision must be approve or reject")
        if not valid_name(approver):
            raise ValueError("approver is not a valid name")
        self._sweep()
        state = APPROVED if decision == "approve" else REJECTED
        record = self.approvals.resolve(approval_id, state, approver, self._clock())
        who = _Who(record.jti, record.actors)
        if state == REJECTED:
            entry = self._append(
                who, record.call.tool, record.call.args, "rejected", record.rule, approver
            )
            outcome = CallOutcome(
                DENIED,
                f"rejected by {approver}",
                rule=record.rule,
                approval_id=record.id,
                audit_seq=None if entry is None else entry.seq,
                stage="approval",
            )
            self.approvals.finish(record.id, outcome)
            return outcome
        try:
            outcome = self._decide(record.token, record.call, approval=record)
        except BaseException:
            failed = CallOutcome(
                DENIED, "internal error", approval_id=record.id, stage="unavailable"
            )
            self.approvals.finish(record.id, failed, denied=True)
            raise
        self.approvals.finish(record.id, outcome, denied=outcome.status == DENIED)
        return outcome

    # -- reading approvals --------------------------------------------------

    def list_pending(self) -> list[Approval]:
        """Pending approvals, oldest first. For the operator only: includes arguments."""
        self._sweep()
        return self.approvals.pending(self._clock())

    def get_approval(self, approval_id: str, token: str) -> Approval:
        """The approval `approval_id`, for the holder of the token that created it.

        The token must still verify (TokenError otherwise). A wrong id and
        somebody else's id are the same answer, ApprovalError("not_found"), so
        the endpoint cannot be used to test which ids exist.
        """
        self.authority.verify(token)
        self._sweep()
        record = self.approvals.get(approval_id)
        if record is None or not hmac.compare_digest(
            record.token.encode("utf-8", "backslashreplace"),
            token.encode("utf-8", "backslashreplace"),
        ):
            raise ApprovalError("not_found")
        return record

    # -- internals ----------------------------------------------------------

    def _decide(self, token: str, call: Call, approval: Approval | None = None) -> CallOutcome:
        """Steps b to e for a fresh call, or for a stored call being approved."""
        tool, args = call.tool, call.args
        approver = None if approval is None else approval.approver
        approval_id = None if approval is None else approval.id
        # While a stored call is re-checked its token may no longer verify,
        # but who made the request was established when it was parked.
        who = (
            _Who(token_fingerprint(token), ())
            if approval is None
            else _Who(approval.jti, approval.actors)
        )

        def deny(stage: str, reason: str, rule: str | None = None) -> CallOutcome:
            return self._deny(
                who,
                tool,
                args,
                stage,
                reason,
                rule=rule,
                approver=approver,
                approval_id=approval_id,
            )

        # b. Verify and ask the grant. Nothing is charged here.
        try:
            now = self._clock()
            verified = self.authority.verify(token)
        except TokenError as exc:
            if exc.code == "unavailable":
                return deny("unavailable", "token state is unavailable")
            return deny("token", exc.code)
        except Exception:  # fail closed on anything unexpected
            return deny("unavailable", "token check failed")
        if approval is None:
            who = _Who(verified.jti, verified.actors)
        elif verified.jti != approval.jti or not hmac.compare_digest(
            request_hash(verified.jti, tool, hash_args(args)), approval.request_hash
        ):
            return deny("approval", "the stored request does not match its approval")
        if type(now) not in (int, float) or not math.isfinite(now):
            return deny("unavailable", "clock returned an invalid time")
        granted = verified.grant.decide(call, now)
        if not granted.allowed:
            return deny("grant", granted.reason)
        if tool not in self._tools:
            return deny("tool", "unknown tool")

        # c. Operator policy.
        try:
            ruling = self._policy.decide(call)
        except Exception:
            return deny("unavailable", "policy check failed")
        if ruling.effect == DENY:
            return deny("policy", ruling.reason, ruling.rule_id)
        if ruling.effect not in (ALLOW, APPROVE):
            return deny("policy", "unknown policy effect")
        if ruling.effect == APPROVE and approval is None:
            return self._park(token, verified, call, ruling.rule_id or "", ruling.reason)
        rule = ruling.rule_id or f"policy: {ruling.effect}"

        # d. Verify again and charge, in one step with the revocation check.
        try:
            authorization = self.authority.authorize(token, call)
        except TokenError as exc:
            if exc.code == "unavailable":
                return deny("unavailable", "token state is unavailable")
            return deny("token", exc.code)
        except Exception:
            return deny("unavailable", "token check failed")
        if not authorization.decision.allowed:
            reason = authorization.decision.reason
            return deny("budget" if "budget" in reason else "grant", reason)

        # e. Audit, then run. No entry, no execution.
        decision = "allow" if approval is None else "approved"
        entry = self._append(who, tool, args, decision, rule, approver)
        if entry is None:
            return CallOutcome(
                DENIED,
                "audit log unavailable; the call was not run",
                rule=ruling.rule_id,
                approval_id=approval_id,
                stage="audit",
            )
        return self._execute(call, ruling.rule_id, approval_id, entry.seq)

    def _park(
        self, token: str, verified: Verified, call: Call, rule: str, reason: str
    ) -> CallOutcome:
        who = _Who(verified.jti, verified.actors)
        try:
            record, created = self.approvals.create(
                token=token,
                jti=verified.jti,
                sub=verified.sub,
                actors=verified.actors,
                call=call,
                rule=rule,
                reason=bounded(reason, MAX_REASON_CHARS),
                now=self._clock(),
            )
        except QueueFull as exc:
            return self._deny(
                who,
                call.tool,
                call.args,
                "approvals",
                f"too many pending approvals ({exc.scope} limit)",
                rule=rule,
            )
        except Exception:
            return self._deny(who, call.tool, call.args, "unavailable", "approval queue failed")
        entry = self._append(who, call.tool, call.args, "approve", rule)
        if entry is None:
            if created:
                self.approvals.discard(record.id)
            return CallOutcome(
                DENIED, "audit log unavailable; nothing was queued", rule=rule, stage="audit"
            )
        return CallOutcome(
            PENDING,
            bounded(reason, MAX_REASON_CHARS),
            rule=rule,
            approval_id=record.id,
            audit_seq=entry.seq,
            stage="policy",
        )

    def _execute(
        self, call: Call, rule: str | None, approval_id: str | None, seq: int
    ) -> CallOutcome:
        def error(reason: str) -> CallOutcome:
            return CallOutcome(
                ERROR, reason, rule=rule, approval_id=approval_id, audit_seq=seq, stage="tool"
            )

        function = self._tools[call.tool]
        try:
            value = function(**plain_args(call.args))
            if inspect.isawaitable(value):
                value = _run_awaitable(value)
        except Exception as exc:  # a failing tool is an error, not a deny
            try:
                text = f"{type(exc).__name__}: {exc}"
            except Exception:
                text = type(exc).__name__
            return error(bounded(f"tool raised {text}", self.max_error_chars))
        try:
            text = json.dumps(value, allow_nan=False, separators=(",", ":"))
        except (TypeError, ValueError, RecursionError):
            return error("tool returned a value that is not plain JSON data; it was withheld")
        if len(text) > self.max_output_bytes:  # ensure_ascii: characters are bytes
            return error(
                f"tool output is {len(text)} bytes, over the limit of "
                f"{self.max_output_bytes}; it was withheld, not truncated"
            )
        return CallOutcome(
            ALLOWED,
            "ok",
            rule=rule,
            approval_id=approval_id,
            result=json.loads(text),
            audit_seq=seq,
            stage="policy",
        )

    def _deny(
        self,
        who: _Who,
        tool: str,
        args: Mapping[str, Any],
        stage: str,
        reason: str,
        *,
        rule: str | None = None,
        approver: str | None = None,
        approval_id: str | None = None,
    ) -> CallOutcome:
        reason = bounded(reason, MAX_REASON_CHARS)
        logged = rule if stage == "policy" and rule else f"{stage}: {reason}"
        if approver is not None:
            logged = f"approved by {approver}, then denied: {logged}"
        entry = self._append(who, tool, args, "deny", logged)
        return CallOutcome(
            DENIED,
            reason,
            rule=rule,
            approval_id=approval_id,
            audit_seq=None if entry is None else entry.seq,
            stage=stage,
        )

    def _append(
        self,
        who: _Who,
        tool: str,
        args: Mapping[str, Any],
        decision: str,
        rule: str,
        approver: str | None = None,
    ) -> AuditEntry | None:
        """Write one audit entry. None means it could not be written."""
        try:
            return self.audit.append(
                jti=who.jti,
                actors=who.actors,
                tool=loggable_tool(tool),
                args=args,
                decision=decision,
                rule=rule,
                approver=approver if decision in ("approved", "rejected") else None,
            )
        except Exception:  # the caller fails closed on None
            return None

    def _sweep(self) -> None:
        """Expire overdue approvals and log each one once. Never raises."""
        try:
            expired = self.approvals.expire(self._clock())
        except Exception:
            return
        for record in expired:
            self._append(
                _Who(record.jti, record.actors),
                record.call.tool,
                record.call.args,
                "deny",
                "approval: expired",
            )
