"""The gateway's decision pipeline, with no web framework in it.

`Gateway.handle_call(token, tool, args)` is the only way a tool runs. The
steps, in this order, each failing closed:

  a. Build `Call(tool, args)`. From here on only the Call's own read-only
     copy of the arguments exists: it is what is checked, hashed, stored for
     approval and finally passed to the tool. What was checked is what runs.
  b. Verify the token and ask its grant, WITHOUT spending budget.
  c. Ask operator policy. deny ends the call. approve parks it in the
     approval queue and returns "pending"; nothing runs. allow continues.
  d. Check that the decision can be recorded (`audit.loggable`), take one of
     the root token's in-flight slots, then `authority.authorize`: verify
     again and charge the budget, atomically with the revocation check. Only
     calls that are about to run are charged.
  e. Write the audit entry, verify the token ONCE MORE (the entry is an fsync,
     long enough for a revocation or the expiry to land), THEN run the tool.
     If the entry cannot be written the tool does not run: an unaudited
     action is worse than a refused one.

Budget. A call that was charged in d and then did not reach the tool (the
entry could not be written, the last verification failed, the tool could not
be started) gets its charge back with `authority.refund`. A call whose tool
STARTED is never refunded, whatever happens next (it raises, it times out, its
output is withheld): the side effect may already have happened.

`Gateway.resolve_approval` runs b to e again on the STORED call when a person
approves it, with the clock read afresh, because the token may have expired
or been revoked, policy may have changed and the budget may be gone.

What goes in the audit log
--------------------------

Every decision writes exactly one entry at the moment it is made:

    outcome                          decision   rule field
    allowed                          allow      the policy rule id
    denied by policy                 deny       the policy rule id
    denied anywhere else             deny       "<stage>: <fixed text or code>"
    parked for approval              approve    the policy rule id
    approved and released            approved   the policy rule id (+ approver)
    approved, then refused           deny       "approved by <who>, then denied: ..."
    rejected by a person             rejected   the policy rule id (+ approver)
    approval ran out of time         deny       "approval: expired"

A tool that raises or times out does not add an entry: the "allow" entry was
written before it ran, and the log records decisions, not tool results. (A
timeout is also reported on the Python logger "toolgate.gateway".) One path
writes two entries: "allow", then "deny" with "token: <code>; allowed at seq
<n> but not run", when the token stopped verifying while the allow entry was
being written.

Token lifecycle, written by `mint_token`, `exchange_token`, `revoke_token`:

    token minted                     allow      "token: minted by admin"
    token exchanged                  allow      "token: exchanged from <parent jti>"
    exchange refused                 deny       "exchange: <code>"
    token revoked                    allow      "token: revoked by admin"

with `tool` set to "token:mint", "token:exchange" or "token:revoke", `jti`
the new (or revoked) token id, or the parent's when an exchange is refused,
and `args_hash` the hash of {"capabilities": [...]} for an issued token and
of {} otherwise. Capability contents are never written.

Arguments never go in the log, only their hash. Everything written is
bounded and none of it is text chosen by a caller, authenticated or not.
Every string in an entry is one of: a fixed text or code from this module, a
TokenError or Decision code, a constraint operator name, a policy rule id or
reason (operator configuration), a token id or actor name from a VERIFIED
token, an approver name that passed `valid_name`, or a tool name that passed
the filter below. In particular a grant refusal is logged as "grant: <code>",
never with the human-readable reason, which quotes the caller's tool and
argument names.

  * Unverified tokens are rate limited in the log (a token bucket, by default
    20 entries a second with a burst of 100). Past that the caller is still
    refused but no entry is written for the attempt; the attempts are counted
    and one entry "unverified: N attempts suppressed" is written when the
    bucket next has room, or by `flush()` at shutdown. Decisions for verified
    tokens are never limited.

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

Not in the log: requests that never present a token.

Optional hooks (M4b), both off by default; with neither configured the
pipeline above is unchanged.

  canonicalizer  `canonicalizer(tool, args) -> (tool, args)`, e.g. a
                 toolgate.canonical.Canonicalizer. Runs before step a, so the
                 Call that is checked, stored for approval and run is built
                 from the canonical form. A CanonicalError is a refusal at
                 stage "canonical", logged as "canonical: <code>".
  provenance     a toolgate.provenance.Provenance. Before step a, for a token
                 that verifies, `prepare` resolves handle references in the
                 arguments (refused at stage "provenance", logged as
                 "provenance: <code>") and labels each argument; step c asks
                 policy with `context(jti, labels)`; every final outcome is
                 passed to `record`, which stores an allowed result and puts
                 its handle in `CallOutcome.handle`. The labels of a parked
                 call are kept with it, and the context is rebuilt from them
                 (with the session state as it is then) when it is approved.
                 Labels are computed by this process only; nothing a caller
                 sends can set one.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import inspect
import json
import logging
import math
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
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
from toolgate.audit import AuditEntry, AuditLog, hash_args, loggable
from toolgate.canonical import CODES as CANONICAL_CODES
from toolgate.canonical import CanonicalError
from toolgate.capability import DECISION_CODES, Call, Decision, Grant
from toolgate.constraints import OPS
from toolgate.policy import ALLOW, APPROVE, DENY, Policy, PolicyContext
from toolgate.provenance import CODES as PROVENANCE_CODES
from toolgate.provenance import ProvenanceError
from toolgate.tokens import Authority, Authorization, EscalationError, TokenError, Verified

ALLOWED, DENIED, PENDING, ERROR = "allowed", "denied", "pending", "error"

MAX_OUTPUT_BYTES = 64 * 1024
MAX_ERROR_CHARS = 2048
MAX_REASON_CHARS = 200
INVALID_TOOL = "<invalid>"
UNVERIFIED = "unverified"
TRUNCATED = "...[truncated]"

# Fixed `tool` labels of the token lifecycle entries, and of the summary entry.
TOKEN_MINT, TOKEN_EXCHANGE, TOKEN_REVOKE = "token:mint", "token:exchange", "token:revoke"
AUDIT_SUMMARY = "audit:summary"
# CallOutcome.code values set by the gateway itself (grant refusals carry a
# capability.DECISION_CODES value instead).
IN_FLIGHT_LIMIT, TOOL_TIMEOUT = "in_flight_limit", "tool_timeout"

DEFAULT_UNVERIFIED_AUDIT_RATE = 20
DEFAULT_UNVERIFIED_AUDIT_BURST = 100

_TOOL_NAME = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")
_MAX_FINGERPRINT_INPUT = 64 * 1024
_LOG = logging.getLogger("toolgate.gateway")
# Reasons `Authority.authorize` gives for a refusal it made itself, as codes.
_AUTHORIZE_CODES = {
    "budget exhausted": "budget_exhausted",
    "budget ledger has no record of this delegation path": "budget_unknown_path",
    "expired during authorization": "expired_during_authorization",
}


class AuditUnavailable(Exception):
    """A token was issued but could not be recorded, so it was revoked again."""


class _NotStarted(Exception):
    """The tool could not be started at all (no thread)."""


@dataclass(frozen=True)
class CallOutcome:
    """What happened to one call.

    status       allowed | denied | pending | error
    stage        which step decided: call, token, grant, tool, policy,
                 approvals, budget, audit, approval, unavailable, limit
    reason       short text; for stage "token" it is the TokenError code
    rule         the policy rule id, when policy was the one that decided
    approval_id  set when status is pending
    result       the tool's return value (plain JSON data) when allowed
    audit_seq    seq of the audit entry written for this decision, if any
    code         machine-readable detail where there is one, else "": a
                 capability.DECISION_CODES value for a grant refusal,
                 "in_flight_limit", "tool_timeout"
    authenticated  False when the token presented did not verify; such a
                 caller is told nothing about the log (see server.py)
    handle       with a provenance layer in value mode: the handle under
                 which the result is stored, for later references
    """

    status: str
    reason: str
    rule: str | None = None
    approval_id: str | None = None
    result: Any = None
    audit_seq: int | None = None
    stage: str = ""
    code: str = ""
    authenticated: bool = True
    handle: str | None = None

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
    """Attribution for an audit entry. `verified` is False for a token fingerprint."""

    jti: str
    actors: tuple[str, ...]
    verified: bool = True


def _positive_number(value: Any, what: str) -> int | float:
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{what} must be a positive number")
    return value


def _capability_args(capabilities: Any) -> dict[str, Any]:
    """What a lifecycle entry hashes for an issued token: its capabilities.

    Only the hash reaches the log. Capabilities that cannot be written as
    canonical JSON (a constraint value no call could carry) hash as {}.
    """
    try:
        data = {"capabilities": [c.to_dict() for c in capabilities]}
        hash_args(data)
    except Exception:
        return {}
    return data


def _grant_log(decision: Decision) -> str:
    """The loggable form of a grant refusal: a fixed code, never `decision.reason`."""
    code = decision.code if decision.code in DECISION_CODES else "denied"
    if code == "constraint_failed":
        # The reason ends "fails <op>". Only a name from the closed set of
        # operators is copied, so nothing of the caller's can ride along.
        op = decision.reason.rpartition(" fails ")[2]
        if op in OPS:
            return f"{code} ({op})"
    return code


class Gateway:
    """Owns the whole pipeline. Thread safe; tools may run concurrently.

    Optional limits, all keyword-only. The first three default to "off" so
    that code built on Gateway keeps its behaviour; `toolgate.server.build`
    turns them on with the defaults in the example config.

      max_in_flight_per_root  most tool executions running at once under one
                              ROOT token (all its exchanged children count
                              together). Over it a call is denied, stage
                              "limit", code "in_flight_limit", nothing charged.
                              Calls released by a person's approval count but
                              are not refused. None: no limit.
      tool_timeout            seconds the caller waits for a tool. The tool
                              then runs on a thread of its own; after the
                              timeout the outcome is an error with code
                              "tool_timeout". A Python thread cannot be
                              killed: the tool may still finish in the
                              background, it keeps its in-flight slot until it
                              does, and its budget is not refunded. None: the
                              tool runs on the calling thread with no timeout.
      tool_error_detail       True: a tool's exception text is returned in the
                              outcome (cut to max_error_chars). False: only
                              the exception type name and a fixed message.
      unverified_audit_rate,  token bucket for audit entries about tokens that
      unverified_audit_burst  did not verify (see the module docstring).
                              rate None: no limit.
    """

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
        max_in_flight_per_root: int | None = None,
        tool_timeout: int | float | None = None,
        tool_error_detail: bool = True,
        unverified_audit_rate: int | float | None = DEFAULT_UNVERIFIED_AUDIT_RATE,
        unverified_audit_burst: int = DEFAULT_UNVERIFIED_AUDIT_BURST,
        canonicalizer: Callable[[str, Any], tuple[str, Any]] | None = None,
        provenance: Any = None,
    ) -> None:
        if type(policy) is not Policy:
            raise ValueError("policy must be a Policy")
        if type(max_output_bytes) is not int or max_output_bytes < 1:
            raise ValueError("max_output_bytes must be a positive integer")
        if type(max_error_chars) is not int or max_error_chars < 1:
            raise ValueError("max_error_chars must be a positive integer")
        if max_in_flight_per_root is not None and (
            type(max_in_flight_per_root) is not int or max_in_flight_per_root < 1
        ):
            raise ValueError("max_in_flight_per_root must be a positive integer or None")
        if tool_timeout is not None:
            _positive_number(tool_timeout, "tool_timeout")
        if type(tool_error_detail) is not bool:
            raise ValueError("tool_error_detail must be true or false")
        if unverified_audit_rate is not None:
            _positive_number(unverified_audit_rate, "unverified_audit_rate")
        if type(unverified_audit_burst) is not int or unverified_audit_burst < 1:
            raise ValueError("unverified_audit_burst must be a positive integer")
        if canonicalizer is not None and not callable(canonicalizer):
            raise ValueError("canonicalizer must be callable")
        if provenance is not None and not all(
            callable(getattr(provenance, name, None)) for name in ("prepare", "context", "record")
        ):
            raise ValueError("provenance must have prepare, context and record")
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
        self.max_in_flight_per_root = max_in_flight_per_root
        self.tool_timeout = tool_timeout
        self.tool_error_detail = tool_error_detail
        self.unverified_audit_rate = unverified_audit_rate
        self.unverified_audit_burst = unverified_audit_burst
        self.canonicalizer = canonicalizer
        self.provenance = provenance
        # approval id -> (session key, argument labels, handles used), for M4b
        self._parked_labels: dict[str, tuple[str, Any, Any]] = {}
        # One lock for the small bookkeeping below. It is never held while a
        # tool runs; it is held across the write of a summary entry.
        self._state = threading.Lock()
        self._in_flight: dict[str, int] = {}
        self._bucket = float(unverified_audit_burst)
        self._bucket_time: float | None = None
        self._suppressed = 0
        # Work that failed and is tried again on the next sweep: expiry
        # entries that could not be written, outcomes that could not be stored.
        self._unlogged_expiries: list[Approval] = []
        self._unfinished: list[tuple[str, CallOutcome, bool]] = []

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

    def in_flight(self, root: str) -> int:
        """How many tool executions are running under the root token id `root`."""
        with self._state:
            return self._in_flight.get(root, 0)

    def suppressed_unverified(self) -> int:
        """Unverified attempts refused since the last summary entry, not yet logged."""
        with self._state:
            return self._suppressed

    def flush(self) -> None:
        """Write the pending "attempts suppressed" summary now. Call at shutdown.

        Never raises. If the entry cannot be written the count is kept.
        """
        with self._state:
            self._write_summary()

    # -- the one way a tool runs --------------------------------------------

    def handle_call(self, token: str, tool: str, args: Any) -> CallOutcome:
        """Decide one tool call and, if everything agrees, run it.

        Always returns a CallOutcome; no exception from the arguments, the
        token, the policy, the stores or the tool escapes.
        """
        self._sweep()
        key: str | None = None
        labels: Any = None
        used: Any = None
        if self.provenance is not None:
            try:
                key = self.authority.verify(token).jti
            except Exception:
                key = None  # step b refuses it; nothing is resolved for it
            if key is not None:
                try:
                    args, labels, used = self.provenance.prepare(key, tool, args)
                except ProvenanceError as exc:
                    code = exc.code if exc.code in PROVENANCE_CODES else "bad_reference"
                    return self._deny(
                        self._attribute(token),
                        loggable_tool(tool),
                        {},
                        "provenance",
                        f"argument refused: {code}",
                        log=code,
                        code=code,
                    )
                except Exception:
                    return self._deny(
                        self._attribute(token),
                        loggable_tool(tool),
                        {},
                        "unavailable",
                        "provenance check failed",
                    )
        if self.canonicalizer is not None:
            try:
                tool, args = self.canonicalizer(tool, args)
            except CanonicalError as exc:
                code = exc.code if exc.code in CANONICAL_CODES else "refused"
                return self._deny(
                    self._attribute(token),
                    loggable_tool(tool),
                    {},
                    "canonical",
                    f"argument refused by canonicalization: {code}",
                    log=code,
                    code=code,
                )
            except Exception:
                return self._deny(
                    self._attribute(token),
                    loggable_tool(tool),
                    {},
                    "canonical",
                    "canonicalization failed",
                )
        try:
            call = Call(tool, args)
            hash_args(call.args)  # also refuses strings that cannot be encoded
        except Exception:
            # Not only ValueError: a mapping handed in from outside can raise
            # anything at all while it is being copied. The token is looked at
            # only to say who sent the bad call.
            return self._deny(
                self._attribute(token), loggable_tool(tool), {}, "call", "malformed call"
            )
        try:
            if key is None:
                return self._decide(token, call)
            context = self.provenance.context(key, labels)
            outcome = self._decide(token, call, context=context, labels=(key, labels, used))
            return self._provenance_record(key, call, outcome, labels, used)
        except Exception:
            # Nothing below is expected to raise. If something does, it is
            # still a refusal with an entry, not a traceback for the caller.
            return self._deny(
                self._attribute(token), call.tool, call.args, "unavailable", "internal error"
            )

    def resolve_approval(self, approval_id: str, decision: str, approver: str) -> CallOutcome:
        """A person approves or rejects a pending call. Single use.

        Raises ValueError for a bad decision or approver name and
        ApprovalError (not_found, not_pending, expired) when there is nothing
        to decide. Approving releases only the stored call, after re-running
        every check; a refusal there ends the approval as denied.
        """
        # Exactly the str "approve" or "reject". An object that merely
        # compares equal to one of them is not a decision.
        if type(decision) is not str or decision not in ("approve", "reject"):
            raise ValueError("decision must be approve or reject")
        if not valid_name(approver):
            raise ValueError("approver is not a valid name")
        self._sweep()
        state = APPROVED if decision == "approve" else REJECTED
        record = self.approvals.resolve(approval_id, state, approver, self._clock())
        who = _Who(record.jti, record.actors)
        with self._state:
            parked = self._parked_labels.pop(record.id, None)
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
            self._finish(record.id, outcome, False)
            if parked is not None:
                outcome = self._provenance_record(parked[0], record.call, outcome, *parked[1:])
            return outcome
        try:
            if parked is None:
                outcome = self._decide(record.token, record.call, approval=record)
            else:
                context = self.provenance.context(parked[0], parked[1])
                outcome = self._decide(record.token, record.call, approval=record, context=context)
        except BaseException:
            failed = CallOutcome(
                DENIED, "internal error", approval_id=record.id, stage="unavailable"
            )
            self._finish(record.id, failed, True)
            raise
        self._finish(record.id, outcome, outcome.status == DENIED)
        if parked is not None:
            outcome = self._provenance_record(parked[0], record.call, outcome, *parked[1:])
        return outcome

    def _provenance_record(
        self, key: str, call: Call, outcome: CallOutcome, labels: Any, used: Any
    ) -> CallOutcome:
        """Hand a final (or pending) outcome to the provenance layer; attach the handle."""
        handle = self.provenance.record(
            key, call.tool, plain_args(call.args), outcome, labels, used
        )
        return outcome if handle is None else replace(outcome, handle=handle)

    # -- token lifecycle, audited -------------------------------------------

    def mint_token(
        self, sub: str, grant: Grant, actor: str, ttl: int | float
    ) -> tuple[str, Verified]:
        """`authority.mint`, with an audit entry. Returns (token, what it says).

        Raises what `Authority.mint` raises, and AuditUnavailable if the entry
        could not be written; the new token is revoked again in that case.
        """
        token = self.authority.mint(sub, grant, actor, ttl)
        return token, self._issued(token, TOKEN_MINT, "token: minted by admin")

    def exchange_token(
        self,
        parent_token: str,
        child_capabilities: Any,
        actor: str,
        ttl: int | float,
    ) -> tuple[str, Verified]:
        """`authority.exchange`, with an audit entry for a success AND a refusal.

        A refusal is logged under the parent token's id (or its fingerprint if
        it does not verify) as "exchange: <code>": a TokenError code,
        "escalation", "invalid_request" or "internal". The checker's sentence
        is not logged; it quotes the requested tool and argument names. Raises
        what `Authority.exchange` raises, and AuditUnavailable as `mint_token`.
        """
        try:
            token = self.authority.exchange(parent_token, child_capabilities, actor, ttl)
        except Exception as exc:
            if isinstance(exc, TokenError):
                code = exc.code
            elif isinstance(exc, EscalationError):
                code = "escalation"
            elif isinstance(exc, (ValueError, TypeError)):
                code = "invalid_request"
            else:
                code = "internal"
            self._append(
                self._attribute(parent_token), TOKEN_EXCHANGE, {}, "deny", f"exchange: {code}"
            )
            raise
        verified = self.authority.verify(token)
        parent = verified.chain[-1] if verified.chain else "unknown"
        return token, self._issued(token, TOKEN_EXCHANGE, f"token: exchanged from {parent}")

    def revoke_token(self, jti: str) -> AuditEntry | None:
        """`authority.revoke`, with an audit entry. Returns the entry, or None.

        The revocation is never held back by the log: if the entry cannot be
        written the token is revoked all the same and None is returned. An id
        that is not a plain printable name is logged as a hash of itself.
        """
        self.authority.revoke(jti)
        if valid_name(jti):
            logged = jti
        else:
            digest = hashlib.sha256(jti.encode("utf-8", "backslashreplace")).hexdigest()
            logged = f"sha256:{digest[:32]}"
        return self._append(_Who(logged, ()), TOKEN_REVOKE, {}, "allow", "token: revoked by admin")

    def _issued(self, token: str, label: str, rule: str) -> Verified:
        """Log a freshly issued token, or take it back if that is not possible."""
        verified = self.authority.verify(token)
        entry = self._append(
            _Who(verified.jti, verified.actors),
            label,
            _capability_args(verified.grant.capabilities),
            "allow",
            rule,
        )
        if entry is None:
            # The token string is not handed out either way.
            with contextlib.suppress(Exception):
                self.authority.revoke(verified.jti)
            raise AuditUnavailable("audit log unavailable; no token was issued")
        return verified

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

    def _attribute(self, token: Any) -> _Who:
        """Who to name in an entry: the verified token, else its fingerprint."""
        try:
            verified = self.authority.verify(token)
            return _Who(verified.jti, verified.actors)
        except Exception:  # attribution only, never a decision
            return _Who(token_fingerprint(token), (), False)

    def _decide(
        self,
        token: str,
        call: Call,
        approval: Approval | None = None,
        context: PolicyContext | None = None,
        labels: tuple[str, Any, Any] | None = None,
    ) -> CallOutcome:
        """Steps b to e for a fresh call, or for a stored call being approved.

        `context` is the provenance context for policy (None without a
        provenance layer); `labels` is kept with the call if it is parked.
        """
        tool, args = call.tool, call.args
        approver = None if approval is None else approval.approver
        approval_id = None if approval is None else approval.id
        # While a stored call is re-checked its token may no longer verify,
        # but who made the request was established when it was parked.
        who = (
            _Who(token_fingerprint(token), (), False)
            if approval is None
            else _Who(approval.jti, approval.actors)
        )

        def deny(
            stage: str,
            reason: str,
            rule: str | None = None,
            *,
            log: str | None = None,
            code: str = "",
        ) -> CallOutcome:
            return self._deny(
                who,
                tool,
                args,
                stage,
                reason,
                rule=rule,
                approver=approver,
                approval_id=approval_id,
                log=log,
                code=code,
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
            # The reason quotes the caller's tool and argument names: it goes
            # back to the caller, and only the code goes to the log.
            return deny("grant", granted.reason, log=_grant_log(granted), code=granted.code)
        # The callable is taken now, once. A registry that changes later in
        # this call cannot turn "known" into a KeyError after the charge.
        function = self._tools.get(tool)
        if function is None:
            return deny("tool", "unknown tool")

        # c. Operator policy.
        try:
            ruling = (
                self._policy.decide(call) if context is None else self._policy.decide(call, context)
            )
        except Exception:
            return deny("unavailable", "policy check failed")
        if ruling.effect == DENY:
            return deny("policy", ruling.reason, ruling.rule_id)
        if ruling.effect not in (ALLOW, APPROVE):
            return deny("policy", "unknown policy effect")
        if ruling.effect == APPROVE and approval is None:
            parked = self._park(token, verified, call, ruling.rule_id or "", ruling.reason)
            if labels is not None and parked.status == PENDING and parked.approval_id:
                with self._state:
                    self._parked_labels[parked.approval_id] = labels
            return parked
        rule = ruling.rule_id or f"policy: {ruling.effect}"

        # d. Everything that can refuse without spending budget goes first:
        # can the decision be recorded at all, and is there a free slot.
        try:
            unloggable = loggable(loggable_tool(tool), args, who.actors) is not None
        except Exception:
            unloggable = True
        if unloggable:
            return deny(
                "audit", "the decision cannot be recorded; the call was not run", log="unloggable"
            )
        root = verified.chain[0] if verified.chain else verified.jti
        if not self._enter(root, force=approval is not None):
            return deny(
                "limit",
                "too many calls in flight for this token; retry shortly",
                log="in_flight",
                code=IN_FLIGHT_LIMIT,
            )
        handed_over = False  # True once _execute owns the slot
        try:
            # Verify again and charge, in one step with the revocation check.
            try:
                authorization = self.authority.authorize(token, call)
            except TokenError as exc:
                if exc.code == "unavailable":
                    return deny("unavailable", "token state is unavailable")
                return deny("token", exc.code)
            except Exception:
                return deny("unavailable", "token check failed")
            refused = authorization.decision
            if not refused.allowed:
                if refused.code in DECISION_CODES:  # the grant said no after all
                    return deny("grant", refused.reason, log=_grant_log(refused), code=refused.code)
                code = _AUTHORIZE_CODES.get(refused.reason, "denied")
                stage = "budget" if code.startswith("budget") else "grant"
                return deny(stage, refused.reason, log=code, code=code)

            # e. Audit, verify once more, then run. No entry, no execution.
            # From here until the tool starts, every refusal gives the charge
            # back: an audit outage must not drain budgets while nothing runs.
            decision = "allow" if approval is None else "approved"
            entry = self._append(who, tool, args, decision, rule, approver)
            if entry is None:
                self._refund(authorization)
                return CallOutcome(
                    DENIED,
                    "audit log unavailable; the call was not run",
                    rule=ruling.rule_id,
                    approval_id=approval_id,
                    stage="audit",
                )
            # Writing the entry is an fsync. A revocation or the expiry can
            # land in that time, so the token is checked one last time.
            late = f"; allowed at seq {entry.seq} but not run"
            try:
                self.authority.verify(token)
            except TokenError as exc:
                self._refund(authorization)
                if exc.code == "unavailable":
                    text = "token state is unavailable"
                    return deny("unavailable", text, log=text + late)
                return deny("token", exc.code, log=exc.code + late)
            except Exception:
                self._refund(authorization)
                return deny("unavailable", "token check failed", log="token check failed" + late)
            handed_over = True
            try:
                return self._execute(
                    function,
                    call,
                    ruling.rule_id,
                    approval_id,
                    entry.seq,
                    lambda: self._leave(root),
                )
            except _NotStarted:
                self._refund(authorization)
                text = "the tool could not be started"
                return deny("unavailable", text, log=text + late)
        finally:
            if not handed_over:
                self._leave(root)

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
                root=verified.chain[0] if verified.chain else verified.jti,
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
        self,
        function: Callable[..., Any],
        call: Call,
        rule: str | None,
        approval_id: str | None,
        seq: int,
        release: Callable[[], None],
    ) -> CallOutcome:
        """Run the tool. Calls `release` exactly once, when the tool has ended.

        Nothing here is ever refunded: once the tool has started, its side
        effect may have happened, whether it then returns, raises or is still
        running when the caller stops waiting. The one exception is
        _NotStarted, raised (after `release`) when no thread could be started.
        """

        def error(reason: str, code: str = "") -> CallOutcome:
            return CallOutcome(
                ERROR,
                reason,
                rule=rule,
                approval_id=approval_id,
                audit_seq=seq,
                stage="tool",
                code=code,
            )

        def run() -> tuple[bool, Any]:
            try:
                value = function(**plain_args(call.args))
                if inspect.isawaitable(value):
                    value = _run_awaitable(value)
            except Exception as exc:  # a failing tool is an error, not a deny
                return False, exc
            return True, value

        if self.tool_timeout is None:
            try:
                ok, value = run()
            finally:
                release()
        else:
            box: list[tuple[bool, Any]] = []
            done = threading.Event()

            def work() -> None:
                try:
                    box.append(run())
                except BaseException as exc:  # reported to the waiting caller
                    box.append((False, exc))
                finally:
                    release()
                    done.set()

            # A daemon thread: a tool that never returns must not keep the
            # process from exiting. It cannot be killed, only abandoned.
            thread = threading.Thread(target=work, name="toolgate-tool", daemon=True)
            try:
                thread.start()
            except Exception:
                release()
                raise _NotStarted from None
            if not done.wait(self.tool_timeout):
                _LOG.error(
                    "tool %s (audit seq %d) did not finish within %s seconds; "
                    "it may still be running",
                    call.tool,
                    seq,
                    self.tool_timeout,
                )
                return error(
                    f"tool did not finish within {self.tool_timeout} seconds; it may still "
                    "complete in the background, and its budget is not refunded",
                    TOOL_TIMEOUT,
                )
            ok, value = box[0]
        if not ok:
            name = bounded(type(value).__name__, 128)
            if not self.tool_error_detail:
                # The text of a tool's exception can hold paths, hosts and
                # connection strings. The caller learns the kind of failure.
                return error(f"tool raised {name}; details are withheld")
            try:
                text = f"{name}: {value}"
            except Exception:
                text = name
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

    def _enter(self, root: str, *, force: bool = False) -> bool:
        """Take an in-flight slot for `root`. False if it has none left."""
        with self._state:
            running = self._in_flight.get(root, 0)
            limit = self.max_in_flight_per_root
            if limit is not None and running >= limit and not force:
                return False
            self._in_flight[root] = running + 1
            return True

    def _leave(self, root: str) -> None:
        with self._state:
            running = self._in_flight.get(root, 0) - 1
            if running > 0:
                self._in_flight[root] = running
            else:
                self._in_flight.pop(root, None)

    def _refund(self, authorization: Authorization) -> None:
        """Give a charge back. If that fails the budget stays spent: fail closed."""
        with contextlib.suppress(Exception):
            self.authority.refund(authorization)

    def _finish(self, approval_id: str, outcome: CallOutcome, denied: bool) -> None:
        """Store how an approval ended. Never raises.

        By now the tool may have run, so a queue that cannot store the outcome
        must not turn the answer into an exception. The outcome is kept and
        stored on a later sweep: an approved record with no outcome is never
        evicted, so giving up would leave it in the queue for good.
        """
        try:
            self.approvals.finish(approval_id, outcome, denied=denied)
        except ApprovalError:
            pass  # gone, or already finished: nothing left to store
        except Exception:
            with self._state:
                self._unfinished.append((approval_id, outcome, denied))

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
        log: str | None = None,
        code: str = "",
    ) -> CallOutcome:
        """Refuse, with one entry. `log` replaces `reason` in the entry.

        `reason` goes to the caller. It is written to the log only when no
        `log` is given, and every caller that passes none passes a fixed text
        or a TokenError code. A reason that can quote the caller MUST come
        with a `log`.
        """
        reason = bounded(reason, MAX_REASON_CHARS)
        text = reason if log is None else bounded(log, MAX_REASON_CHARS)
        logged = rule if stage == "policy" and rule else f"{stage}: {text}"
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
            code=code,
            authenticated=who.verified,
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
        """Write one audit entry. None means it could not be written.

        An entry about a token that did not verify must first get through the
        token bucket; one that does not is counted, not written.
        """
        if not who.verified and not self._admit_unverified():
            return None
        return self._write(who, tool, args, decision, rule, approver)

    def _write(
        self,
        who: _Who,
        tool: str,
        args: Mapping[str, Any],
        decision: str,
        rule: str,
        approver: str | None = None,
    ) -> AuditEntry | None:
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

    # -- the token bucket for unverified tokens -----------------------------

    def _refill(self) -> None:
        """Add the tokens earned since the last look. Caller holds the lock."""
        rate = self.unverified_audit_rate
        if rate is None:
            return
        try:
            now = self._clock()
        except Exception:
            return
        if type(now) not in (int, float) or not math.isfinite(now):
            return
        if self._bucket_time is not None and now > self._bucket_time:
            earned = (now - self._bucket_time) * rate
            self._bucket = min(float(self.unverified_audit_burst), self._bucket + earned)
        self._bucket_time = now  # also when the clock stepped back: nothing is earned

    def _write_summary(self) -> bool:
        """Write "N attempts suppressed" if N > 0. Caller holds the lock."""
        if self._suppressed == 0:
            return True
        entry = self._write(
            _Who(UNVERIFIED, (), False),
            AUDIT_SUMMARY,
            {},
            "deny",
            f"unverified: {self._suppressed} attempts suppressed",
        )
        if entry is None:
            return False
        self._suppressed = 0
        return True

    def _admit_unverified(self) -> bool:
        """May one more entry about an unverified token be written now?"""
        if self.unverified_audit_rate is None:
            return True
        with self._state:
            self._refill()
            # What was dropped earlier is accounted for before anything new.
            if self._suppressed and self._bucket >= 1 and self._write_summary():
                self._bucket -= 1
            if self._bucket >= 1:
                self._bucket -= 1
                return True
            self._suppressed += 1
            return False

    def _flush_suppressed(self) -> None:
        """Write the summary if there is one and the bucket has room."""
        if self.unverified_audit_rate is None:
            return
        with self._state:
            if not self._suppressed:
                return
            self._refill()
            if self._bucket >= 1 and self._write_summary():
                self._bucket -= 1

    # -- housekeeping -------------------------------------------------------

    def _sweep(self) -> None:
        """Expire overdue approvals and log each one once. Never raises.

        `approvals.expire` reports a record exactly once, and by then it is
        already marked expired. So an expiry whose entry cannot be written is
        remembered here and written by a later sweep instead of being lost.
        The same goes for an outcome the queue could not store.
        """
        try:
            expired = self.approvals.expire(self._clock())
        except Exception:
            expired = []
        with self._state:
            todo = self._unlogged_expiries + expired
            unfinished = self._unfinished
            self._unlogged_expiries, self._unfinished = [], []
        unlogged = [
            record
            for record in todo
            if self._append(
                _Who(record.jti, record.actors),
                record.call.tool,
                record.call.args,
                "deny",
                "approval: expired",
            )
            is None
        ]
        still: list[tuple[str, CallOutcome, bool]] = []
        for approval_id, outcome, denied in unfinished:
            try:
                self.approvals.finish(approval_id, outcome, denied=denied)
            except ApprovalError:
                pass
            except Exception:
                still.append((approval_id, outcome, denied))
        if unlogged or still:
            with self._state:
                self._unlogged_expiries = unlogged + self._unlogged_expiries
                self._unfinished = still + self._unfinished
        self._flush_suppressed()
