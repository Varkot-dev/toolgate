"""Tokens: mint, verify, exchange (delegate), revoke and authorize.

A token is a JWT signed with Ed25519 (JWS algorithm "EdDSA"). Its claims:

    iss    who signed it (this gateway's token service)
    aud    the one gateway the token is for
    sub    the principal (the user). Never changes down a delegation chain.
    act    who is acting, nested in the RFC 8693 style: {"sub": agent, "act": {...}}
    iat    issued at, seconds since the epoch
    exp    expiry, seconds since the epoch; also the grant's expires_at
    jti    this token's id
    caps   the capabilities, as written by Capability.to_dict
    chain  ids of the ancestor tokens, root first; empty for a root token
    der    der[i][k] is the index of the capability in ancestor chain[k] that
           capability i was derived from. It is the path the budget is charged
           along.

The rules this module enforces:

  * A child token is only signed after check_attenuation accepted it, its
    expiry is never later than its parent's, and `sub` is copied unchanged.
  * Verification trusts nothing in the token header: the algorithm is pinned,
    the header must be exactly {"alg": "EdDSA", "typ": "JWT"}.
  * The grant used for a decision is always rebuilt from the signed bytes.
  * Revoking a token id invalidates that token and every descendant, because
    every descendant carries the id in `chain`.
  * A call is charged to the capability that permits it and to every ancestor
    capability on its `der` path, atomically (see store.py).
  * Anything unexpected is a refusal (TokenError), never an acceptance.

These are bearer tokens: whoever holds the string can use it. Binding a token
to a holder key (DPoP style) is a later milestone.

Known limits
------------

  * Bearer tokens: there is no proof of possession yet, so a stolen token
    works for the thief until it expires or is revoked.
  * The actor name is self-declared attribution. Whoever calls mint or
    exchange picks it, it is recorded for the audit log, and it is never used
    for a decision.
  * A clock set backwards can revive an expired token (unless the store has
    pruned it in the meantime). Expiry is only as good as the clock.
  * First-fit derivation can strand budget. A child capability is bound to the
    first parent capability that covers it. If that one is exhausted the child
    gets nothing, even if another parent capability that also covers it still
    has budget left.
  * With overlapping capabilities a limited one does not cap an unlimited one.
    A call both permit is still allowed by the unlimited capability once the
    limited one is spent. Grant writers must not rely on a limited capability
    to bound an overlapping broader one.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import json
import math
import re
import secrets
import threading
import time
import weakref
from collections import OrderedDict
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jwt import PyJWS
from jwt.exceptions import InvalidAlgorithmError, InvalidSignatureError, PyJWTError

from toolgate.attenuation import check_attenuation
from toolgate.capability import Call, Capability, Decision, Grant
from toolgate.constraints import Constraint
from toolgate.store import Entry, Store

ALGORITHM = "EdDSA"
_HEADER = {"alg": ALGORITHM, "typ": "JWT"}
_CLAIMS = frozenset({"iss", "aud", "sub", "act", "iat", "exp", "jti", "caps", "chain", "der"})
# header "." payload "." signature, base64url without padding. The signature
# part may be empty only so that an unsigned token is reported as a bad
# algorithm or bad signature instead of as noise.
_COMPACT = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_MAX_TOKEN_CHARS = 64 * 1024
_MAX_CAPABILITIES = 256
_MAX_NAME_CHARS = 256
_MAX_PRINCIPAL_CHARS = 128  # `sub` and actor names; they end up in the audit log
# Limits on what one exchange may ask for, checked before the attenuation
# check, whose cost grows with (parent constraints x child constraints) for
# every (parent capability, child capability) pair. The byte limit refuses
# nothing that could have been signed: a larger request cannot fit in
# _MAX_TOKEN_CHARS once it is base64 encoded.
_MAX_CONSTRAINTS = 64  # per capability
_MAX_REQUEST_BYTES = 48 * 1024  # all requested capabilities, serialized
# The verify cache (see Authority) keeps at most this many tokens, and never
# one longer than _MAX_CACHED_CHARS, so it holds at most about 4 MB of keys.
DEFAULT_VERIFY_CACHE_SIZE = 256
_MAX_CACHED_CHARS = 16 * 1024


class TokenError(Exception):
    """A token was refused. `code` is short and machine readable.

    Codes: malformed, bad_algorithm, bad_signature, wrong_issuer,
    wrong_audience, expired, not_yet_valid, depth_exceeded, revoked,
    unknown_token, too_many_children, unavailable.

    "unavailable" means the store or the clock failed. It says nothing about
    the token, and it is still a refusal: the caller must deny, and may retry.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class EscalationError(Exception):
    """An exchange asked for a child grant the parent grant does not cover."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RequestTooLarge(TokenError, ValueError):
    """An exchange asked for more than the size limits allow.

    The code is "malformed". It is also a ValueError, because that is what
    exchange has always raised for a request it cannot read.
    """

    def __init__(self, detail: str) -> None:
        super().__init__("malformed", detail)


@dataclass(frozen=True)
class Verified:
    """What a token says, after its signature and every claim were checked.

    A record returned by `Authority.verify` is also a receipt: it can be
    handed back to that same Authority's `recheck` and `authorize`, which then
    skip the signature and the claim parsing. They do not trust the fields of
    the record handed back. The Authority keeps its own private copy of every
    record it returns and decides from that copy; the record handed back is
    only used to find it. A record built by hand, copied (for example with
    dataclasses.replace), returned by another Authority, or with a field
    swapped by object.__setattr__ is refused with TokenError "malformed".
    """

    jti: str
    sub: str  # the principal; identical at every hop of a chain
    actors: tuple[str, ...]  # newest first: this token's actor, then its delegators
    grant: Grant  # rebuilt from the signed bytes
    chain: tuple[str, ...]  # ancestor token ids, root first
    der: tuple[tuple[int, ...], ...]  # der[i][k]: capability index in chain[k]
    exp: int | float
    iat: int | float

    @property
    def depth(self) -> int:
        """Number of delegation steps between the root token and this one."""
        return len(self.chain)

    def budget_path(self, capability: int) -> list[Entry]:
        """Ledger entries one call under `capability` is charged to.

        This token's own entry first, then its parent's, up to the root.
        """
        indices = self.der[capability]
        path: list[Entry] = [(self.jti, capability)]
        for k in range(len(self.chain) - 1, -1, -1):
            path.append((self.chain[k], indices[k]))
        return path


@dataclass(frozen=True)
class Authorization:
    """Result of `Authority.authorize`: the decision and the verified token.

    Truthy only if the call is allowed. Also unpacks as (decision, verified).
    """

    decision: Decision
    verified: Verified

    def __bool__(self) -> bool:
        return self.decision.allowed

    def __iter__(self) -> Iterator[Any]:
        return iter((self.decision, self.verified))


# ---------------------------------------------------------------------------
# Strict parsing helpers
# ---------------------------------------------------------------------------


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """json object hook that refuses duplicate keys.

    Python's json keeps the last of two equal keys and says nothing. Two
    parsers that disagree about which one wins is how a token can show one
    grant to the checker and another to whatever reads it next.
    """
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):  # "1e999" would otherwise parse to infinity
        raise ValueError("number out of range")
    return value


def _loads(data: bytes) -> Any:
    """Parse JSON bytes strictly: UTF-8, no duplicate keys, no NaN or Infinity."""
    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_unique_keys,
        parse_constant=_no_constant,
        parse_float=_finite_float,
    )


def _dumps(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), allow_nan=False).encode("ascii")


def _b64decode(segment: str) -> bytes:
    """Decode unpadded base64url and insist on the one canonical spelling."""
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != segment:
        raise binascii.Error("non-canonical base64url")
    return raw


def _is_time(value: Any) -> bool:
    """An int or a finite float. bool is an int subclass and is refused."""
    return type(value) is int or (type(value) is float and math.isfinite(value))


def _is_name(value: Any) -> bool:
    return type(value) is str and 0 < len(value) <= _MAX_NAME_CHARS


def _is_encodable(value: str) -> bool:
    """False for text with lone surrogates, which UTF-8 cannot carry."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _is_id(value: Any) -> bool:
    """A token id: a name the store can actually be asked about."""
    return _is_name(value) and _is_encodable(value)


def _is_principal(value: Any) -> bool:
    """A `sub` or actor name the audit log can record and a person can read.

    Exact str, 1 to 128 characters, all printable. str.isprintable is False
    for control characters (NUL, newline, escape), for invisible format
    characters such as bidi overrides, and for lone surrogates.
    """
    return type(value) is str and 0 < len(value) <= _MAX_PRINCIPAL_CHARS and value.isprintable()


def _bad(detail: str) -> TokenError:
    return TokenError("malformed", detail)


def _flatten_act(act: Any, expected: int) -> tuple[str, ...]:
    """Turn nested {"sub": a, "act": {"sub": b, ...}} into (a, b, ...).

    There must be exactly one actor per token in the chain, this one included.
    """
    actors: list[str] = []
    node = act
    while True:
        if type(node) is not dict or not set(node) <= {"sub", "act"}:
            raise _bad("act must be an object with sub and optionally act")
        if not _is_principal(node.get("sub")):
            raise _bad("act.sub must be a short printable string")
        actors.append(node["sub"])
        if len(actors) > expected:
            raise _bad("act is nested deeper than the chain")
        if "act" not in node:
            break
        node = node["act"]
    if len(actors) != expected:
        raise _bad("act nesting does not match the chain length")
    return tuple(actors)


def _nest_act(actors: Sequence[str]) -> dict[str, Any]:
    """Inverse of _flatten_act: (a, b, c) becomes {"sub": a, "act": {"sub": b, ...}}."""
    node: dict[str, Any] = {"sub": actors[-1]}
    for name in reversed(actors[:-1]):
        node = {"sub": name, "act": node}
    return node


def _rebuild_capabilities(capabilities: Any, limited: bool = False) -> tuple[Capability, ...]:
    """Fresh Capability objects made from the JSON text of the given ones.

    A caller's objects are never trusted as they are: a frozen dataclass can
    still be altered with object.__setattr__, and a subclass can lie. So they
    are written out as JSON and parsed back, and only the parsed copy is
    checked and signed. Raises ValueError for anything that does not survive.

    With `limited` (an exchange, where the caller is an untrusted agent) the
    request must also stay within the size limits, each checked as early as
    it can be: the count before anything is touched, the bytes before they
    are parsed, the constraints per capability before the caller compares
    them with the parent's. Over a limit raises RequestTooLarge.
    """
    if type(capabilities) not in (list, tuple):
        raise ValueError("capabilities must be a list or tuple")
    if len(capabilities) > _MAX_CAPABILITIES:
        if limited:
            raise RequestTooLarge(f"at most {_MAX_CAPABILITIES} capabilities per token")
        raise ValueError(f"at most {_MAX_CAPABILITIES} capabilities per token")
    plain = []
    for cap in capabilities:
        if type(cap) is Capability:
            plain.append(cap.to_dict())
        elif type(cap) is dict:
            plain.append(cap)
        else:
            raise ValueError("each capability must be a Capability or a dict")
    try:
        text = _dumps(plain)
        if limited and len(text) > _MAX_REQUEST_BYTES:
            raise RequestTooLarge(f"capabilities are larger than {_MAX_REQUEST_BYTES} bytes")
        parsed = _loads(text)
    except RequestTooLarge:
        raise
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError(f"capabilities are not plain JSON data: {exc}") from None
    rebuilt = tuple(Capability.from_dict(c) for c in parsed)
    if limited and any(len(c.constraints) > _MAX_CONSTRAINTS for c in rebuilt):
        raise RequestTooLarge(f"at most {_MAX_CONSTRAINTS} constraints per capability")
    return rebuilt


# ---------------------------------------------------------------------------
# The token service
# ---------------------------------------------------------------------------


class Authority:
    """The gateway's token service: the only holder of the signing key.

    `clock` returns the current time in seconds since the epoch and `new_id`
    returns a fresh token id; both are injectable so tests and demos are
    deterministic. `max_children` is how many child tokens may ever be
    exchanged from any one token. Callers of `mint` and `revoke` are trusted (the gateway
    authenticates the user before it calls them); `verify`, `exchange` and
    `authorize` take tokens from untrusted agents.

    `verify_cache_size` is how many token strings the verify cache keeps (0
    turns it off). The cache remembers, per exact token string, only what
    cannot change: that its signature is good and what its claims say. Every
    verify still checks expiry and the not-before time against a fresh clock
    reading, and asks the store about revocation and registration; refusals
    are never cached. The key also holds issuer, audience and max_depth, so
    changing one of them cannot let an old entry through.

    Records returned by `verify` are tracked by identity, weakly, so that
    `recheck` and `authorize` accept only those (see Verified). This trust
    sits at the same level as the signing key: code that reads the
    Authority's private attributes can sign tokens anyway.
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        issuer: str,
        audience: str,
        store: Store,
        *,
        max_depth: int = 4,
        max_ttl: int | float = 900,
        clock: Callable[[], float] = time.time,
        new_id: Callable[[], str] | None = None,
        max_children: int = 64,
        verify_cache_size: int = DEFAULT_VERIFY_CACHE_SIZE,
    ) -> None:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("private_key must be an Ed25519 private key")
        if not _is_name(issuer) or not _is_name(audience):
            raise ValueError("issuer and audience must be non-empty strings")
        if type(max_depth) is not int or max_depth < 0:
            raise ValueError("max_depth must be a non-negative integer")
        if not _is_time(max_ttl) or max_ttl <= 0:
            raise ValueError("max_ttl must be a positive number of seconds")
        self._key = private_key
        self._public: Ed25519PublicKey = private_key.public_key()
        self.issuer = issuer
        self.audience = audience
        if type(max_children) is not int or max_children < 0:
            raise ValueError("max_children must be a non-negative integer")
        if type(verify_cache_size) is not int or verify_cache_size < 0:
            raise ValueError("verify_cache_size must be a non-negative integer")
        self.store = store
        self.max_depth = max_depth
        self.max_children = max_children
        self.max_ttl = max_ttl
        self._clock = clock
        self._new_id = new_id if new_id is not None else (lambda: secrets.token_urlsafe(16))
        self._jws = PyJWS()
        self.verify_cache_size = verify_cache_size
        # (issuer, audience, max_depth, token) -> this Authority's own record.
        self._cache: OrderedDict[tuple[str, str, int, str], Verified] = OrderedDict()
        # id(record handed out) -> (weak reference to it, private copy, its grant)
        self._receipts: dict[int, tuple[weakref.ref[Verified], Verified, Grant]] = {}
        self._next_sweep = 1024
        self._lock = threading.Lock()

    @property
    def public_key(self) -> Ed25519PublicKey:
        """The key anybody can check this authority's signatures with."""
        return self._public

    # -- issuing ------------------------------------------------------------

    def mint(self, sub: str, grant: Grant, actor: str, ttl: int | float) -> str:
        """Sign a root token: `actor` may use `grant` on behalf of `sub`.

        The token expires at min(now + ttl, grant.expires_at), with ttl capped
        at max_ttl. Raises ValueError for input that cannot be signed.
        """
        now = self._now()
        if type(grant) is not Grant:
            raise ValueError("grant must be a Grant")
        if not _is_time(grant.expires_at):
            raise ValueError("grant expiry must be a finite number")
        capabilities = _rebuild_capabilities(grant.capabilities)
        exp = min(now + self._capped(ttl), grant.expires_at)
        if not now < exp:
            raise ValueError("grant has already expired")
        return self._issue(sub, (actor,), capabilities, exp, now, (), [() for _ in capabilities])

    def exchange(
        self,
        parent_token: str,
        child_capabilities: Sequence[Capability | Mapping[str, Any]],
        actor: str,
        ttl: int | float,
    ) -> str:
        """Sign a weaker token for a sub-agent, derived from `parent_token`.

        Raises TokenError if the parent does not verify, the depth limit is
        reached, the parent already has max_children children or the store is
        unavailable; EscalationError if the child would allow anything the
        parent does not; ValueError if the request itself is not well formed
        (RequestTooLarge, which is both a ValueError and a TokenError, if it
        is over the size limits).
        """
        now = self._now()
        parent = self._verify(parent_token, self.audience, now)
        if parent.depth + 1 > self.max_depth:
            raise TokenError("depth_exceeded", f"delegation depth is limited to {self.max_depth}")
        if not _is_principal(actor):
            raise ValueError("actor must be a short printable string")
        # Size limits come first: the attenuation check below is the expensive
        # step and must never run on a request of unbounded size.
        capabilities = _rebuild_capabilities(child_capabilities, limited=True)
        # Monotonic expiry: a child can never outlive its parent, whatever ttl says.
        exp = min(parent.exp, now + self._capped(ttl))
        child = Grant(capabilities, exp)
        result = check_attenuation(parent.grant, child)
        if not result.ok:
            raise EscalationError(result.reason)
        if len(result.derivation) != len(capabilities):
            raise EscalationError("attenuation check returned no derivation")
        # Child capability i came from parent capability d, so its path to the
        # root is the parent's own path for d, plus d itself.
        der = [(*parent.der[d], d) for d in result.derivation]
        # `sub` is copied, never chosen by the caller (principal invariance).
        # The nested `act` claim is attribution history for the audit log only.
        # It must never be used for an authorization decision: authority comes
        # from `caps` alone, which were just checked against the parent.
        actors = (actor, *parent.actors)
        # Counted last, so a request refused above uses up no slot. The test
        # and the increment are one atomic step in the store, so concurrent
        # exchanges cannot get past the limit together. If signing fails after
        # this point the slot stays used: failing closed, and it is rare.
        if not self._ask_store("add_child", parent.jti, self.max_children):
            if not self._ask_store("is_registered", parent.jti):  # pruned since verify
                raise TokenError("unknown_token", "the store has no record of this token")
            raise TokenError(
                "too_many_children", f"a token may have at most {self.max_children} children"
            )
        return self._issue(
            parent.sub, actors, capabilities, exp, now, (*parent.chain, parent.jti), der
        )

    def _issue(
        self,
        sub: str,
        actors: tuple[str, ...],
        capabilities: tuple[Capability, ...],
        exp: int | float,
        now: int | float,
        chain: tuple[str, ...],
        der: Sequence[Sequence[int]],
    ) -> str:
        if not _is_principal(sub):
            raise ValueError("sub must be a short printable string")
        if not _is_principal(actors[0]):
            raise ValueError("actor must be a short printable string")
        jti = self._new_id()
        claims = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": sub,
            "act": _nest_act(actors),
            "iat": now,
            "exp": exp,
            "jti": jti,
            "caps": [c.to_dict() for c in capabilities],
            "chain": list(chain),
            "der": [list(d) for d in der],
        }
        payload = _dumps(claims)
        # Self-check before signing: read the exact bytes back with the same
        # code `verify` uses. Nothing is signed that verify would refuse, and
        # nothing is signed that reads back differently from what was checked.
        try:
            readback = self._read_claims(payload, self.audience, now)
        except TokenError as exc:
            raise ValueError(f"refusing to sign: {exc}") from None
        if readback.grant != Grant(capabilities, exp) or readback.sub != sub:
            raise ValueError("refusing to sign: claims do not read back as written")
        token = self._jws.encode(payload, self._key, algorithm=ALGORITHM, headers={"typ": "JWT"})
        if len(token) > _MAX_TOKEN_CHARS:
            raise ValueError("token would be too large")
        # Every capability gets a ledger entry, limited or not, so that a
        # missing entry always means "unknown token" and never "unlimited".
        # The expiry is recorded so that `prune` can forget the token later.
        try:
            self.store.register(jti, [c.max_calls for c in capabilities], exp)
        except ValueError:
            raise  # a repeated token id; the caller's new_id is at fault
        except Exception as exc:
            raise TokenError("unavailable", f"store: {type(exc).__name__}") from None
        return token

    # -- checking -----------------------------------------------------------

    def verify(self, token: str, audience: str | None = None) -> Verified:
        """Check a token completely and return what it says, or raise TokenError.

        `audience` defaults to this authority's own. Verification consults the
        store, so a token is only valid while the store knows it and neither
        it nor any ancestor is revoked.
        """
        return self._verify(token, self.audience if audience is None else audience, self._now())

    def recheck(self, verified: Verified) -> None:
        """Check again what can have changed since `verify` returned `verified`.

        `verified` must be a record this Authority's `verify` returned (see
        Verified); anything else is TokenError "malformed". The signature,
        the claims and the structure of a token string cannot change, so they
        are not checked again. What can change is checked, with the clock
        read afresh: expiry ("expired"), a clock now earlier than the token's
        issue time ("not_yet_valid"), and revocation of the token or any
        ancestor ("revoked"), in one store call. A clock or store failure is
        TokenError "unavailable". Returns None if the token still holds.

        Not checked again: whether the store still has the token registered.
        It can only lose it to `prune`, which forgets tokens that have
        expired, so with a clock that does not run backwards the expiry check
        refuses such a token first; and `authorize` charges the budget, which
        refuses a token the store does not know.
        """
        self._recheck(self._own(verified), self._now())

    def authorize(self, token: str | Verified, call: Call) -> Authorization:
        """Decide one tool call made with `token`, and charge its budget.

        `token` is a token string, which is verified completely, or a record
        `verify` returned, which is rechecked (see `recheck`) and decided from
        this Authority's own copy of it. The Authorization carries the record
        passed in, or for a string the fresh one.

        Raises TokenError if the token does not verify, or with code
        "unavailable" if the store or the clock fails; never a raw store or
        clock exception. Otherwise returns the Decision with the Verified
        record. A denied call charges nothing: a call whose charge only
        completed after the token expired, or after which the clock failed,
        is refused and its charge is given back (best effort; if the refund
        itself fails the budget stays spent, which fails closed).
        """
        now = self._now()
        if type(token) is Verified:
            shown = token
            verified = self._own(token)
            self._recheck(verified, now)
        else:
            shown = verified = self._verify(token, self.audience, now)
        decision = verified.grant.decide(call, now)
        if not decision.allowed:
            return Authorization(decision, shown)
        # Capabilities are tried in order. The first that permits the call and
        # still has budget on its whole path pays for it. The path comes from
        # the signed `der` claim: an ancestor's decide() is never re-run here,
        # because it could pick a different capability than the one this
        # capability was actually derived from.
        refusal = "budget exhausted"
        for index, capability in enumerate(verified.grant.capabilities):
            if not capability.decide(call).allowed:
                continue
            path = verified.budget_path(index)
            charged = self._ask_store("charge", path)
            if charged.ok:
                # The charge may have waited on a lock for a long time. `now`
                # is stale by then, so the clock is read again: a call must
                # not be allowed after the token's expiry just because its
                # check started before. Either way the call will not run, so
                # its charge is given back. A refund is a second write that
                # can fail; then the budget stays spent (fails closed).
                try:
                    late = not self._now() < verified.exp
                except TokenError:
                    self._refund_quietly(path)
                    raise
                if late:
                    self._refund_quietly(path)
                    return Authorization(Decision(False, "expired during authorization"), shown)
                return Authorization(Decision(True, "ok", index), shown)
            if charged.reason == "revoked":  # revoked between verify and charge
                raise TokenError("revoked", "the token or an ancestor was revoked")
            if charged.reason != "exhausted":
                refusal = "budget ledger has no record of this delegation path"
        return Authorization(Decision(False, refusal), shown)

    def refund(self, authorization: Authorization) -> bool:
        """Give back the budget `authorize` charged, for a call that never ran.

        Only an allowed Authorization was charged; anything else returns False
        and changes nothing. Counters never go below zero. Raises TokenError
        "unavailable" if the store could not record the refund, in which case
        the budget simply stays spent (which fails closed). The caller must
        never refund a call whose tool started to run.
        """
        if type(authorization) is not Authorization:
            raise ValueError("authorization must be an Authorization")
        decision, verified = authorization.decision, authorization.verified
        if not decision.allowed or type(decision.capability) is not int:
            return False
        # For a record verify returned, the path comes from the private copy,
        # whatever was done to the record since.
        with self._lock:
            receipt = self._receipts.get(id(verified))
        if receipt is not None and receipt[0]() is verified:
            verified = receipt[1]
        if not 0 <= decision.capability < len(verified.der):
            return False
        return bool(self._ask_store("refund", verified.budget_path(decision.capability)))

    def _refund_quietly(self, path: Any) -> None:
        """Give back a charge made inside `authorize`. A failed refund is not raised."""
        with contextlib.suppress(TokenError):
            self._ask_store("refund", path)

    def revoke(self, jti: str) -> None:
        """Revoke a token id. The token and all its descendants stop verifying.

        Raises ValueError if `jti` is not a non-empty string, TokenError
        "malformed" if it is text no token id can be (lone surrogates), and
        TokenError "unavailable" if the store could not record it.
        """
        if not _is_name(jti):
            raise ValueError("jti must be a non-empty string")
        if not _is_encodable(jti):
            raise _bad("jti is not encodable text")
        self._ask_store("revoke", jti)

    def prune(self) -> int:
        """Let the store forget every token that has expired by now.

        Returns how many tokens were forgotten. This is never called by
        verify, authorize or exchange; run it from a timer or a maintenance
        job. See store.py for why forgetting an expired token is safe.
        """
        return self._ask_store("prune", self._now())

    # -- internals ----------------------------------------------------------

    def _now(self) -> int | float:
        """The current time, or TokenError "unavailable": no clock, no decision."""
        try:
            now = self._clock()
        except Exception as exc:
            raise TokenError("unavailable", f"clock: {type(exc).__name__}") from None
        if not _is_time(now):
            raise TokenError("unavailable", "clock returned an invalid time")
        return now

    def _ask_store(self, method: str, *args: Any) -> Any:
        """Call a store method; any failure becomes TokenError "unavailable".

        A store outage is not the token's fault and must not be reported as
        "malformed", but it is still a refusal.
        """
        try:
            return getattr(self.store, method)(*args)
        except Exception as exc:
            raise TokenError("unavailable", f"store: {type(exc).__name__}") from None

    def _capped(self, ttl: Any) -> int | float:
        if not _is_time(ttl) or ttl <= 0:
            raise ValueError("ttl must be a positive number of seconds")
        return min(ttl, self.max_ttl)

    def _verify(self, token: Any, audience: Any, now: int | float) -> Verified:
        """Fail closed: whatever goes wrong in here ends as a TokenError.

        Returns a fresh record for the caller, registered as a receipt.
        """
        own = self._cached(token, audience)
        if own is not None:
            # Signature and claims were checked when this string was first
            # seen; only the time can have moved since.
            try:
                self._check_times(own, now)
            except TokenError:
                self._forget(token, audience)
                raise
        else:
            try:
                payload = self._check_signature(token)
                own = self._read_claims(payload, audience, now)
            except TokenError:
                raise
            except Exception as exc:
                raise TokenError("malformed", type(exc).__name__) from None
        # The token is well formed. A failure from here on is the store's.
        if self._ask_store("any_revoked", (own.jti, *own.chain)):
            raise TokenError("revoked", "the token or an ancestor was revoked")
        if not self._ask_store("is_registered", own.jti):
            raise TokenError("unknown_token", "the store has no record of this token")
        self._remember(token, audience, own)
        return self._hand_out(own)

    # -- receipts and the verify cache ---------------------------------------

    def _hand_out(self, own: Verified) -> Verified:
        """A record for the caller with its own Grant objects, tracked as a receipt.

        `own` stays private. Its plain fields (str, int, float and tuples of
        them) cannot be changed by anybody and are shared; the Grant,
        Capability and Constraint objects are dataclasses that
        object.__setattr__ can bend, so the caller gets copies of those.
        """
        grant = Grant(
            tuple(
                Capability(
                    c.tool,
                    tuple(Constraint(k.arg, k.op, k.value) for k in c.constraints),
                    c.max_calls,
                )
                for c in own.grant.capabilities
            ),
            own.grant.expires_at,
        )
        record = Verified(
            jti=own.jti,
            sub=own.sub,
            actors=own.actors,
            grant=grant,
            chain=own.chain,
            der=own.der,
            exp=own.exp,
            iat=own.iat,
        )
        with self._lock:
            # Entries whose record is gone are dropped in sweeps spaced so
            # that the cost per record stays constant. (No weakref callback:
            # it could run inside this lock, from the garbage collector.)
            if len(self._receipts) >= self._next_sweep:
                self._receipts = {k: v for k, v in self._receipts.items() if v[0]() is not None}
                self._next_sweep = 2 * len(self._receipts) + 1024
            self._receipts[id(record)] = (weakref.ref(record), own, grant)
        return record

    def _own(self, verified: Any) -> Verified:
        """This Authority's private copy of a record its `verify` handed out.

        Refuses (TokenError "malformed") anything else: an object of another
        type, a record built or copied by hand (it was never handed out, so
        its identity is unknown), and a handed-out record one of whose fields
        was replaced (each must still be the very object it was given).
        """
        if type(verified) is not Verified:
            raise _bad("not a verified token record")
        with self._lock:
            receipt = self._receipts.get(id(verified))
        if receipt is None or receipt[0]() is not verified:
            raise _bad("not a record this authority verified")
        own, grant = receipt[1], receipt[2]
        if not (
            verified.grant is grant
            and verified.jti is own.jti
            and verified.sub is own.sub
            and verified.actors is own.actors
            and verified.chain is own.chain
            and verified.der is own.der
            and verified.exp is own.exp
            and verified.iat is own.iat
        ):
            raise _bad("the verified record was altered")
        return own

    def _check_times(self, own: Verified, now: int | float) -> None:
        if not now < own.exp:
            raise TokenError("expired")
        if own.iat > now:
            raise TokenError("not_yet_valid")

    def _recheck(self, own: Verified, now: int | float) -> None:
        """Expiry, not-before and revocation of a private record: one store call."""
        self._check_times(own, now)
        if self._ask_store("any_revoked", (own.jti, *own.chain)):
            raise TokenError("revoked", "the token or an ancestor was revoked")

    def _cache_key(self, token: Any, audience: Any) -> tuple[str, str, int, str] | None:
        if (
            self.verify_cache_size <= 0
            or type(token) is not str
            or len(token) > _MAX_CACHED_CHARS
            or type(audience) is not str
            or type(self.issuer) is not str
            or type(self.max_depth) is not int
        ):
            return None
        return (self.issuer, audience, self.max_depth, token)

    def _cached(self, token: Any, audience: Any) -> Verified | None:
        key = self._cache_key(token, audience)
        if key is None:
            return None
        with self._lock:
            own = self._cache.get(key)
            if own is not None:
                self._cache.move_to_end(key)
            return own

    def _forget(self, token: Any, audience: Any) -> None:
        key = self._cache_key(token, audience)
        if key is not None:
            with self._lock:
                self._cache.pop(key, None)

    def _remember(self, token: Any, audience: Any, own: Verified) -> None:
        """Keep a token that passed every check, least recently used out first."""
        key = self._cache_key(token, audience)
        if key is None:
            return
        with self._lock:
            self._cache[key] = own
            self._cache.move_to_end(key)
            while len(self._cache) > self.verify_cache_size:
                self._cache.popitem(last=False)

    def _check_signature(self, token: Any) -> bytes:
        """Return the payload bytes of a correctly signed token."""
        if type(token) is not str:
            raise _bad("token must be a string")
        if len(token) > _MAX_TOKEN_CHARS:
            raise _bad("token is too large")
        if not _COMPACT.fullmatch(token):
            raise _bad("token is not three base64url segments")
        header_segment, payload_segment, _ = token.split(".")
        try:
            header = _loads(_b64decode(header_segment))
        except (ValueError, RecursionError) as exc:
            raise _bad(f"unreadable header: {exc}") from None
        if type(header) is not dict:
            raise _bad("header must be an object")
        # The algorithm is fixed by this code, never chosen by the token.
        if header.get("alg") != ALGORITHM:
            raise TokenError("bad_algorithm", "only EdDSA is accepted")
        if header != _HEADER:
            raise _bad("unexpected header parameters")
        try:
            self._jws.decode_complete(token, key=self._public, algorithms=[ALGORITHM])
        except InvalidSignatureError:
            raise TokenError("bad_signature") from None
        except InvalidAlgorithmError:
            raise TokenError("bad_algorithm", "only EdDSA is accepted") from None
        except PyJWTError as exc:
            raise _bad(type(exc).__name__) from None
        try:
            return _b64decode(payload_segment)
        except ValueError as exc:
            raise _bad(f"unreadable payload: {exc}") from None

    def _read_claims(self, payload: bytes, audience: Any, now: int | float) -> Verified:
        """Validate every claim of an already authenticated payload."""
        try:
            claims = _loads(payload)
        except (ValueError, RecursionError) as exc:
            raise _bad(f"unreadable payload: {exc}") from None
        if type(claims) is not dict:
            raise _bad("payload must be an object")
        unknown = set(claims) - _CLAIMS
        if unknown:
            raise _bad(f"unknown claim {sorted(unknown)[0]!r}")
        missing = _CLAIMS - set(claims)
        if missing:
            raise _bad(f"missing claim {sorted(missing)[0]!r}")

        if type(claims["iss"]) is not str or type(claims["aud"]) is not str:
            raise _bad("iss and aud must each be one string")
        if claims["iss"] != self.issuer:
            raise TokenError("wrong_issuer")
        if type(audience) is not str or claims["aud"] != audience:
            raise TokenError("wrong_audience")

        sub, jti, iat, exp = claims["sub"], claims["jti"], claims["iat"], claims["exp"]
        if not _is_principal(sub) or not _is_id(jti):
            raise _bad("sub and jti must be non-empty strings")
        if not _is_time(iat) or not _is_time(exp):
            raise _bad("iat and exp must be finite numbers")
        if not iat < exp:
            raise _bad("exp must be later than iat")
        if not now < exp:
            raise TokenError("expired")
        if iat > now:
            raise TokenError("not_yet_valid")

        chain = claims["chain"]
        if type(chain) is not list:
            raise _bad("chain must be a list")
        if len(chain) > self.max_depth:
            raise TokenError("depth_exceeded", f"delegation depth is limited to {self.max_depth}")
        if not all(_is_id(j) for j in chain):
            raise _bad("chain entries must be non-empty strings")
        if len(set(chain)) != len(chain) or jti in chain:
            raise _bad("chain repeats a token id")

        actors = _flatten_act(claims["act"], len(chain) + 1)

        caps, der = claims["caps"], claims["der"]
        if type(caps) is not list or type(der) is not list:
            raise _bad("caps and der must be lists")
        if len(caps) > _MAX_CAPABILITIES:
            raise _bad("too many capabilities")
        if len(der) != len(caps):
            raise _bad("der must have one entry per capability")
        for indices in der:
            if type(indices) is not list or len(indices) != len(chain):
                raise _bad("each der entry must have one index per ancestor")
            for index in indices:
                if type(index) is not int or not 0 <= index < _MAX_CAPABILITIES:
                    raise _bad("der indices must be small non-negative integers")
        try:
            grant = Grant.from_dict({"capabilities": caps, "expires_at": exp})
        except (ValueError, TypeError) as exc:
            raise _bad(f"caps: {exc}") from None

        return Verified(
            jti=jti,
            sub=sub,
            actors=actors,
            grant=grant,
            chain=tuple(chain),
            der=tuple(tuple(indices) for indices in der),
            exp=exp,
            iat=iat,
        )
