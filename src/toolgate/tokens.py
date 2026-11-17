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
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import secrets
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jwt import PyJWS
from jwt.exceptions import InvalidAlgorithmError, InvalidSignatureError, PyJWTError

from toolgate.attenuation import check_attenuation
from toolgate.capability import Call, Capability, Decision, Grant
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


class TokenError(Exception):
    """A token was refused. `code` is short and machine readable.

    Codes: malformed, bad_algorithm, bad_signature, wrong_issuer,
    wrong_audience, expired, not_yet_valid, depth_exceeded, revoked,
    unknown_token.
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


@dataclass(frozen=True)
class Verified:
    """What a token says, after its signature and every claim were checked."""

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
        if not _is_name(node.get("sub")):
            raise _bad("act.sub must be a non-empty string")
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


def _rebuild_capabilities(capabilities: Any) -> tuple[Capability, ...]:
    """Fresh Capability objects made from the JSON text of the given ones.

    A caller's objects are never trusted as they are: a frozen dataclass can
    still be altered with object.__setattr__, and a subclass can lie. So they
    are written out as JSON and parsed back, and only the parsed copy is
    checked and signed. Raises ValueError for anything that does not survive.
    """
    if type(capabilities) not in (list, tuple):
        raise ValueError("capabilities must be a list or tuple")
    if len(capabilities) > _MAX_CAPABILITIES:
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
        parsed = _loads(_dumps(plain))
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError(f"capabilities are not plain JSON data: {exc}") from None
    return tuple(Capability.from_dict(c) for c in parsed)


# ---------------------------------------------------------------------------
# The token service
# ---------------------------------------------------------------------------


class Authority:
    """The gateway's token service: the only holder of the signing key.

    `clock` returns the current time in seconds since the epoch and `new_id`
    returns a fresh token id; both are injectable so tests and demos are
    deterministic. Callers of `mint` and `revoke` are trusted (the gateway
    authenticates the user before it calls them); `verify`, `exchange` and
    `authorize` take tokens from untrusted agents.
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
        self.store = store
        self.max_depth = max_depth
        self.max_ttl = max_ttl
        self._clock = clock
        self._new_id = new_id if new_id is not None else (lambda: secrets.token_urlsafe(16))
        self._jws = PyJWS()

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

        Raises TokenError if the parent does not verify or the depth limit is
        reached, EscalationError if the child would allow anything the parent
        does not, ValueError if the request itself is not well formed.
        """
        now = self._now()
        parent = self._verify(parent_token, self.audience, now)
        if parent.depth + 1 > self.max_depth:
            raise TokenError("depth_exceeded", f"delegation depth is limited to {self.max_depth}")
        capabilities = _rebuild_capabilities(child_capabilities)
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
        if not _is_name(sub):
            raise ValueError("sub must be a non-empty string")
        if not _is_name(actors[0]):
            raise ValueError("actor must be a non-empty string")
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
        self.store.register(jti, [c.max_calls for c in capabilities])
        return token

    # -- checking -----------------------------------------------------------

    def verify(self, token: str, audience: str | None = None) -> Verified:
        """Check a token completely and return what it says, or raise TokenError.

        `audience` defaults to this authority's own. Verification consults the
        store, so a token is only valid while the store knows it and neither
        it nor any ancestor is revoked.
        """
        return self._verify(token, self.audience if audience is None else audience, self._now())

    def authorize(self, token: str, call: Call) -> Authorization:
        """Decide one tool call made with `token`, and charge its budget.

        Raises TokenError if the token does not verify. Otherwise returns the
        Decision with the Verified record. A denied call charges nothing.
        """
        now = self._now()
        verified = self._verify(token, self.audience, now)
        decision = verified.grant.decide(call, now)
        if not decision.allowed:
            return Authorization(decision, verified)
        # Capabilities are tried in order. The first that permits the call and
        # still has budget on its whole path pays for it. The path comes from
        # the signed `der` claim: an ancestor's decide() is never re-run here,
        # because it could pick a different capability than the one this
        # capability was actually derived from.
        refusal = "budget exhausted"
        for index, capability in enumerate(verified.grant.capabilities):
            if not capability.decide(call).allowed:
                continue
            charged = self.store.charge(verified.budget_path(index))
            if charged.ok:
                return Authorization(Decision(True, "ok", index), verified)
            if charged.reason == "revoked":  # revoked between verify and charge
                raise TokenError("revoked", "the token or an ancestor was revoked")
            if charged.reason != "exhausted":
                refusal = "budget ledger has no record of this delegation path"
        return Authorization(Decision(False, refusal), verified)

    def revoke(self, jti: str) -> None:
        """Revoke a token id. The token and all its descendants stop verifying."""
        if not _is_name(jti):
            raise ValueError("jti must be a non-empty string")
        self.store.revoke(jti)

    # -- internals ----------------------------------------------------------

    def _now(self) -> int | float:
        now = self._clock()
        if not _is_time(now):
            raise TokenError("malformed", "clock returned an invalid time")
        return now

    def _capped(self, ttl: Any) -> int | float:
        if not _is_time(ttl) or ttl <= 0:
            raise ValueError("ttl must be a positive number of seconds")
        return min(ttl, self.max_ttl)

    def _verify(self, token: Any, audience: Any, now: int | float) -> Verified:
        """Fail closed: whatever goes wrong in here ends as a TokenError."""
        try:
            payload = self._check_signature(token)
            verified = self._read_claims(payload, audience, now)
            if self.store.any_revoked((verified.jti, *verified.chain)):
                raise TokenError("revoked", "the token or an ancestor was revoked")
            if not self.store.is_registered(verified.jti):
                raise TokenError("unknown_token", "the store has no record of this token")
            return verified
        except TokenError:
            raise
        except Exception as exc:
            raise TokenError("malformed", type(exc).__name__) from None

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
        if not _is_name(sub) or not _is_name(jti):
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
        if not all(_is_name(j) for j in chain):
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
