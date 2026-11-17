"""Offline attenuation with chained signatures (docs/PLAN.md section 3.8).

A chain token is a base Grant plus an ordered list of caveats. A call is
allowed only if the base grant allows it AND every caveat holds. The holder of
a token can append a caveat by itself, with no network call and no key other
than the token, and nobody can remove one.

Because caveats are only ever added and all of them must hold, a derived token
is weaker by construction. That is why this module never calls
check_attenuation: the online exchange needs a subsumption check because the
child grant is written fresh, while here the child is "the parent, and also
this".

Two constructions share the caveat language and the decision rule.

Construction 1, HMAC chain (macaroon style)

    sig0 = HMAC-SHA256(root_key, ROOT_TAG   + canonical({"grant", "id"}))
    sigN = HMAC-SHA256(sigN-1,   CAVEAT_TAG + canonical(caveat N))

    The token carries only the last signature. Appending needs that signature
    as the HMAC key, which the holder has. Removing caveat N needs sigN-1,
    which the holder does not have and cannot compute, because HMAC cannot be
    run backwards. Verifying recomputes the chain from the root key.

Construction 2, Ed25519 chain (Biscuit style)

    block 0 = {"body": {"grant", "id"}, "i": 0, "next": pk1}  signed by the root key
    block N = {"body": caveat N,        "i": N, "next": pkN+1} signed by skN

    What is signed is a tag followed by the block: ROOT_TAG for block 0,
    CAVEAT_TAG for every later block, and a third tag for the seal.

    The token carries skLAST, the private key matching the last block's
    "next" key. Appending signs a new block with it, names a fresh key pair
    and carries the new private key instead; the old one is dropped. Verifying
    needs only the root PUBLIC key. `seal` replaces the private key with a
    signature made by it, so a sealed token can be used but not narrowed.

Limits, stated plainly

  * These are bearer tokens. Whoever holds the string holds the authority, so
    theft still matters and proof of possession still applies. Nothing here
    binds a token to its holder.
  * Construction 1 can only be verified by a holder of the root key. A third
    party cannot verify it, and anyone who can verify it can also mint
    tokens. Construction 2 exists to remove that limit.
  * Revocation needs a lookup (by the token identifier), which gives back part
    of the offline benefit.
  * Tokens grow with every caveat: about 50 to 150 characters per caveat in
    construction 1, and about 180 more than that per block in construction 2.
    Parsing refuses more than MAX_CAVEATS caveats or MAX_TOKEN_CHARS characters.
  * An unsealed construction 2 token shows its last private key to whoever
    receives it. Seal before presenting to a party that should not be able to
    derive further tokens (it could still replay the sealed one: bearer).
  * Python cannot wipe memory. "The old private key is discarded" means it is
    absent from the new token, not that it is erased from the process.
  * Call budgets (Capability.max_calls) are not enforced here. Counting calls
    is state, and an offline token has nowhere to keep it.
  * A token object is never trusted. Every verify serializes it, rebuilds all
    of it from those bytes with exact type checks, and decides on the rebuilt
    copy only.
  * An HMAC root key longer than 64 bytes is equivalent to its SHA-256 digest:
    HMAC-SHA256 first replaces a key longer than its 64-byte block with the
    hash of that key, so the 32-byte digest issues and verifies the same
    tokens as the long key. A SHA-256 fingerprint of the root key must
    therefore never be published or logged. Fingerprinting a root key at all
    is best avoided.
  * Small-order Ed25519 public keys are rejected everywhere a public key is
    read: the root public key, every block's "next" key and the key that
    checks the proof or seal. Ed25519 as implemented by OpenSSL accepts them,
    and a signature that needs no private key then verifies under them: for
    every message under the identity point, and for a fraction of messages
    under the points of order 2, 4 and 8. A block naming such a key would let
    any bearer drop every later caveat and forge the seal.
  * No string in a token may contain a surrogate code point (U+D800 to
    U+DFFF). A surrogate pair and the single character it stands for have the
    same ASCII JSON escape, so allowing them would give two different objects
    one signed encoding.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from toolgate.capability import Call, Capability, Decision, Grant
from toolgate.constraints import Constraint

MAX_TOKEN_CHARS = 32768
MAX_CAVEATS = 64
MAX_IDENTIFIER_CHARS = 128
MIN_ROOT_KEY_BYTES = 32

HMAC_PREFIX = "tgm1"
KEY_PREFIX = "tgk1"

# Domain separation: every signed or MACed message starts with a tag naming the
# construction and the role of the message, so bytes made for one purpose can
# never be accepted for another, even if a key were reused.
_TAG_HMAC_ROOT = b"toolgate.chain.hmac.v1.root\n"
_TAG_HMAC_CAVEAT = b"toolgate.chain.hmac.v1.caveat\n"
_TAG_KEY_ROOT = b"toolgate.chain.ed25519.v1.root\n"
_TAG_KEY_CAVEAT = b"toolgate.chain.ed25519.v1.caveat\n"
_TAG_KEY_SEAL = b"toolgate.chain.ed25519.v1.seal\n"

_SIG_LEN = 64  # Ed25519 signature
_KEY_LEN = 32  # Ed25519 private seed, Ed25519 public key
_MAC_LEN = 32  # HMAC-SHA256


class ChainError(ValueError):
    """A token could not be built, parsed or verified. Always means deny."""


# ---------------------------------------------------------------------------
# Canonical bytes
# ---------------------------------------------------------------------------


_SURROGATE = re.compile("[\ud800-\udfff]")


def _canonical(obj: Any) -> bytes:
    """The one byte string for a JSON value: sorted keys, no whitespace, ASCII only.

    Strings holding a surrogate code point are refused. With ASCII escaping the
    two-code-point string "\\ud83d\\ude00" and the one-character string
    U+1F600 are written identically, so without this check two different
    objects would share one encoding and the signed bytes would not say which
    one was meant. The check reads the unescaped dump, where a surrogate is
    still a surrogate; object keys are covered because they are in it too.
    """
    try:
        raw = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
        text = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ChainError(f"value cannot be encoded: {exc}") from None
    if _SURROGATE.search(raw):
        raise ChainError("strings must not contain surrogate code points")
    return text.encode("ascii")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not allowed")


def _parse_canonical(data: bytes) -> Any:
    """Decode JSON and require that it is exactly the canonical encoding of itself.

    That one comparison rejects whitespace, unsorted keys, "1.50", "1E5", "-0",
    escaped ASCII and every other second spelling of the same value, so two
    different byte strings never parse to the same object.
    """
    try:
        obj = json.loads(
            data.decode("ascii"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError) as exc:
        raise ChainError(f"bad JSON: {exc}") from None
    if _canonical(obj) != data:
        raise ChainError("encoding is not canonical")
    return obj


_B64_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text: Any) -> bytes:
    """Strict unpadded URL-safe base64: one spelling per byte string."""
    if type(text) is not str or not text or not _B64_ALPHABET.issuperset(text):
        raise ChainError("bad base64 segment")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        raise ChainError("bad base64 segment") from None
    if _b64encode(raw) != text:  # stray bits in the last character
        raise ChainError("base64 segment is not canonical")
    return raw


def _keys(obj: Any, expected: set[str], what: str) -> dict[str, Any]:
    if type(obj) is not dict or set(obj) != expected:
        raise ChainError(f"{what} must be an object with exactly the keys {sorted(expected)}")
    return obj


# ---------------------------------------------------------------------------
# Grants as JSON. Lossless, unlike Grant.to_dict, which cannot hold two
# constraints with the same operator on one argument and forgets their order.
# ---------------------------------------------------------------------------


def _constraint_obj(c: Constraint) -> dict[str, Any]:
    if type(c) is not Constraint:
        raise ChainError("constraint must be a Constraint")
    out: dict[str, Any] = {"arg": c.arg, "op": c.op}
    if c.op != "any":
        out["value"] = list(c.value) if c.op == "in" else c.value
    return out


def _constraint_from(obj: Any) -> Constraint:
    if type(obj) is not dict or not {"arg", "op"} <= set(obj) <= {"arg", "op", "value"}:
        raise ChainError("bad constraint")
    if (obj["op"] == "any") == ("value" in obj):
        raise ChainError("bad constraint: any takes no value, every other operator needs one")
    try:
        return Constraint(obj["arg"], obj["op"], obj.get("value"))
    except (ValueError, TypeError) as exc:  # TypeError: unhashable op
        raise ChainError(f"bad constraint: {exc}") from None


def _grant_obj(grant: Grant) -> dict[str, Any]:
    if type(grant) is not Grant:
        raise ChainError("grant must be a Grant")
    caps = []
    for cap in grant.capabilities:
        if type(cap) is not Capability:
            raise ChainError("capability must be a Capability")
        caps.append(
            {
                "constraints": [_constraint_obj(c) for c in cap.constraints],
                "max_calls": cap.max_calls,
                "tool": cap.tool,
            }
        )
    return {"capabilities": caps, "expires_at": grant.expires_at}


def _grant_from(obj: Any) -> Grant:
    _keys(obj, {"capabilities", "expires_at"}, "grant")
    if type(obj["capabilities"]) is not list:
        raise ChainError("capabilities must be a list")
    caps = []
    for item in obj["capabilities"]:
        _keys(item, {"constraints", "max_calls", "tool"}, "capability")
        if type(item["constraints"]) is not list:
            raise ChainError("constraints must be a list")
        try:
            caps.append(
                Capability(
                    item["tool"],
                    tuple(_constraint_from(c) for c in item["constraints"]),
                    item["max_calls"],
                )
            )
        except ChainError:
            raise
        except ValueError as exc:
            raise ChainError(f"bad capability: {exc}") from None
    try:
        return Grant(tuple(caps), obj["expires_at"])
    except ValueError as exc:
        raise ChainError(f"bad grant: {exc}") from None


def _check_identifier(identifier: Any) -> str:
    if type(identifier) is not str or not 0 < len(identifier) <= MAX_IDENTIFIER_CHARS:
        raise ChainError(f"identifier must be a string of 1 to {MAX_IDENTIFIER_CHARS} characters")
    return identifier


def _root_obj(identifier: str, grant: Grant) -> dict[str, Any]:
    return {"grant": _grant_obj(grant), "id": _check_identifier(identifier)}


def _root_from(obj: Any) -> tuple[str, Grant]:
    _keys(obj, {"grant", "id"}, "root block")
    return _check_identifier(obj["id"]), _grant_from(obj["grant"])


# ---------------------------------------------------------------------------
# Caveats
# ---------------------------------------------------------------------------


def _is_time(value: Any) -> bool:
    return type(value) is int or (type(value) is float and math.isfinite(value))


@dataclass(frozen=True)
class ToolsCaveat:
    """The call's tool must be one of `tools`. An empty list denies everything."""

    tools: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.tools) not in (list, tuple):
            raise ChainError("tools must be a list of tool names")
        object.__setattr__(self, "tools", tuple(self.tools))
        if not all(type(t) is str and t for t in self.tools):
            raise ChainError("tool names must be non-empty strings")
        if len(set(self.tools)) != len(self.tools):
            raise ChainError("tool names must not repeat")

    def check(self, call: Call, now: float) -> str | None:
        """None if the caveat holds, else the reason it does not."""
        if call.tool in self.tools:
            return None
        return f"tool {call.tool!r} is not in the allowed list"


@dataclass(frozen=True)
class ArgCaveat:
    """If the call is to `tool`, `constraint` must hold on its argument.

    A call to `tool` that lacks the argument fails. Calls to other tools are
    not affected by this caveat.
    """

    tool: str
    constraint: Constraint

    def __post_init__(self) -> None:
        if type(self.tool) is not str or not self.tool:
            raise ChainError("tool name must be a non-empty string")
        if type(self.constraint) is not Constraint:
            raise ChainError("constraint must be a Constraint")

    def check(self, call: Call, now: float) -> str | None:
        if call.tool != self.tool:
            return None
        c = self.constraint
        if c.arg not in call.args:
            return f"argument {c.arg!r} is missing"
        if not c.holds(call.args[c.arg]):
            return f"argument {c.arg!r} fails {c.op}"
        return None


@dataclass(frozen=True)
class ExpiryCaveat:
    """`now` must be strictly before `not_after` (seconds since the Unix epoch)."""

    not_after: float

    def __post_init__(self) -> None:
        if not _is_time(self.not_after):
            raise ChainError("not_after must be a finite number")

    def check(self, call: Call, now: float) -> str | None:
        if _is_time(now) and now < self.not_after:
            return None
        return "caveat expired"


Caveat = ToolsCaveat | ArgCaveat | ExpiryCaveat


def _caveat_obj(caveat: Caveat) -> dict[str, Any]:
    """Module function, not a method: a subclass cannot substitute its own encoding."""
    kind = type(caveat)
    if kind is ToolsCaveat:
        return {"tools": list(caveat.tools), "type": "tools"}
    if kind is ArgCaveat:
        return {
            "constraint": _constraint_obj(caveat.constraint),
            "tool": caveat.tool,
            "type": "arg",
        }
    if kind is ExpiryCaveat:
        return {"not_after": caveat.not_after, "type": "expiry"}
    raise ChainError("unknown caveat type")


def _caveat_from(obj: Any) -> Caveat:
    """Rebuild a caveat from parsed JSON. Unknown types and extra keys fail closed."""
    if type(obj) is not dict or type(obj.get("type")) is not str:
        raise ChainError("caveat must be an object with a type")
    kind = obj["type"]
    if kind == "tools":
        _keys(obj, {"tools", "type"}, "tools caveat")
        if type(obj["tools"]) is not list:
            raise ChainError("tools must be a list")
        return ToolsCaveat(tuple(obj["tools"]))
    if kind == "arg":
        _keys(obj, {"constraint", "tool", "type"}, "arg caveat")
        return ArgCaveat(obj["tool"], _constraint_from(obj["constraint"]))
    if kind == "expiry":
        _keys(obj, {"not_after", "type"}, "expiry caveat")
        return ExpiryCaveat(obj["not_after"])
    raise ChainError(f"unknown caveat type {kind!r}")


def encode_caveat(caveat: Caveat) -> bytes:
    """The canonical bytes of a caveat: what gets MACed or signed."""
    return _canonical(_caveat_obj(caveat))


def decode_caveat(data: bytes) -> Caveat:
    """Inverse of encode_caveat. Rejects anything that is not the canonical encoding."""
    if type(data) is not bytes:
        raise ChainError("caveat encoding must be bytes")
    return _caveat_from(_parse_canonical(data))


def _decide(grant: Grant, caveats: tuple[Caveat, ...], call: Any, now: Any) -> Decision:
    """The decision rule both constructions share: base grant AND every caveat."""
    if type(call) is not Call:
        return Decision(False, "not a Call")
    base = grant.decide(call, now)
    if not base.allowed:
        return base
    for i, caveat in enumerate(caveats, start=1):
        reason = caveat.check(call, now)
        if reason is not None:
            return Decision(False, f"caveat {i}: {reason}")
    return base


@dataclass(frozen=True)
class Verified:
    """The contents of a token whose signature chain checked out.

    Built only inside verify, from the verified bytes. This, not the token
    object the caller handed in, is what a decision is made on.
    """

    identifier: str
    grant: Grant
    caveats: tuple[Caveat, ...]

    def decide(self, call: Call, now: float) -> Decision:
        return _decide(self.grant, self.caveats, call, now)


def _split(text: Any, prefix: str) -> list[str]:
    if type(text) is not str:
        raise ChainError("token must be a string")
    if len(text) > MAX_TOKEN_CHARS:
        raise ChainError("token is too long")
    parts = text.split(".")
    if parts[0] != prefix:
        raise ChainError(f"not a {prefix} token")
    return parts[1:]


def _check_caveats(caveats: Any) -> tuple[Caveat, ...]:
    if type(caveats) is not tuple or len(caveats) > MAX_CAVEATS:
        raise ChainError(f"a token carries at most {MAX_CAVEATS} caveats")
    return caveats


# ---------------------------------------------------------------------------
# Construction 1: HMAC chain
# ---------------------------------------------------------------------------


def _mac(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


@dataclass(frozen=True)
class HmacToken:
    """Base grant, caveats and the LAST signature of the HMAC chain.

    The signature is the secret that lets the holder append a caveat, so it is
    kept out of repr. Unverified until HmacAuthority.verify says otherwise.
    """

    identifier: str
    grant: Grant
    caveats: tuple[Caveat, ...] = ()
    signature: bytes = field(default=b"", repr=False)

    def serialize(self) -> str:
        """`tgm1.<root block>.<caveat>...<signature>`, each part unpadded base64url."""
        if type(self.signature) is not bytes or len(self.signature) != _MAC_LEN:
            raise ChainError("signature must be 32 bytes")
        parts = [HMAC_PREFIX, _b64encode(_canonical(_root_obj(self.identifier, self.grant)))]
        parts += [_b64encode(encode_caveat(c)) for c in _check_caveats(self.caveats)]
        parts.append(_b64encode(self.signature))
        text = ".".join(parts)
        if len(text) > MAX_TOKEN_CHARS:
            raise ChainError("token is too long")
        return text

    @classmethod
    def parse(cls, text: str) -> HmacToken:
        """Rebuild a token from its string. The result is NOT verified."""
        parts = _split(text, HMAC_PREFIX)
        if not 2 <= len(parts) <= MAX_CAVEATS + 2:
            raise ChainError("wrong number of token segments")
        identifier, grant = _root_from(_parse_canonical(_b64decode(parts[0])))
        caveats = tuple(decode_caveat(_b64decode(p)) for p in parts[1:-1])
        signature = _b64decode(parts[-1])
        if len(signature) != _MAC_LEN:
            raise ChainError("signature must be 32 bytes")
        return cls(identifier, grant, caveats, signature)


class HmacAuthority:
    """Issues and verifies construction 1 tokens. Whoever verifies can also issue."""

    def __init__(self, root_key: bytes) -> None:
        if type(root_key) is not bytes or len(root_key) < MIN_ROOT_KEY_BYTES:
            raise ChainError(f"root key must be at least {MIN_ROOT_KEY_BYTES} bytes")
        self._root_key = root_key

    def issue(self, identifier: str, grant: Grant) -> HmacToken:
        """sig0 = HMAC(root_key, tag + canonical(identifier, grant))."""
        root = _canonical(_root_obj(identifier, grant))
        return _round_trip(
            HmacToken(identifier, grant, (), _mac(self._root_key, _TAG_HMAC_ROOT + root))
        )

    def verify(self, token: HmacToken | str) -> Verified:
        """Recompute the chain from the root key. Raises ChainError on any mismatch."""
        fresh = _reparse(token, HmacToken)
        sig = _mac(
            self._root_key, _TAG_HMAC_ROOT + _canonical(_root_obj(fresh.identifier, fresh.grant))
        )
        for caveat in fresh.caveats:
            sig = _mac(sig, _TAG_HMAC_CAVEAT + encode_caveat(caveat))
        if not hmac.compare_digest(sig, fresh.signature):
            raise ChainError("signature mismatch: the chain does not lead to this signature")
        return Verified(fresh.identifier, fresh.grant, fresh.caveats)

    def authorize(self, token: HmacToken | str, call: Call, now: float) -> Decision:
        """Verify, then base grant, then every caveat. Never raises: any failure is a deny."""
        return _authorize(lambda: self.verify(token), call, now)


def _authorize(verify: Any, call: Any, now: Any) -> Decision:
    """Run `verify`, then decide. Any exception at all is a deny (fail closed).

    ChainError is the expected failure. Anything else means an object was bent
    into a shape the checks did not foresee (for example through
    object.__setattr__); the answer is still no, and the exception type is
    named so the cause can be found.
    """
    try:
        verified = verify()
    except ChainError as exc:
        return Decision(False, f"invalid token: {exc}")
    except Exception as exc:
        return Decision(False, f"invalid token: unexpected {type(exc).__name__}")
    try:
        return verified.decide(call, now)
    except Exception as exc:
        return Decision(False, f"decision failed: unexpected {type(exc).__name__}")


def _reparse(token: Any, kind: type) -> Any:
    """Turn a token object or string into a fresh object built only from bytes."""
    if type(token) is str:
        return kind.parse(token)
    if type(token) is not kind:
        raise ChainError(f"expected a {kind.__name__} or its serialized string")
    return kind.parse(token.serialize())


def _round_trip(token: Any) -> Any:
    """Return `token` only if its string form parses back to an equal object.

    Run on every token before it is handed out, so the object a caller holds
    and the bytes that were signed always mean the same thing. It also makes
    an oversized result fail here, where it is made, not at a later serialize.
    """
    if type(token).parse(token.serialize()) != token:
        raise ChainError("token does not survive serialization unchanged")
    return token


# ---------------------------------------------------------------------------
# Construction 2: Ed25519 chain
# ---------------------------------------------------------------------------


# Small-order public keys.
#
# Ed25519 points form a group of order 8 * L (L prime). Exactly 8 points have
# an order dividing 8: order 1 (0, 1); order 2 (0, -1); order 4 (+-sqrt(-1), 0);
# order 8, four points (+-x8, +-y8). A key is encoded as y in the low 255 bits,
# little-endian, and the parity of x in the top bit. So the 8 points use only
# five y values modulo p = 2^255 - 19:
#
#     0, 1, p - 1, y8, p - y8
#
# A lenient decoder (OpenSSL is one) reduces y modulo p, so y and y + p are
# the same point whenever y + p < 2^255, that is whenever y < 19. Of the five
# values only 0 and 1 are that small, which adds two more spellings, p and
# p + 1. That makes seven 255-bit y fields. Each is listed with the sign bit
# clear and set: for x != 0 the two are the point and its negative, both of
# small order; for x = 0 (y = 1 and y = p - 1 and their aliases) the set bit
# is a non-canonical spelling of the same point. 7 * 2 = 14 encodings, 8 of
# them canonical and 6 not. Nothing else decodes to a small-order point,
# because decoding is determined by (y mod p, sign bit). The test file checks
# this set against 8 * P computed with its own curve arithmetic.
_P = 2**255 - 19
_Y_ORDER_8 = int.from_bytes(
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), "little"
)
_SMALL_ORDER_Y = (0, 1, _P - 1, _Y_ORDER_8, _P - _Y_ORDER_8, _P, _P + 1)
_SMALL_ORDER_KEYS = frozenset(
    (y | sign << 255).to_bytes(_KEY_LEN, "little") for y in _SMALL_ORDER_Y for sign in (0, 1)
)


def _check_public_bytes(raw: bytes, what: str) -> bytes:
    """Refuse the 14 encodings of small-order points. See the note above."""
    if raw in _SMALL_ORDER_KEYS:
        raise ChainError(f"{what} is a small-order public key")
    return raw


def _block_tag(index: int) -> bytes:
    """Block 0 and the caveat blocks are signed under different tags."""
    return _TAG_KEY_ROOT if index == 0 else _TAG_KEY_CAVEAT


def _block_bytes(index: int, body: dict[str, Any], next_key: bytes) -> bytes:
    """What block `index` signs: its payload, its position and the next public key.

    One canonical JSON object, so there is no way to shift bytes between the
    three fields and keep the same message.
    """
    return _canonical({"body": body, "i": index, "next": _b64encode(next_key)})


def _seal_bytes(signatures: tuple[bytes, ...]) -> bytes:
    digest = hashlib.sha256(b"".join(signatures)).hexdigest()
    return _TAG_KEY_SEAL + _canonical({"blocks": len(signatures), "digest": digest})


def _public_key(raw: bytes, what: str) -> Ed25519PublicKey:
    try:
        return Ed25519PublicKey.from_public_bytes(_check_public_bytes(raw, f"{what} key"))
    except ValueError as exc:
        raise ChainError(f"bad public key: {exc}") from None


def _check_signature(public: bytes, signature: bytes, message: bytes, what: str) -> None:
    try:
        _public_key(public, what).verify(signature, message)
    except InvalidSignature:
        raise ChainError(f"{what}: bad signature") from None


@dataclass(frozen=True)
class KeyToken:
    """Base grant, caveats, one signature and one "next" public key per block.

    `proof` is what shows the token was not cut short: the private key matching
    the last block's next key (unsealed, 32 bytes), or a signature made with
    that key (sealed, 64 bytes). Unverified until verify_public says otherwise.
    """

    identifier: str
    grant: Grant
    caveats: tuple[Caveat, ...]
    next_keys: tuple[bytes, ...]
    signatures: tuple[bytes, ...]
    proof: bytes = field(repr=False)
    sealed: bool = False

    def _blocks(self) -> list[bytes]:
        caveats = _check_caveats(self.caveats)
        n = len(caveats) + 1
        for name, items, size in (
            ("next_keys", self.next_keys, _KEY_LEN),
            ("signatures", self.signatures, _SIG_LEN),
        ):
            if type(items) is not tuple or len(items) != n:
                raise ChainError(f"{name} must have one entry per block")
            if not all(type(b) is bytes and len(b) == size for b in items):
                raise ChainError(f"{name} entries must be {size} bytes")
        for index, key in enumerate(self.next_keys):
            _check_public_bytes(key, f"block {index}: next key")
        if type(self.sealed) is not bool or type(self.proof) is not bytes:
            raise ChainError("bad proof")
        if len(self.proof) != (_SIG_LEN if self.sealed else _KEY_LEN):
            raise ChainError("proof has the wrong length")
        bodies = [_root_obj(self.identifier, self.grant)] + [_caveat_obj(c) for c in caveats]
        return [_block_bytes(i, body, self.next_keys[i]) for i, body in enumerate(bodies)]

    def serialize(self) -> str:
        """`tgk1.<block>.<sig>...<k|s>.<proof>`: k carries a private key, s a seal."""
        parts = [KEY_PREFIX]
        for block, signature in zip(self._blocks(), self.signatures, strict=True):
            parts += [_b64encode(block), _b64encode(signature)]
        parts += ["s" if self.sealed else "k", _b64encode(self.proof)]
        text = ".".join(parts)
        if len(text) > MAX_TOKEN_CHARS:
            raise ChainError("token is too long")
        return text

    @classmethod
    def parse(cls, text: str) -> KeyToken:
        """Rebuild a token from its string. The result is NOT verified."""
        parts = _split(text, KEY_PREFIX)
        if len(parts) < 4 or len(parts) % 2 or len(parts) > 2 * (MAX_CAVEATS + 2):
            raise ChainError("wrong number of token segments")
        if parts[-2] not in ("k", "s"):
            raise ChainError("bad proof marker")
        sealed = parts[-2] == "s"
        proof = _b64decode(parts[-1])
        bodies, next_keys, signatures = [], [], []
        for index in range((len(parts) - 2) // 2):
            block = _keys(
                _parse_canonical(_b64decode(parts[2 * index])), {"body", "i", "next"}, "block"
            )
            if type(block["i"]) is not int or block["i"] != index:
                raise ChainError(f"block {index} is out of position")
            bodies.append(block["body"])
            next_keys.append(_b64decode(block["next"]))
            signatures.append(_b64decode(parts[2 * index + 1]))
        identifier, grant = _root_from(bodies[0])
        caveats = tuple(_caveat_from(body) for body in bodies[1:])
        token = cls(identifier, grant, caveats, tuple(next_keys), tuple(signatures), proof, sealed)
        token._blocks()  # length checks
        return token


def _verify_key_token(token: KeyToken | str, root_public: bytes) -> Verified:
    fresh: KeyToken = _reparse(token, KeyToken)
    signer = root_public
    for index, block in enumerate(fresh._blocks()):
        _check_signature(
            signer, fresh.signatures[index], _block_tag(index) + block, f"block {index}"
        )
        signer = fresh.next_keys[index]
    # The chain is intact up to the last block. Now prove nothing was cut off
    # the end: only the real last key can produce this proof.
    if fresh.sealed:
        _check_signature(signer, fresh.proof, _seal_bytes(fresh.signatures), "seal")
    else:
        derived = Ed25519PrivateKey.from_private_bytes(fresh.proof).public_key().public_bytes_raw()
        if not hmac.compare_digest(derived, signer):
            raise ChainError("the carried private key does not match the last block's next key")
    return Verified(fresh.identifier, fresh.grant, fresh.caveats)


def _raw_public(key: Any) -> bytes:
    if isinstance(key, Ed25519PublicKey):
        return _check_public_bytes(key.public_bytes_raw(), "root public key")
    if type(key) is bytes and len(key) == _KEY_LEN:
        return _check_public_bytes(key, "root public key")
    raise ChainError("root public key must be an Ed25519PublicKey or its 32 raw bytes")


def verify_public(token: KeyToken | str, root_public_key: Ed25519PublicKey | bytes) -> Verified:
    """Verify a construction 2 token with nothing but the root PUBLIC key.

    Raises ChainError unless block 0 is signed by the root key, every later
    block is signed by the key the block before it named, every block sits at
    the position it was signed for, and the proof matches the last named key.
    """
    return _verify_key_token(token, _raw_public(root_public_key))


def authorize_public(
    token: KeyToken | str, root_public_key: Ed25519PublicKey | bytes, call: Call, now: float
) -> Decision:
    """verify_public, then base grant, then every caveat. Never raises: failure is a deny."""
    return _authorize(lambda: verify_public(token, root_public_key), call, now)


class KeyAuthority:
    """Issues construction 2 tokens. Only issuing needs the root private key."""

    def __init__(self, root_private_key: Ed25519PrivateKey | bytes) -> None:
        if type(root_private_key) is bytes and len(root_private_key) == _KEY_LEN:
            root_private_key = Ed25519PrivateKey.from_private_bytes(root_private_key)
        if not isinstance(root_private_key, Ed25519PrivateKey):
            raise ChainError("root key must be an Ed25519PrivateKey or its 32 raw bytes")
        _check_public_bytes(root_private_key.public_key().public_bytes_raw(), "root public key")
        self._root = root_private_key

    @property
    def public_key(self) -> bytes:
        """The 32 raw bytes of the root public key. Safe to publish."""
        return self._root.public_key().public_bytes_raw()

    def issue(self, identifier: str, grant: Grant) -> KeyToken:
        """Block 0: the grant and a fresh public key, signed by the root key."""
        first = Ed25519PrivateKey.generate()
        next_key = first.public_key().public_bytes_raw()
        block = _block_bytes(0, _root_obj(identifier, grant), next_key)
        signature = self._root.sign(_block_tag(0) + block)
        return _round_trip(
            KeyToken(identifier, grant, (), (next_key,), (signature,), first.private_bytes_raw())
        )

    def verify(self, token: KeyToken | str) -> Verified:
        return verify_public(token, self.public_key)

    def authorize(self, token: KeyToken | str, call: Call, now: float) -> Decision:
        return authorize_public(token, self.public_key, call, now)


def _last_key(token: KeyToken) -> Ed25519PrivateKey:
    if type(token) is not KeyToken:
        raise ChainError("expected a KeyToken")
    token._blocks()
    if token.sealed:
        raise ChainError("token is sealed: it can be used but not attenuated")
    key = Ed25519PrivateKey.from_private_bytes(token.proof)
    if not hmac.compare_digest(key.public_key().public_bytes_raw(), token.next_keys[-1]):
        raise ChainError("the carried private key does not match the last block's next key")
    return key


def seal(token: KeyToken) -> KeyToken:
    """Swap the last private key for a signature made with it.

    The sealed token verifies and authorizes exactly as before, but nobody,
    including its holder, can append a block to it.
    """
    key = _last_key(token)
    return KeyToken(
        token.identifier,
        token.grant,
        token.caveats,
        token.next_keys,
        token.signatures,
        key.sign(_seal_bytes(token.signatures)),
        True,
    )


# ---------------------------------------------------------------------------
# Attenuation: the holder's operation. No authority, no root key, no network.
# ---------------------------------------------------------------------------


def attenuate(token: HmacToken | KeyToken, caveat: Caveat) -> HmacToken | KeyToken:
    """Return a NEW token with `caveat` appended, using only what the token carries.

    HMAC chain: the new signature is HMAC(old signature, tag + canonical(caveat)).
    Ed25519 chain: the carried private key signs a block holding the caveat,
    its position and a fresh public key; the new token carries the fresh
    private key and no trace of the old one.

    Raises ChainError here, at the point of narrowing, if the result would be
    too long to serialize or would not parse back to the same token.
    """
    if type(token) not in (HmacToken, KeyToken):
        raise ChainError("expected an HmacToken or a KeyToken")
    encoded = encode_caveat(caveat)  # also rejects anything that is not an exact caveat type
    if len(_check_caveats(token.caveats)) >= MAX_CAVEATS:
        raise ChainError(f"a token carries at most {MAX_CAVEATS} caveats")
    caveats = (*token.caveats, caveat)
    if type(token) is HmacToken:
        if type(token.signature) is not bytes or len(token.signature) != _MAC_LEN:
            raise ChainError("signature must be 32 bytes")
        signature = _mac(token.signature, _TAG_HMAC_CAVEAT + encoded)
        return _round_trip(HmacToken(token.identifier, token.grant, caveats, signature))
    signer = _last_key(token)
    fresh = Ed25519PrivateKey.generate()
    next_key = fresh.public_key().public_bytes_raw()
    block = _block_bytes(len(caveats), _caveat_obj(caveat), next_key)
    return _round_trip(
        KeyToken(
            token.identifier,
            token.grant,
            caveats,
            (*token.next_keys, next_key),
            (*token.signatures, signer.sign(_block_tag(len(caveats)) + block)),
            fresh.private_bytes_raw(),
        )
    )
