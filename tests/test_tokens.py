"""Tokens: mint, verify, exchange, revoke, authorize, and attempts to break them."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import string
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st
from jwt import PyJWS

sys.path.insert(0, str(Path(__file__).resolve().parent))

from strategies import grants, scenarios  # noqa: E402
from toolgate import Call, Capability, Constraint, Grant, check_attenuation  # noqa: E402
from toolgate.store import MemoryStore, SqliteStore  # noqa: E402
from toolgate.tokens import (  # noqa: E402
    Authority,
    Authorization,
    EscalationError,
    TokenError,
    Verified,
)

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
ISS = "https://gateway.test"
AUD = "gateway"
T0 = 1_000_000


class Clock:
    """A clock the test moves by hand, so nothing ever sleeps."""

    def __init__(self, now: float = T0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def make(store=None, clock=None, key=KEY, **kwargs) -> tuple[Authority, Clock]:
    clock = clock or Clock()
    store = store if store is not None else MemoryStore()
    return Authority(key, kwargs.pop("issuer", ISS), AUD, store, clock=clock, **kwargs), clock


def cap(tool: str, max_calls: int | None = None, **args: Any) -> Capability:
    """cap("read", path={"glob": "reports/*"}) and so on."""
    return Capability.from_dict({"tool": tool, "args": args, "max_calls": max_calls})


READ = cap("read", path={"glob": "reports/*"})
SEND = cap("send", to={"in": ["a@x.test", "b@x.test"]}, amount={"max": 100})
GRANT = Grant((READ, SEND), T0 + 3600)
READ_CALL = Call("read", {"path": "reports/q3.txt"})


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def claims_of(token: str) -> dict[str, Any]:
    return json.loads(unb64(token.split(".")[1]))


def sign(payload: dict[str, Any] | bytes, key=KEY, headers=None) -> str:
    """Sign arbitrary bytes with the gateway key.

    This models a bug in the signer or a second service sharing the key:
    verify must not lean on "only well-formed payloads are ever signed".
    """
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return PyJWS().encode(raw, key, algorithm="EdDSA", headers=headers)


def resign(token: str, **changes: Any) -> str:
    """The same claims with some replaced (or removed when the value is ...)."""
    claims = claims_of(token)
    for name, value in changes.items():
        if value is ...:
            claims.pop(name)
        else:
            claims[name] = value
    return sign(claims)


def code_of(authority: Authority, token: Any, **kwargs: Any) -> str:
    with pytest.raises(TokenError) as info:
        authority.verify(token, **kwargs)
    return info.value.code


# ---------------------------------------------------------------------------
# mint and verify: the happy path
# ---------------------------------------------------------------------------


def test_mint_then_verify_returns_what_was_granted():
    authority, _ = make()
    token = authority.mint("user:alice", GRANT, "agent:orchestrator", ttl=300)
    v = authority.verify(token)
    assert type(v) is Verified
    assert v.sub == "user:alice"
    assert v.actors == ("agent:orchestrator",)
    assert v.grant == Grant(GRANT.capabilities, T0 + 300)
    assert v.chain == () and v.depth == 0
    assert v.der == ((), ())
    assert (v.iat, v.exp) == (T0, T0 + 300)
    with pytest.raises(AttributeError):
        v.sub = "user:mallory"  # frozen


def test_claims_on_the_wire():
    authority, _ = make(new_id=lambda: "id-1")
    claims = claims_of(authority.mint("user:alice", GRANT, "agent:a", ttl=300))
    assert claims == {
        "iss": ISS,
        "aud": AUD,
        "sub": "user:alice",
        "act": {"sub": "agent:a"},
        "iat": T0,
        "exp": T0 + 300,
        "jti": "id-1",
        "caps": [c.to_dict() for c in GRANT.capabilities],
        "chain": [],
        "der": [[], []],
    }


def test_header_is_eddsa_and_nothing_else():
    authority, _ = make()
    header = json.loads(unb64(authority.mint("u", GRANT, "a", ttl=60).split(".")[0]))
    assert header == {"alg": "EdDSA", "typ": "JWT"}


def test_exp_is_the_earlier_of_ttl_and_grant_expiry():
    authority, _ = make()
    short_grant = Grant((READ,), T0 + 10)
    assert authority.verify(authority.mint("u", short_grant, "a", ttl=300)).exp == T0 + 10
    assert authority.verify(authority.mint("u", GRANT, "a", ttl=5)).exp == T0 + 5


def test_ttl_is_capped_at_max_ttl():
    authority, _ = make(max_ttl=120)
    assert authority.verify(authority.mint("u", GRANT, "a", ttl=10**9)).exp == T0 + 120
    default, _ = make()
    assert default.verify(default.mint("u", GRANT, "a", ttl=10**9)).exp == T0 + 900


def test_token_ids_are_random_and_unguessable_by_default():
    authority, _ = make()
    ids = {authority.verify(authority.mint("u", GRANT, "a", ttl=60)).jti for _ in range(50)}
    assert len(ids) == 50
    assert all(len(i) >= 22 for i in ids)  # 16 random bytes, base64url


def test_a_repeated_token_id_is_refused_at_mint():
    authority, _ = make(new_id=lambda: "same")
    authority.mint("u", GRANT, "a", ttl=60)
    with pytest.raises(ValueError, match="already registered"):
        authority.mint("u", GRANT, "a", ttl=60)


@pytest.mark.parametrize("ttl", [0, -1, True, "60", None, float("nan"), float("inf")])
def test_mint_rejects_bad_ttl(ttl):
    authority, _ = make()
    with pytest.raises(ValueError):
        authority.mint("u", GRANT, "a", ttl=ttl)


@pytest.mark.parametrize("name", ["", None, 7, b"u", "x" * 300])
def test_mint_rejects_bad_names(name):
    authority, _ = make()
    with pytest.raises(ValueError):
        authority.mint(name, GRANT, "a", ttl=60)
    with pytest.raises(ValueError):
        authority.mint("u", GRANT, name, ttl=60)


def test_mint_rejects_an_expired_grant_and_non_grants():
    authority, _ = make()
    with pytest.raises(ValueError, match="expired"):
        authority.mint("u", Grant((READ,), T0), "a", ttl=60)
    with pytest.raises(ValueError):
        authority.mint("u", GRANT.to_dict(), "a", ttl=60)


def test_mint_rebuilds_the_grant_instead_of_trusting_the_object():
    # A frozen dataclass can be altered behind its validation. What gets signed
    # is a copy rebuilt from JSON, so the smuggled value is validated again.
    authority, _ = make()
    tampered = Grant((cap("read", path={"glob": "reports/*"}),), T0 + 60)
    object.__setattr__(tampered.capabilities[0].constraints[0], "op", "regex")
    with pytest.raises(ValueError, match="unknown operator"):
        authority.mint("u", tampered, "a", ttl=60)


def test_constructor_validates_its_arguments():
    store = MemoryStore()
    with pytest.raises(ValueError):
        Authority(KEY.public_key(), ISS, AUD, store)
    with pytest.raises(ValueError):
        Authority(b"k" * 32, ISS, AUD, store)
    with pytest.raises(ValueError):
        Authority(KEY, "", AUD, store)
    with pytest.raises(ValueError):
        Authority(KEY, ISS, AUD, store, max_depth=-1)
    with pytest.raises(ValueError):
        Authority(KEY, ISS, AUD, store, max_ttl=0)


# ---------------------------------------------------------------------------
# verify: the "done when" list
# ---------------------------------------------------------------------------


def test_expired_token_is_rejected():
    authority, clock = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    clock.now = T0 + 59
    authority.verify(token)
    clock.now = T0 + 60  # exactly at expiry is already too late
    assert code_of(authority, token) == "expired"
    clock.now = T0 + 10**6
    assert code_of(authority, token) == "expired"


def test_token_from_the_future_is_rejected():
    authority, clock = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    clock.now = T0 - 1
    assert code_of(authority, token) == "not_yet_valid"


def test_wrong_audience_is_rejected():
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    assert code_of(authority, token, audience="some-other-service") == "wrong_audience"
    assert code_of(authority, resign(token, aud="some-other-service")) == "wrong_audience"
    authority.verify(token, audience=AUD)


@pytest.mark.parametrize("aud", [[AUD], [AUD, "other"], "", None, 1, {"aud": AUD}])
def test_audience_must_be_exactly_one_string(aud):
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    assert code_of(authority, resign(token, aud=aud)) in ("malformed", "wrong_audience")


@pytest.mark.parametrize("audience", [[AUD], "", 0, b"gateway"])
def test_verify_rejects_a_non_string_expected_audience(audience):
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    assert code_of(authority, token, audience=audience) == "wrong_audience"


def test_wrong_issuer_is_rejected():
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    assert code_of(authority, resign(token, iss="https://evil.test")) == "wrong_issuer"
    assert code_of(authority, resign(token, iss=[ISS])) == "malformed"


def test_tampered_payload_is_rejected():
    authority, _ = make()
    token = authority.mint("user:alice", GRANT, "a", ttl=60)
    header, payload, signature = token.split(".")
    claims = claims_of(token)
    claims["sub"] = "user:admin"
    forged = ".".join([header, b64(json.dumps(claims, separators=(",", ":")).encode()), signature])
    assert code_of(authority, forged) == "bad_signature"


def test_tampered_signature_is_rejected():
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    head, signature = token.rsplit(".", 1)
    raw = bytearray(unb64(signature))
    raw[10] ^= 0x01
    assert code_of(authority, f"{head}.{b64(bytes(raw))}") == "bad_signature"
    assert code_of(authority, f"{head}.{b64(bytes(64))}") == "bad_signature"
    assert code_of(authority, f"{head}.{b64(bytes(raw[:32]))}") == "bad_signature"


def test_token_signed_with_another_key_is_rejected():
    store = MemoryStore()
    authority, _ = make(store=store)
    impostor, _ = make(store=store, key=OTHER_KEY)
    token = impostor.mint("u", GRANT, "a", ttl=60)
    impostor.verify(token)
    assert code_of(authority, token) == "bad_signature"


def test_revoked_token_is_rejected():
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    jti = authority.verify(token).jti
    authority.revoke(jti)
    assert code_of(authority, token) == "revoked"
    with pytest.raises(TokenError) as info:
        authority.authorize(token, READ_CALL)
    assert info.value.code == "revoked"


def test_revoking_an_ancestor_invalidates_the_grandchild():
    authority, _ = make()
    root = authority.mint("u", GRANT, "orchestrator", ttl=300)
    child = authority.exchange(root, [READ], "researcher", ttl=200)
    grandchild = authority.exchange(child, [READ], "summarizer", ttl=100)
    sibling = authority.exchange(root, [SEND], "mailer", ttl=200)
    for token in (root, child, grandchild, sibling):
        authority.verify(token)

    authority.revoke(authority.verify(child).jti)
    assert code_of(authority, child) == "revoked"
    assert code_of(authority, grandchild) == "revoked"
    authority.verify(root)  # revocation flows down, not up
    authority.verify(sibling)  # and not sideways

    authority.revoke(authority.verify(root).jti)
    assert code_of(authority, root) == "revoked"
    assert code_of(authority, sibling) == "revoked"


def test_a_revoked_token_cannot_be_exchanged_nor_can_its_children():
    authority, _ = make()
    root = authority.mint("u", GRANT, "orchestrator", ttl=300)
    child = authority.exchange(root, [READ], "researcher", ttl=200)
    authority.revoke(authority.verify(root).jti)
    for token in (root, child):  # the child is still unexpired and correctly signed
        with pytest.raises(TokenError) as info:
            authority.exchange(token, [READ], "x", ttl=10)
        assert info.value.code == "revoked"


def test_revoke_rejects_non_string_ids():
    authority, _ = make()
    for bad in ("", None, 5):
        with pytest.raises(ValueError):
            authority.revoke(bad)


def test_depth_limit():
    authority, _ = make(max_depth=2)
    token = authority.mint("u", GRANT, "a0", ttl=300)
    token = authority.exchange(token, [READ], "a1", ttl=300)
    token = authority.exchange(token, [READ], "a2", ttl=300)
    assert authority.verify(token).depth == 2
    with pytest.raises(TokenError) as info:
        authority.exchange(token, [READ], "a3", ttl=300)
    assert info.value.code == "depth_exceeded"


def test_default_depth_limit_is_four():
    authority, _ = make()
    token = authority.mint("u", GRANT, "a0", ttl=300)
    for n in range(4):
        token = authority.exchange(token, [READ], f"a{n + 1}", ttl=300)
    with pytest.raises(TokenError) as info:
        authority.exchange(token, [READ], "a5", ttl=300)
    assert info.value.code == "depth_exceeded"


def test_a_deeper_token_from_a_laxer_authority_is_rejected_by_a_stricter_one():
    store = MemoryStore()
    lax, _ = make(store=store, max_depth=5)
    strict, _ = make(store=store, max_depth=1)
    token = lax.mint("u", GRANT, "a0", ttl=300)
    token = lax.exchange(token, [READ], "a1", ttl=300)
    strict.verify(token)
    token = lax.exchange(token, [READ], "a2", ttl=300)
    assert code_of(strict, token) == "depth_exceeded"


def test_max_depth_zero_forbids_all_delegation():
    authority, _ = make(max_depth=0)
    token = authority.mint("u", GRANT, "a0", ttl=300)
    with pytest.raises(TokenError) as info:
        authority.exchange(token, [READ], "a1", ttl=300)
    assert info.value.code == "depth_exceeded"


# ---------------------------------------------------------------------------
# verify: algorithm confusion and header games
# ---------------------------------------------------------------------------


def with_header(token: str, header: dict[str, Any], signature: str | None = None) -> str:
    _, payload, old_signature = token.split(".")
    head = b64(json.dumps(header, separators=(",", ":")).encode())
    return f"{head}.{payload}.{old_signature if signature is None else signature}"


@pytest.mark.parametrize("alg", ["none", "None", "NONE", "nOnE", "", None])
def test_alg_none_is_rejected(alg):
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    header = {"alg": alg, "typ": "JWT"}
    assert code_of(authority, with_header(token, header, signature="")) == "bad_algorithm"
    assert code_of(authority, with_header(token, header)) == "bad_algorithm"


def test_hs256_signed_with_the_public_key_is_rejected():
    # The classic confusion: the verifier holds a public key, the attacker
    # says "HS256" and uses those public bytes as the HMAC secret.
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    public = authority.public_key
    secrets_to_try = [
        public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        public.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH),
        b"",
    ]
    for secret in secrets_to_try:
        for alg, digest in (("HS256", hashlib.sha256), ("HS512", hashlib.sha512)):
            head = b64(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
            signing_input = f"{head}.{token.split('.')[1]}"
            mac = hmac.new(secret, signing_input.encode(), digest).digest()
            assert code_of(authority, f"{signing_input}.{b64(mac)}") == "bad_algorithm"


@pytest.mark.parametrize("alg", ["eddsa", "EdDSA ", "Ed25519", "ES256", "RS256", ["EdDSA"]])
def test_other_algorithm_names_are_rejected(alg):
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    assert code_of(authority, with_header(token, {"alg": alg, "typ": "JWT"})) == "bad_algorithm"


@pytest.mark.parametrize(
    "extra",
    [
        {"kid": "1"},
        {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}},
        {"jku": "https://evil.test/keys"},
        {"x5u": "https://evil.test/cert"},
        {"crit": ["exp"]},
        {"b64": False},
        {"typ": "at+jwt"},
        {"typ": ...},
    ],
)
def test_correctly_signed_tokens_with_extra_header_parameters_are_rejected(extra):
    # Signed with the real key, so only the header check can stop these.
    authority, _ = make()
    claims = claims_of(authority.mint("u", GRANT, "a", ttl=60))
    header = {"alg": "EdDSA", "typ": "JWT", **extra}
    if header["typ"] is ...:
        del header["typ"]
    head = b64(json.dumps(header).encode())
    body = b64(json.dumps(claims).encode())
    signature = b64(KEY.sign(f"{head}.{body}".encode()))
    assert code_of(authority, f"{head}.{body}.{signature}") == "malformed"


def test_duplicate_keys_in_the_header_are_rejected():
    authority, _ = make()
    claims = claims_of(authority.mint("u", GRANT, "a", ttl=60))
    head = b64(b'{"alg":"none","typ":"JWT","alg":"EdDSA"}')
    body = b64(json.dumps(claims).encode())
    signature = b64(KEY.sign(f"{head}.{body}".encode()))
    assert code_of(authority, f"{head}.{body}.{signature}") == "malformed"


# ---------------------------------------------------------------------------
# verify: strict payload parsing
# ---------------------------------------------------------------------------


def test_duplicate_json_keys_are_rejected_even_when_correctly_signed():
    authority, _ = make()
    token = authority.mint("user:alice", GRANT, "a", ttl=60)
    raw = unb64(token.split(".")[1]).decode()
    assert raw.endswith("}")
    # Python's json would keep the last "sub"; another parser might keep the first.
    doubled = raw[:-1] + ',"sub":"user:admin"}'
    assert json.loads(doubled)["sub"] == "user:admin"
    assert code_of(authority, sign(doubled.encode())) == "malformed"


def test_duplicate_keys_nested_inside_a_capability_are_rejected():
    authority, _ = make()
    token = authority.mint("u", Grant((cap("pay", amount={"max": 5}),), T0 + 60), "a", ttl=60)
    raw = unb64(token.split(".")[1]).decode()
    doubled = raw.replace('{"max":5}', '{"max":5,"max":5000}')
    assert doubled != raw
    assert code_of(authority, sign(doubled.encode())) == "malformed"


@pytest.mark.parametrize("claim", ["nbf", "scope", "admin", "cnf", "expires_at", "Sub", ""])
def test_unknown_claims_are_rejected(claim):
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    assert code_of(authority, resign(token, **{claim: 1})) == "malformed"


@pytest.mark.parametrize(
    "claim", ["iss", "aud", "sub", "act", "iat", "exp", "jti", "caps", "chain", "der"]
)
def test_every_claim_is_required(claim):
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    assert code_of(authority, resign(token, **{claim: ...})) == "malformed"
    if claim not in ("iss", "aud"):
        assert code_of(authority, resign(token, **{claim: None})) == "malformed"


@pytest.mark.parametrize(
    "exp",
    [True, "9999999999", [9999999999], {"v": 1}, None, "never"],
)
def test_exp_of_the_wrong_type_is_malformed(exp):
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    assert code_of(authority, resign(token, exp=exp)) == "malformed"


@pytest.mark.parametrize("exp", [-1, 0, -1e300, T0 - 0.5, T0])
def test_negative_or_past_exp_is_rejected(exp):
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    assert code_of(authority, resign(token, exp=exp)) in ("expired", "malformed")


@pytest.mark.parametrize("literal", ["1e999", "NaN", "Infinity", "-Infinity", "1" + "0" * 5000])
def test_exp_that_is_not_a_finite_number_is_malformed(literal):
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    raw = unb64(token.split(".")[1]).decode()
    forged = raw.replace(f'"exp":{T0 + 60}', f'"exp":{literal}')
    assert forged != raw
    assert code_of(authority, sign(forged.encode())) == "malformed"


def test_float_exp_is_accepted_and_honoured_exactly():
    authority, clock = make()
    token = authority.mint("u", Grant((READ,), T0 + 2.5), "a", ttl=60)
    assert authority.verify(token).exp == T0 + 2.5
    clock.now = T0 + 2.4
    authority.verify(token)
    clock.now = T0 + 2.5
    assert code_of(authority, token) == "expired"


@pytest.mark.parametrize("iat", [True, "0", None, [], T0 + 60, T0 + 61])
def test_bad_iat_is_rejected(iat):
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    assert code_of(authority, resign(token, iat=iat)) in ("malformed", "not_yet_valid")


@pytest.mark.parametrize("value", ["", 5, None, ["u"], {"id": "u"}, True, "x" * 300])
def test_sub_and_jti_must_be_non_empty_strings(value):
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    assert code_of(authority, resign(token, sub=value)) == "malformed"
    assert code_of(authority, resign(token, jti=value)) == "malformed"


@pytest.mark.parametrize(
    "act",
    [
        "agent",
        None,
        [],
        {},
        {"sub": ""},
        {"sub": 5},
        {"sub": "a", "role": "admin"},
        {"sub": "a", "act": {"sub": "b"}},  # deeper than a root token's chain
        {"sub": "a", "act": None},
        {"sub": "a", "act": "b"},
    ],
)
def test_malformed_act_is_rejected(act):
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    assert code_of(authority, resign(token, act=act)) == "malformed"


def test_act_nesting_must_match_the_chain_length():
    authority, _ = make()
    root = authority.mint("u", GRANT, "a0", ttl=60)
    child = authority.exchange(root, [READ], "a1", ttl=60)
    assert code_of(authority, resign(child, act={"sub": "a1"})) == "malformed"


@pytest.mark.parametrize(
    "caps",
    [
        None,
        "all",
        {"tool": "read"},
        ["read"],
        [None],
        [{"tool": "read", "args": {}, "admin": True}],
        [{"tool": "", "args": {}}],
        [{"tool": 5, "args": {}}],
        [{"args": {}}],
        [{"tool": "read", "args": []}],
        [{"tool": "read", "args": {"path": {"regex": ".*"}}}],
        [{"tool": "read", "args": {"path": {}}}],
        [{"tool": "read", "args": {"path": {"any": 1}}}],
        [{"tool": "read", "args": {"path": {"in": []}}}],
        [{"tool": "read", "args": {"path": {"eq": None}}}],
        [{"tool": "read", "args": {"path": {"max": "9"}}}],
        [{"tool": "read", "args": {}, "max_calls": 0}],
        [{"tool": "read", "args": {}, "max_calls": -3}],
        [{"tool": "read", "args": {}, "max_calls": True}],
        [{"tool": "read", "args": {}, "max_calls": 2.0}],
        [{"tool": "read", "args": {}, "max_calls": "2"}],
    ],
)
def test_malformed_caps_are_rejected(caps):
    authority, _ = make()
    token = authority.mint("u", Grant((READ,), T0 + 60), "a", ttl=60)
    der = [[] for _ in caps] if isinstance(caps, list) else [[]]
    assert code_of(authority, resign(token, caps=caps, der=der)) == "malformed"


@pytest.mark.parametrize(
    "chain",
    [None, "p", {"0": "p"}, [1], [None], [""], [["p"]], ["p", "p"], ["x" * 300]],
)
def test_malformed_chain_is_rejected(chain):
    authority, _ = make()
    token = authority.mint("u", Grant((READ,), T0 + 60), "a", ttl=60)
    n = len(chain) if isinstance(chain, list) else 1
    act: dict[str, Any] = {"sub": "a"}
    for _ in range(n):
        act = {"sub": "a", "act": act}
    forged = resign(token, chain=chain, der=[[0] * n], act=act)
    assert code_of(authority, forged) == "malformed"


def test_chain_must_not_contain_the_token_itself():
    authority, _ = make()
    token = authority.mint("u", Grant((READ,), T0 + 60), "a", ttl=60)
    jti = claims_of(token)["jti"]
    forged = resign(token, chain=[jti], der=[[0]], act={"sub": "a", "act": {"sub": "b"}})
    assert code_of(authority, forged) == "malformed"


def test_enormous_chain_is_rejected_by_the_depth_limit():
    authority, _ = make()
    token = authority.mint("u", Grant((READ,), T0 + 60), "a", ttl=60)
    chain = [f"t{n}" for n in range(2000)]
    assert code_of(authority, resign(token, chain=chain, der=[[0] * 2000])) == "depth_exceeded"
    five = [f"t{n}" for n in range(5)]
    assert code_of(authority, resign(token, chain=five, der=[[0] * 5])) == "depth_exceeded"


def test_oversized_token_is_rejected_before_any_parsing():
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    head, payload, signature = token.split(".")
    assert code_of(authority, f"{head}.{payload + 'A' * 70_000}.{signature}") == "malformed"
    assert code_of(authority, resign(token, sub="x" * 70_000)) == "malformed"


@pytest.mark.parametrize(
    "der",
    [
        None,
        "0",
        {},
        [],  # no entry for the one capability
        [[0], [0]],  # two entries for one capability
        [[]],  # no index for the one ancestor
        [[0, 0]],  # two indices for one ancestor
        [0],
        [None],
        [[-1]],
        [[True]],
        [[0.0]],
        [["0"]],
        [[None]],
        [[10**6]],
        [[2**70]],
        [[[0]]],
    ],
)
def test_malformed_der_is_rejected(der):
    authority, _ = make()
    root = authority.mint("u", Grant((READ,), T0 + 60), "a0", ttl=60)
    child = authority.exchange(root, [READ], "a1", ttl=60)
    assert claims_of(child)["der"] == [[0]]
    assert code_of(authority, resign(child, der=der)) == "malformed"


@pytest.mark.parametrize(
    "token",
    [
        None,
        b"a.b.c",
        7,
        "",
        ".",
        "..",
        "a.b",
        "a.b.c.d",
        "not a token",
        "e30.e30.e30",
        "e30.e30.",
        "W10.e30.AAAA",  # header is a JSON list
        "bnVsbA.e30.AAAA",  # header is JSON null
        "eyJhbGciOiJFZERTQSJ9.e30.AAAA",
    ],
)
def test_garbage_is_rejected_with_a_token_error(token):
    authority, _ = make()
    with pytest.raises(TokenError):
        authority.verify(token)
    with pytest.raises(TokenError):
        authority.authorize(token, READ_CALL)
    with pytest.raises(TokenError):
        authority.exchange(token, [READ], "x", ttl=10)


@pytest.mark.parametrize("payload", [b"[]", b"null", b'"x"', b"5", b"", b"{", b"\xff\xfe", b"{}"])
def test_correctly_signed_non_object_payloads_are_malformed(payload):
    authority, _ = make()
    assert code_of(authority, sign(payload)) == "malformed"


def test_deeply_nested_json_is_malformed_not_a_crash():
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    deep: Any = "x"
    for _ in range(600):  # stays under the 64 kB limit, exceeds every sane depth
        deep = [deep]
    forged = sign(json.dumps({**claims_of(token), "caps": deep}).encode())
    assert code_of(authority, forged) == "malformed"
    bomb = sign(b'{"caps":' + b"[" * 30_000 + b"]" * 30_000 + b"}")
    assert code_of(authority, bomb) == "malformed"


@pytest.mark.parametrize("suffix", ["=", "==", " ", "\n", "\x00", ".", "A"])
def test_decorated_tokens_are_rejected(suffix):
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    for decorated in (token + suffix, suffix + token):
        with pytest.raises(TokenError):
            authority.verify(decorated)


def test_non_canonical_base64_in_the_signature_is_rejected():
    # 64 bytes encode to 86 characters; the last one carries 2 unused bits.
    # A lax decoder accepts four spellings of the same signature.
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
    last = alphabet.index(token[-1])
    assert last % 4 == 0
    for other in (last + 1, last + 2, last + 3):
        with pytest.raises(TokenError):
            authority.verify(token[:-1] + alphabet[other])


def test_unexpected_errors_fail_closed():
    class BrokenStore(MemoryStore):
        def any_revoked(self, jtis):
            raise RuntimeError("database is on fire")

    authority, _ = make(store=BrokenStore())
    token = authority.mint("u", GRANT, "a", ttl=60)
    assert code_of(authority, token) == "unavailable"


@pytest.mark.parametrize("now", [float("nan"), float("inf"), None, "now", True])
def test_a_broken_clock_fails_closed(now):
    authority, clock = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    clock.now = now
    with pytest.raises(TokenError):
        authority.verify(token)
    with pytest.raises(TokenError):
        authority.authorize(token, READ_CALL)


def test_token_unknown_to_the_store_is_rejected():
    # Same key, different store: for example the store was wiped. Without
    # this check every revocation would be forgotten along with it.
    issuing, _ = make()
    other, _ = make()
    token = issuing.mint("u", GRANT, "a", ttl=60)
    assert code_of(other, token) == "unknown_token"


# ---------------------------------------------------------------------------
# exchange
# ---------------------------------------------------------------------------


def test_exchange_builds_the_child_claims():
    ids = iter(["root", "child", "grandchild"])
    authority, clock = make(new_id=lambda: next(ids))
    root = authority.mint("user:alice", GRANT, "orchestrator", ttl=300)
    clock.now = T0 + 10
    narrower = cap("send", to={"eq": "a@x.test"}, amount={"max": 20})
    child = authority.exchange(root, [narrower, READ], "mailer", ttl=100)
    clock.now = T0 + 20
    grandchild = authority.exchange(child, [READ], "reader", ttl=50)

    c = authority.verify(child)
    assert c.sub == "user:alice"
    assert c.actors == ("mailer", "orchestrator")
    assert c.chain == ("root",)
    assert c.der == ((1,), (0,))  # send came from root capability 1, read from 0
    assert (c.iat, c.exp) == (T0 + 10, T0 + 110)
    assert c.grant == Grant((narrower, READ), T0 + 110)

    g = authority.verify(grandchild)
    assert g.sub == "user:alice"
    assert g.actors == ("reader", "mailer", "orchestrator")
    assert g.chain == ("root", "child")
    assert g.der == ((0, 1),)  # root capability 0, then child capability 1
    assert g.budget_path(0) == [("grandchild", 0), ("child", 1), ("root", 0)]
    assert claims_of(grandchild)["act"] == {
        "sub": "reader",
        "act": {"sub": "mailer", "act": {"sub": "orchestrator"}},
    }


def test_sub_is_unchanged_down_the_chain():
    authority, _ = make()
    token = authority.mint("user:alice", GRANT, "a0", ttl=300)
    for n in range(4):
        token = authority.exchange(token, [READ], f"a{n + 1}", ttl=300)
        assert authority.verify(token).sub == "user:alice"
        assert claims_of(token)["sub"] == "user:alice"


def test_the_actor_name_gives_no_authority():
    # act is attribution only: calling yourself the user or the root agent
    # changes what the audit log says, not what the token can do.
    authority, _ = make()
    root = authority.mint("user:alice", GRANT, "orchestrator", ttl=300)
    child = authority.exchange(root, [READ], "user:alice", ttl=100)
    v = authority.verify(child)
    assert v.sub == "user:alice" and v.actors == ("user:alice", "orchestrator")
    assert v.grant.capabilities == (READ,)
    assert not authority.authorize(child, Call("send", {"to": "a@x.test", "amount": 1}))


@pytest.mark.parametrize("ttl", [1, 100, 300, 301, 900, 10**9])
def test_child_never_outlives_its_parent(ttl):
    authority, clock = make()
    root = authority.mint("u", GRANT, "a0", ttl=300)
    clock.now = T0 + 50
    child = authority.exchange(root, [READ], "a1", ttl=ttl)
    grandchild = authority.exchange(child, [READ], "a2", ttl=ttl)
    r, c, g = (authority.verify(t).exp for t in (root, child, grandchild))
    assert g <= c <= r == T0 + 300
    assert c == min(T0 + 300, T0 + 50 + ttl)


def test_child_ttl_is_capped_by_max_ttl_too():
    authority, _ = make(max_ttl=120)
    root = authority.mint("u", Grant((READ,), T0 + 10**6), "a0", ttl=120)
    child = authority.exchange(root, [READ], "a1", ttl=10**9)
    assert authority.verify(child).exp == T0 + 120


def test_an_expired_parent_cannot_be_exchanged():
    authority, clock = make()
    root = authority.mint("u", GRANT, "a0", ttl=60)
    clock.now = T0 + 60
    with pytest.raises(TokenError) as info:
        authority.exchange(root, [READ], "a1", ttl=60)
    assert info.value.code == "expired"


ESCALATIONS = {
    "wider glob": cap("read", path={"glob": "*"}),
    "sibling directory": cap("read", path={"glob": "secrets/*"}),
    "shorter prefix": cap("read", path={"glob": "report*"}),
    "extra tool": cap("delete", path={"glob": "reports/*"}),
    "extra recipient": cap("send", to={"in": ["a@x.test", "evil@x.test"]}, amount={"max": 100}),
    "higher ceiling": cap("send", to={"eq": "a@x.test"}, amount={"max": 101}),
    "dropped constraint": cap("send", to={"eq": "a@x.test"}),
    "any instead of a list": cap("send", to={"any": True}, amount={"max": 100}),
    "extra argument": cap("read", path={"glob": "reports/*"}, mode={"any": True}),
}


@pytest.mark.parametrize("name", sorted(ESCALATIONS))
def test_escalation_on_exchange_is_refused(name):
    authority, _ = make(new_id=iter(["root", "never"]).__next__)
    root = authority.mint("u", GRANT, "a0", ttl=300)
    with pytest.raises(EscalationError) as info:
        authority.exchange(root, [READ, ESCALATIONS[name]], "a1", ttl=60)
    assert "not covered" in info.value.reason
    assert not authority.store.is_registered("never")  # nothing was issued or recorded


def test_escalating_the_budget_is_refused():
    authority, _ = make()
    limited = cap("read", max_calls=3, path={"glob": "reports/*"})
    root = authority.mint("u", Grant((limited,), T0 + 300), "a0", ttl=300)
    for bigger in (4, 1000, None):
        with pytest.raises(EscalationError):
            authority.exchange(
                root, [cap("read", max_calls=bigger, path={"glob": "reports/*"})], "a1", ttl=60
            )
    authority.exchange(root, [limited], "a1", ttl=60)
    authority.exchange(root, [cap("read", max_calls=1, path={"glob": "reports/*"})], "a1", ttl=60)


def test_escalation_is_checked_against_the_parent_not_the_root():
    authority, _ = make()
    root = authority.mint("u", GRANT, "a0", ttl=300)
    child = authority.exchange(root, [cap("read", path={"glob": "reports/q3/*"})], "a1", ttl=60)
    with pytest.raises(EscalationError):
        authority.exchange(child, [READ], "a2", ttl=60)  # the root had it, the child does not
    with pytest.raises(EscalationError):
        authority.exchange(child, [SEND], "a2", ttl=60)


def test_capabilities_may_be_given_as_dicts():
    authority, _ = make()
    root = authority.mint("u", GRANT, "a0", ttl=300)
    child = authority.exchange(root, [READ.to_dict()], "a1", ttl=60)
    assert authority.verify(child).grant.capabilities == (READ,)
    with pytest.raises(EscalationError):
        authority.exchange(root, [{"tool": "read", "args": {"path": {"glob": "*"}}}], "a1", ttl=60)


class Liar(str):
    """A string that claims to equal everything."""

    def __eq__(self, other):
        return True

    def __hash__(self):
        return hash(str(self))


class LooseCapability(Capability):
    pass


def test_objects_that_lie_are_rebuilt_before_the_check():
    authority, _ = make()
    root = authority.mint("u", Grant((cap("read", path={"eq": "a"}),), T0 + 300), "a0", ttl=300)

    # A value smuggled past Constraint's validation: it compares equal to "a",
    # but what would be signed is its real text.
    sneaky = cap("read", path={"eq": "a"})
    object.__setattr__(sneaky.constraints[0], "value", Liar("secrets"))
    with pytest.raises(EscalationError):
        authority.exchange(root, [sneaky], "a1", ttl=60)

    with pytest.raises(ValueError):
        authority.exchange(root, [LooseCapability("read")], "a1", ttl=60)


@pytest.mark.parametrize(
    "caps",
    [
        None,
        "read",
        READ,
        {"tool": "read"},
        [None],
        ["read"],
        [{"tool": "read", "args": {"path": {"regex": ".*"}}}],
        [{"tool": "read", "args": {}, "extra": 1}],
        [{"tool": "read", "args": {"path": {"eq": float("nan")}}}],
        [{"tool": "read", "args": {"path": {"eq": object()}}}],
        [READ] * 300,
    ],
)
def test_exchange_rejects_requests_it_cannot_read(caps):
    authority, _ = make()
    root = authority.mint("u", GRANT, "a0", ttl=300)
    with pytest.raises(ValueError):
        authority.exchange(root, caps, "a1", ttl=60)


@pytest.mark.parametrize("ttl", [0, -5, True, None, "60", float("nan")])
def test_exchange_rejects_bad_ttl(ttl):
    authority, _ = make()
    root = authority.mint("u", GRANT, "a0", ttl=300)
    with pytest.raises(ValueError):
        authority.exchange(root, [READ], "a1", ttl=ttl)


@pytest.mark.parametrize("actor", ["", None, 5, ["a"], "x" * 300])
def test_exchange_rejects_bad_actor(actor):
    authority, _ = make()
    root = authority.mint("u", GRANT, "a0", ttl=300)
    with pytest.raises(ValueError):
        authority.exchange(root, [READ], actor, ttl=60)


def test_a_token_for_another_audience_cannot_be_exchanged_or_used():
    # Two services share the signing key and the store but have different names.
    store = MemoryStore()
    gateway, _ = make(store=store)
    other = Authority(KEY, ISS, "billing", store, clock=Clock())
    foreign = other.mint("u", GRANT, "a0", ttl=300)
    other.verify(foreign)
    with pytest.raises(TokenError) as info:
        gateway.exchange(foreign, [READ], "a1", ttl=60)
    assert info.value.code == "wrong_audience"
    with pytest.raises(TokenError) as info:
        gateway.authorize(foreign, READ_CALL)
    assert info.value.code == "wrong_audience"
    assert code_of(gateway, foreign) == "wrong_audience"


def test_a_child_with_no_capabilities_is_legal_and_useless():
    authority, _ = make()
    root = authority.mint("u", GRANT, "a0", ttl=300)
    child = authority.exchange(root, [], "a1", ttl=60)
    assert authority.verify(child).grant.capabilities == ()
    assert not authority.authorize(child, READ_CALL)


# ---------------------------------------------------------------------------
# authorize and budgets
# ---------------------------------------------------------------------------


def budgeted(n: int | None, pattern: str = "reports/*") -> Capability:
    return cap("read", max_calls=n, path={"glob": pattern})


def used(authority: Authority, token: str, index: int = 0) -> int:
    return authority.store.usage(authority.verify(token).jti, index)[0]


def test_authorize_returns_the_decision_and_the_verified_token():
    authority, _ = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    result = authority.authorize(token, Call("send", {"to": "a@x.test", "amount": 5}))
    assert type(result) is Authorization and result
    decision, verified = result
    assert decision.allowed and decision.capability == 1
    assert verified == authority.verify(token)

    denied = authority.authorize(token, Call("send", {"to": "evil@x.test", "amount": 5}))
    assert not denied and denied.decision.reason == "argument 'to' fails in"
    assert not authority.authorize(token, Call("delete", {}))
    assert not authority.authorize(token, "read reports/q3.txt")  # not a Call


def test_authorize_refuses_at_expiry():
    authority, clock = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    clock.now = T0 + 60
    with pytest.raises(TokenError) as info:
        authority.authorize(token, READ_CALL)
    assert info.value.code == "expired"


def test_a_single_token_exhausts_its_budget():
    authority, _ = make()
    token = authority.mint("u", Grant((budgeted(2),), T0 + 300), "a", ttl=60)
    assert authority.authorize(token, READ_CALL)
    assert authority.authorize(token, READ_CALL)
    third = authority.authorize(token, READ_CALL)
    assert not third and third.decision.reason == "budget exhausted"
    assert used(authority, token) == 2


def test_siblings_given_the_full_parent_budget_share_it():
    authority, _ = make()
    parent = authority.mint("u", Grant((budgeted(3),), T0 + 300), "orchestrator", ttl=300)
    a = authority.exchange(parent, [budgeted(3)], "worker-a", ttl=60)
    b = authority.exchange(parent, [budgeted(3)], "worker-b", ttl=60)
    outcomes = [bool(authority.authorize(t, READ_CALL)) for t in (a, b, a, b, a, b)]
    assert outcomes == [True, True, True, False, False, False]
    assert sum(outcomes) == 3
    assert (used(authority, a), used(authority, b), used(authority, parent)) == (2, 1, 3)
    # The parent spent its own budget through its children.
    exhausted = authority.authorize(parent, READ_CALL)
    assert not exhausted and exhausted.decision.reason == "budget exhausted"


def test_the_parents_own_calls_count_against_its_children():
    authority, _ = make()
    parent = authority.mint("u", Grant((budgeted(2),), T0 + 300), "orchestrator", ttl=300)
    child = authority.exchange(parent, [budgeted(2)], "worker", ttl=60)
    assert authority.authorize(parent, READ_CALL)
    assert authority.authorize(parent, READ_CALL)
    assert not authority.authorize(child, READ_CALL)
    assert used(authority, child) == 0


def test_a_grandchild_call_charges_all_three_levels():
    authority, _ = make()
    root = authority.mint("u", Grant((SEND, budgeted(10)), T0 + 300), "a0", ttl=300)
    child = authority.exchange(root, [budgeted(5)], "a1", ttl=200)
    grandchild = authority.exchange(child, [budgeted(4)], "a2", ttl=100)

    assert authority.authorize(grandchild, READ_CALL)
    assert used(authority, grandchild) == 1
    assert used(authority, child) == 1
    assert used(authority, root, 1) == 1  # the read capability is index 1 in the root
    assert used(authority, root, 0) == 0  # send was not touched

    assert authority.authorize(child, READ_CALL)
    assert (used(authority, grandchild), used(authority, child), used(authority, root, 1)) == (
        1,
        2,
        2,
    )


def test_an_unlimited_child_of_a_limited_parent_is_an_escalation():
    authority, _ = make()
    root = authority.mint("u", Grant((budgeted(5),), T0 + 300), "a0", ttl=300)
    with pytest.raises(EscalationError):
        authority.exchange(root, [budgeted(None)], "a1", ttl=100)


def test_a_limited_child_of_an_unlimited_parent_is_limited():
    authority, _ = make()
    root = authority.mint("u", Grant((budgeted(None),), T0 + 300), "a0", ttl=300)
    child = authority.exchange(root, [budgeted(1)], "a1", ttl=100)
    assert authority.authorize(child, READ_CALL)
    assert not authority.authorize(child, READ_CALL)
    assert authority.authorize(root, READ_CALL)
    assert authority.store.usage(authority.verify(root).jti, 0) == (2, None)


def test_refund_gives_back_exactly_what_authorize_charged():
    authority, _ = make()
    root = authority.mint("u", Grant((SEND, budgeted(10)), T0 + 300), "a0", ttl=300)
    child = authority.exchange(root, [budgeted(5)], "a1", ttl=200)
    grandchild = authority.exchange(child, [budgeted(4)], "a2", ttl=100)
    kept = authority.authorize(child, READ_CALL)
    charged = authority.authorize(grandchild, READ_CALL)
    assert charged and kept
    assert (used(authority, grandchild), used(authority, child), used(authority, root, 1)) == (
        1,
        2,
        2,
    )
    assert authority.refund(charged) is True
    # Every level of the grandchild's path gets one call back; the child's own call stays.
    assert (used(authority, grandchild), used(authority, child), used(authority, root, 1)) == (
        0,
        1,
        1,
    )
    assert used(authority, root, 0) == 0


def test_refund_of_a_denied_authorization_changes_nothing():
    authority, _ = make()
    token = authority.mint("u", Grant((budgeted(1),), T0 + 300), "a0", ttl=300)
    assert authority.authorize(token, READ_CALL)
    exhausted = authority.authorize(token, READ_CALL)
    not_granted = authority.authorize(token, Call("delete", {}))
    assert not exhausted and not not_granted
    assert authority.refund(exhausted) is False and authority.refund(not_granted) is False
    assert used(authority, token) == 1
    for bad in (None, True, (exhausted.decision, exhausted.verified)):
        with pytest.raises(ValueError):
            authority.refund(bad)


def test_refund_reports_a_store_failure_as_unavailable():
    class NoRefunds(MemoryStore):
        def refund(self, path):
            raise OSError("disk gone")

    authority, _ = make(store=NoRefunds())
    token = authority.mint("u", Grant((budgeted(2),), T0 + 300), "a0", ttl=300)
    charged = authority.authorize(token, READ_CALL)
    with pytest.raises(TokenError) as info:
        authority.refund(charged)
    assert info.value.code == "unavailable"
    assert used(authority, token) == 1  # fails closed: the budget stays spent


def test_a_denied_call_charges_nothing():
    authority, _ = make()
    parent = authority.mint("u", Grant((budgeted(3),), T0 + 300), "a0", ttl=300)
    child = authority.exchange(parent, [budgeted(3, "reports/q3/*")], "a1", ttl=60)
    for call in (
        Call("read", {"path": "secrets/key"}),
        Call("read", {"path": "reports/q2/x"}),  # the parent would allow it, the child not
        Call("read", {}),
        Call("read", {"path": "reports/q3/x", "mode": "rw"}),
        Call("delete", {"path": "reports/q3/x"}),
    ):
        assert not authority.authorize(child, call)
    assert (used(authority, child), used(authority, parent)) == (0, 0)


def test_a_failed_charge_leaves_every_counter_unchanged():
    authority, _ = make()
    root = authority.mint("u", Grant((budgeted(10),), T0 + 300), "a0", ttl=300)
    middle = authority.exchange(root, [budgeted(1)], "a1", ttl=200)
    leaf_a = authority.exchange(middle, [budgeted(1)], "a2", ttl=100)
    leaf_b = authority.exchange(middle, [budgeted(1)], "a3", ttl=100)
    assert authority.authorize(leaf_a, READ_CALL)  # uses up the middle token's one call

    refused = authority.authorize(leaf_b, READ_CALL)
    assert not refused and refused.decision.reason == "budget exhausted"
    # leaf_b had budget and so did the root: neither moved, because the middle refused.
    assert used(authority, leaf_b) == 0
    assert used(authority, middle) == 1
    assert used(authority, root) == 1


def test_budget_follows_the_recorded_derivation_not_a_fresh_decision():
    # Parent capability 0 permits the call but could not cover the child (its
    # budget is too small), so the child was derived from capability 1.
    # Re-running parent.decide would pick 0 and charge the wrong budget.
    authority, _ = make()
    parent_grant = Grant((budgeted(1), budgeted(5)), T0 + 300)
    parent = authority.mint("u", parent_grant, "a0", ttl=300)
    child = authority.exchange(parent, [budgeted(3)], "a1", ttl=60)
    assert authority.verify(child).der == ((1,),)
    assert parent_grant.decide(READ_CALL, T0).capability == 0

    for _ in range(3):
        assert authority.authorize(child, READ_CALL)
    assert not authority.authorize(child, READ_CALL)
    assert used(authority, parent, 0) == 0
    assert used(authority, parent, 1) == 3


def test_two_children_derived_from_one_parent_capability_share_it_inside_one_token():
    authority, _ = make()
    parent = authority.mint("u", Grant((budgeted(3),), T0 + 300), "a0", ttl=300)
    child = authority.exchange(
        parent, [budgeted(3, "reports/a/*"), budgeted(3, "reports/b/*")], "a1", ttl=60
    )
    assert authority.verify(child).der == ((0,), (0,))
    calls = [Call("read", {"path": f"reports/{d}/x"}) for d in "abab"]
    assert [bool(authority.authorize(child, c)) for c in calls] == [True, True, True, False]


def test_a_second_capability_pays_when_the_first_is_exhausted():
    # Two capabilities that both permit the call are two budgets. Stopping at
    # the first would make the order of capabilities change how much a grant allows.
    authority, _ = make()
    token = authority.mint("u", Grant((budgeted(1), budgeted(2)), T0 + 300), "a", ttl=60)
    indices = [authority.authorize(token, READ_CALL).decision.capability for _ in range(4)]
    assert indices == [0, 1, 1, None]
    assert (used(authority, token, 0), used(authority, token, 1)) == (1, 2)


def test_budgets_are_per_token_not_per_grant():
    authority, _ = make()
    grant = Grant((budgeted(1),), T0 + 300)
    first = authority.mint("u", grant, "a", ttl=60)
    second = authority.mint("u", grant, "a", ttl=60)
    assert authority.authorize(first, READ_CALL)
    assert not authority.authorize(first, READ_CALL)
    assert authority.authorize(second, READ_CALL)


def test_revocation_between_verify_and_charge_is_caught_by_the_charge():
    class RevokedLate(MemoryStore):
        """Reports nothing revoked at verify time, as if the revoke landed just after."""

        def any_revoked(self, jtis):
            return False

    authority, _ = make(store=RevokedLate())
    token = authority.mint("u", Grant((budgeted(3),), T0 + 300), "a", ttl=60)
    authority.revoke(authority.verify(token).jti)
    with pytest.raises(TokenError) as info:
        authority.authorize(token, READ_CALL)
    assert info.value.code == "revoked"
    assert used(authority, token) == 0


def test_forged_der_index_cannot_reach_an_unlimited_or_missing_budget():
    # Even with a correct signature (a signer bug, say), a der index that
    # points at no real capability of the ancestor is a refusal, not "no limit".
    authority, _ = make()
    parent = authority.mint("u", Grant((budgeted(1),), T0 + 300), "a0", ttl=300)
    child = authority.exchange(parent, [budgeted(1)], "a1", ttl=60)
    forged = resign(child, jti="forged", der=[[7]])
    authority.store.register("forged", [1])
    result = authority.authorize(forged, READ_CALL)
    assert not result and "no record" in result.decision.reason
    assert authority.store.usage("forged", 0) == (0, 1)
    assert used(authority, parent) == 0


def test_tokens_work_the_same_on_a_sqlite_store(tmp_path):
    store = SqliteStore(str(tmp_path / "gateway.db"))
    authority, _ = make(store=store)
    parent = authority.mint("u", Grant((budgeted(3),), T0 + 300), "a0", ttl=300)
    a = authority.exchange(parent, [budgeted(3)], "a1", ttl=60)
    b = authority.exchange(parent, [budgeted(3)], "a2", ttl=60)
    assert [bool(authority.authorize(t, READ_CALL)) for t in (a, b, a, b)] == [
        True,
        True,
        True,
        False,
    ]
    store.close()

    # A restarted gateway with the same key and database keeps budgets and revocations.
    reopened = SqliteStore(str(tmp_path / "gateway.db"))
    restarted, _ = make(store=reopened)
    assert not restarted.authorize(a, READ_CALL)
    restarted.revoke(restarted.verify(parent).jti)
    assert code_of(restarted, b) == "revoked"
    reopened.close()


# ---------------------------------------------------------------------------
# properties
# ---------------------------------------------------------------------------

_CHARS = string.ascii_letters + string.digits + "-_.= "


def serializable(grant: Grant) -> bool:
    try:
        grant.to_dict()
    except ValueError:  # two constraints with the same operator on one argument
        return False
    return True


@settings(max_examples=300, deadline=None)
@given(grant=grants(), data=st.data())
def test_property_mint_verify_roundtrip_and_any_one_character_change_is_rejected(grant, data):
    authority, _ = make(clock=Clock(0))  # strategy expiries are 1 to 100
    if not serializable(grant):
        with pytest.raises(ValueError):
            authority.mint("user", grant, "agent", ttl=900)
        return
    token = authority.mint("user", grant, "agent", ttl=900)
    verified = authority.verify(token)
    assert verified.grant == Grant.from_dict(grant.to_dict())
    assert verified.grant.to_dict() == grant.to_dict()
    assert verified.grant.expires_at == grant.expires_at
    assert (verified.sub, verified.actors, verified.chain) == ("user", ("agent",), ())

    for _ in range(4):
        position = data.draw(st.integers(0, len(token) - 1))
        replacement = data.draw(st.sampled_from(_CHARS))
        if replacement == token[position]:
            continue
        changed = token[:position] + replacement + token[position + 1 :]
        with pytest.raises(TokenError):
            authority.verify(changed)


@settings(max_examples=300, deadline=None)
@given(scenario=scenarios())
def test_property_exchange_agrees_with_the_checker_and_never_widens(scenario):
    parent_grant, child_grant, call, _, _ = scenario
    if not serializable(parent_grant) or not serializable(child_grant):
        return
    authority, _ = make(clock=Clock(0))
    parent = authority.mint("user", parent_grant, "a0", ttl=900)
    parent_seen = authority.verify(parent).grant
    ttl = child_grant.expires_at if child_grant.expires_at > 0 else 1
    expected_child = Grant(
        Grant.from_dict(child_grant.to_dict()).capabilities, min(parent_seen.expires_at, ttl)
    )
    expected = check_attenuation(parent_seen, expected_child)
    try:
        child = authority.exchange(parent, child_grant.capabilities, "a1", ttl=ttl)
    except EscalationError:
        assert not expected.ok
        return
    assert expected.ok
    seen = authority.verify(child)
    assert seen.grant == expected_child
    assert seen.exp <= authority.verify(parent).exp
    assert seen.der == tuple((d,) for d in expected.derivation)
    # The invariant of the whole system, now through signed tokens.
    if authority.authorize(child, call):
        assert parent_seen.allows(call, 0)


@settings(max_examples=100, deadline=None)
@given(
    limit=st.integers(1, 4),
    child_limits=st.lists(st.integers(1, 4), min_size=1, max_size=3),
    order=st.lists(st.integers(0, 3), max_size=20),
)
def test_property_a_family_never_spends_more_than_the_root_allows(limit, child_limits, order):
    authority, _ = make()
    root = authority.mint("u", Grant((budgeted(limit),), T0 + 300), "a0", ttl=300)
    tokens = [root]
    for n, child_limit in enumerate(child_limits):
        if child_limit <= limit:
            tokens.append(authority.exchange(root, [budgeted(child_limit)], f"a{n}", ttl=60))
    allowed = sum(bool(authority.authorize(tokens[i % len(tokens)], READ_CALL)) for i in order)
    assert allowed <= limit
    assert used(authority, root) == allowed
    for token in tokens[1:]:
        own_used, own_limit = authority.store.usage(authority.verify(token).jti, 0)
        assert own_used <= own_limit


def test_constraint_values_survive_the_wire_with_their_types():
    authority, _ = make()
    tricky = Capability(
        "t",
        (
            Constraint("a", "in", (1, 1.5, True, "1", "")),
            Constraint("b", "eq", False),
            Constraint("c", "max", -2.5),
            Constraint("d", "glob", 'we"ird/é中*\\'),
            Constraint("e", "any"),
            Constraint("f", "eq", 2**80),
        ),
        7,
    )
    token = authority.mint("u", Grant((tricky,), T0 + 60), "a", ttl=60)
    back = authority.verify(token).grant.capabilities[0]
    assert back == tricky
    values = back.constraints[0].value
    assert [type(v) for v in values] == [int, float, bool, str, str]


# ---------------------------------------------------------------------------
# robustness: fan-out, pruning, expiry during a charge, outages, names, sizes
# ---------------------------------------------------------------------------


def exchange_code(authority: Authority, *args: Any, **kwargs: Any) -> str:
    with pytest.raises(TokenError) as info:
        authority.exchange(*args, **kwargs)
    return info.value.code


def test_exchange_fan_out_is_limited_per_parent():
    authority, _ = make(max_children=3)
    root = authority.mint("u", GRANT, "a0", ttl=300)
    children = [authority.exchange(root, [READ], f"a{n}", ttl=60) for n in range(3)]
    assert exchange_code(authority, root, [READ], "a3", ttl=60) == "too_many_children"
    assert exchange_code(authority, root, [], "a3", ttl=60) == "too_many_children"
    # The limit is per parent token: a child has its own count, and so does a new root.
    assert authority.exchange(children[0], [READ], "b0", ttl=30)
    other_root = authority.mint("u", GRANT, "a0", ttl=300)
    assert authority.exchange(other_root, [READ], "a1", ttl=60)
    for token in children:
        assert authority.verify(token)  # the refusals broke nothing


def test_default_fan_out_limit_is_64():
    authority, _ = make()
    assert authority.max_children == 64
    root = authority.mint("u", GRANT, "a0", ttl=300)
    for n in range(64):
        authority.exchange(root, [READ], f"a{n}", ttl=60)
    assert exchange_code(authority, root, [READ], "late", ttl=60) == "too_many_children"


def test_a_refused_exchange_does_not_use_up_a_child_slot():
    authority, _ = make(max_children=1)
    root = authority.mint("u", GRANT, "a0", ttl=300)
    with pytest.raises(EscalationError):
        authority.exchange(root, [cap("delete")], "a1", ttl=60)
    with pytest.raises(ValueError):
        authority.exchange(root, [READ], "", ttl=60)
    with pytest.raises(ValueError):
        authority.exchange(root, [READ], "a1", ttl=0)
    assert authority.exchange(root, [READ], "a1", ttl=60)


def test_max_children_zero_forbids_all_delegation_and_bad_values_are_refused():
    authority, _ = make(max_children=0)
    root = authority.mint("u", GRANT, "a0", ttl=300)
    assert exchange_code(authority, root, [READ], "a1", ttl=60) == "too_many_children"
    for bad in (-1, True, 2.0, "3", None):
        with pytest.raises(ValueError):
            make(max_children=bad)


def test_fan_out_limit_holds_on_sqlite_across_a_restart(tmp_path):
    store = SqliteStore(str(tmp_path / "gateway.db"))
    authority, _ = make(store=store, max_children=2)
    root = authority.mint("u", GRANT, "a0", ttl=300)
    authority.exchange(root, [READ], "a1", ttl=60)
    store.close()
    reopened = SqliteStore(str(tmp_path / "gateway.db"))
    restarted, _ = make(store=reopened, max_children=2)
    restarted.exchange(root, [READ], "a2", ttl=60)
    assert exchange_code(restarted, root, [READ], "a3", ttl=60) == "too_many_children"
    reopened.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_prune_forgets_expired_tokens_and_nothing_else(kind, tmp_path):
    store = MemoryStore() if kind == "memory" else SqliteStore(str(tmp_path / "gateway.db"))
    authority, clock = make(store=store)
    root = authority.mint("u", Grant((budgeted(5),), T0 + 300), "a0", ttl=300)
    short = authority.exchange(root, [budgeted(2)], "a1", ttl=30)
    longer = authority.exchange(root, [budgeted(2)], "a2", ttl=200)
    root_jti, short_jti = authority.verify(root).jti, authority.verify(short).jti
    assert authority.authorize(short, READ_CALL)
    authority.revoke(short_jti)

    assert authority.prune() == 0  # nothing has expired yet
    clock.now = T0 + 30
    assert authority.prune() == 1  # exactly the short-lived child
    assert not store.is_registered(short_jti)
    assert store.usage(short_jti, 0) is None
    assert not store.any_revoked([short_jti])  # its revocation entry went with it
    assert code_of(authority, short) == "expired"
    # Everything still alive is untouched, including what the dead child spent.
    assert store.usage(root_jti, 0) == (1, 5)
    assert authority.authorize(longer, READ_CALL)
    assert authority.authorize(root, READ_CALL)

    clock.now = T0 + 300
    assert authority.prune() == 2
    assert not store.is_registered(root_jti)
    # A clock set backwards after pruning no longer revives anything.
    clock.now = T0 + 1
    assert code_of(authority, short) == "unknown_token"
    assert code_of(authority, root) == "unknown_token"
    if kind == "sqlite":
        store.close()


def test_prune_is_never_run_on_the_hot_path():
    class Counting(MemoryStore):
        pruned = 0

        def prune(self, now):
            self.pruned += 1
            return super().prune(now)

    store = Counting()
    authority, clock = make(store=store)
    root = authority.mint("u", GRANT, "a0", ttl=300)
    child = authority.exchange(root, [READ], "a1", ttl=60)
    authority.verify(child)
    authority.authorize(child, READ_CALL)
    authority.revoke(authority.verify(child).jti)
    assert store.pruned == 0
    authority.prune()
    assert store.pruned == 1


def test_a_charge_that_finishes_after_expiry_is_denied():
    clock = Clock()

    class SlowStore(MemoryStore):
        """The charge waits for a lock, and the token expires while it waits."""

        def charge(self, path):
            result = super().charge(path)
            clock.now = T0 + 60
            return result

    authority, _ = make(store=SlowStore(), clock=clock)
    token = authority.mint("u", Grant((budgeted(3),), T0 + 300), "a", ttl=60)
    result = authority.authorize(token, READ_CALL)
    assert not result
    assert result.decision.reason == "expired during authorization"
    assert result.verified.jti == claims_of(token)["jti"]
    # The call was charged and will not run, so the charge was given back.
    assert authority.store.usage(result.verified.jti, 0) == (0, 3)


def test_a_clock_fault_right_after_the_charge_refunds_it():
    clock = Clock()

    class BrokenAfterCharge(MemoryStore):
        def charge(self, path):
            result = super().charge(path)
            clock.now = float("nan")  # the second clock reading is invalid
            return result

    authority, _ = make(store=BrokenAfterCharge(), clock=clock)
    token = authority.mint("u", Grant((budgeted(3),), T0 + 300), "a", ttl=60)
    jti = claims_of(token)["jti"]
    with pytest.raises(TokenError) as info:
        authority.authorize(token, READ_CALL)
    assert info.value.code == "unavailable"
    assert authority.store.usage(jti, 0) == (0, 3)


def test_a_late_refund_that_fails_inside_authorize_leaves_the_budget_spent():
    clock = Clock()

    class NoRefund(MemoryStore):
        def charge(self, path):
            result = super().charge(path)
            clock.now = T0 + 60
            return result

        def refund(self, path):
            raise OSError("disk gone")

    authority, _ = make(store=NoRefund(), clock=clock)
    token = authority.mint("u", Grant((budgeted(3),), T0 + 300), "a", ttl=60)
    result = authority.authorize(token, READ_CALL)
    assert not result and result.decision.reason == "expired during authorization"
    assert authority.store.usage(claims_of(token)["jti"], 0) == (1, 3)  # fails closed


def test_a_slow_charge_that_finishes_just_before_expiry_is_allowed():
    clock = Clock()

    class SlowStore(MemoryStore):
        def charge(self, path):
            result = super().charge(path)
            clock.now = T0 + 59.5
            return result

    authority, _ = make(store=SlowStore(), clock=clock)
    token = authority.mint("u", Grant((budgeted(3),), T0 + 300), "a", ttl=60)
    assert authority.authorize(token, READ_CALL)


class Outage(RuntimeError):
    pass


def broken_store(method: str) -> MemoryStore:
    """A MemoryStore whose one named method starts failing when `down` is set."""

    class Broken(MemoryStore):
        down = False

    original = getattr(MemoryStore, method)

    def failing(self, *args, **kwargs):
        if self.down:
            raise Outage("database is on fire")
        return original(self, *args, **kwargs)

    setattr(Broken, method, failing)
    return Broken()


@pytest.mark.parametrize("method", ["any_revoked", "is_registered", "charge"])
def test_a_store_outage_is_unavailable_never_a_raw_error(method):
    store = broken_store(method)
    authority, _ = make(store=store)
    token = authority.mint("u", Grant((budgeted(3),), T0 + 300), "a", ttl=60)
    store.down = True
    with pytest.raises(TokenError) as info:
        authority.authorize(token, READ_CALL)
    assert info.value.code == "unavailable"
    if method != "charge":
        assert code_of(authority, token) == "unavailable"
        assert exchange_code(authority, token, [budgeted(1)], "a1", ttl=30) == "unavailable"
    store.down = False
    assert authority.authorize(token, READ_CALL)  # the outage was transient


@pytest.mark.parametrize("method", ["add_child", "register"])
def test_a_store_outage_during_exchange_is_unavailable(method):
    store = broken_store(method)
    authority, _ = make(store=store)
    root = authority.mint("u", GRANT, "a0", ttl=300)
    store.down = True
    assert exchange_code(authority, root, [READ], "a1", ttl=60) == "unavailable"


def test_a_store_outage_during_revoke_is_unavailable():
    store = broken_store("revoke")
    authority, _ = make(store=store)
    store.down = True
    with pytest.raises(TokenError) as info:
        authority.revoke("some-token-id")
    assert info.value.code == "unavailable"


def test_a_closed_sqlite_store_is_unavailable_not_malformed(tmp_path):
    store = SqliteStore(str(tmp_path / "gateway.db"))
    authority, _ = make(store=store)
    token = authority.mint("u", GRANT, "a", ttl=60)
    store.close()
    assert code_of(authority, token) == "unavailable"
    with pytest.raises(TokenError) as info:
        authority.authorize(token, READ_CALL)
    assert info.value.code == "unavailable"
    assert exchange_code(authority, token, [READ], "a1", ttl=30) == "unavailable"
    with pytest.raises(TokenError) as info:
        authority.revoke("x")
    assert info.value.code == "unavailable"


def test_a_clock_that_raises_is_unavailable_everywhere():
    class FailingClock(Clock):
        fail_after: int | None = None

        def __call__(self) -> float:
            if self.fail_after is not None:
                if self.fail_after == 0:
                    raise OSError("no time source")
                self.fail_after -= 1
            return self.now

    clock = FailingClock()
    authority, _ = make(clock=clock)
    token = authority.mint("u", Grant((budgeted(3),), T0 + 300), "a", ttl=60)
    clock.fail_after = 0
    assert code_of(authority, token) == "unavailable"
    assert exchange_code(authority, token, [budgeted(1)], "a1", ttl=30) == "unavailable"
    with pytest.raises(TokenError) as info:
        authority.authorize(token, READ_CALL)
    assert info.value.code == "unavailable"
    # The clock works for the first read and fails for the one after the charge.
    clock.fail_after = 1
    with pytest.raises(TokenError) as info:
        authority.authorize(token, READ_CALL)
    assert info.value.code == "unavailable"


@pytest.mark.parametrize("now", [float("nan"), None, "now"])
def test_a_clock_returning_nonsense_is_unavailable_not_malformed(now):
    authority, clock = make()
    token = authority.mint("u", GRANT, "a", ttl=60)
    clock.now = now
    assert code_of(authority, token) == "unavailable"


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
@pytest.mark.parametrize("jti", ["evil\ud800", "\udfff", "a\udc80b"])
def test_revoking_text_that_cannot_be_encoded_is_malformed(kind, jti):
    store = MemoryStore() if kind == "memory" else SqliteStore(":memory:")
    authority, _ = make(store=store)
    with pytest.raises(TokenError) as info:
        authority.revoke(jti)
    assert info.value.code == "malformed"
    assert not isinstance(info.value, UnicodeError)


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_a_token_id_that_cannot_be_encoded_is_malformed_not_unavailable(kind):
    store = MemoryStore() if kind == "memory" else SqliteStore(":memory:")
    authority, _ = make(store=store)
    root = authority.mint("u", GRANT, "a0", ttl=300)
    child = authority.exchange(root, [READ], "a1", ttl=60)
    assert code_of(authority, resign(root, jti="evil\ud800")) == "malformed"
    assert code_of(authority, resign(child, chain=["evil\ud800"])) == "malformed"


BAD_PRINCIPALS = [
    "evil\ud800",
    "a\x00b",
    "line\nbreak",
    "tab\there",
    "\x1b[2Jcleared",
    "rtl‮override",
    "",
    "x" * 129,
    Liar("agent"),
    b"agent",
    None,
]


@pytest.mark.parametrize("name", BAD_PRINCIPALS)
def test_names_the_audit_log_cannot_record_are_refused_when_issuing(name):
    authority, _ = make()
    with pytest.raises(ValueError):
        authority.mint(name, GRANT, "a", ttl=60)
    with pytest.raises(ValueError):
        authority.mint("u", GRANT, name, ttl=60)
    root = authority.mint("u", GRANT, "a0", ttl=300)
    with pytest.raises(ValueError):
        authority.exchange(root, [READ], name, ttl=60)
    assert authority.exchange(root, [READ], "a1", ttl=60)  # nothing was counted or left behind


@pytest.mark.parametrize("name", [n for n in BAD_PRINCIPALS if type(n) is str])
def test_names_the_audit_log_cannot_record_are_refused_when_verifying(name):
    authority, _ = make()
    root = authority.mint("u", GRANT, "a0", ttl=300)
    child = authority.exchange(root, [READ], "a1", ttl=60)
    assert code_of(authority, resign(root, sub=name)) == "malformed"
    assert code_of(authority, resign(root, act={"sub": name})) == "malformed"
    nested = {"sub": "a1", "act": {"sub": name}}
    assert code_of(authority, resign(child, act=nested)) == "malformed"


@pytest.mark.parametrize("name", ["x" * 128, "agent-1", "Zoë", "助手 7", "a b", "u@example.test"])
def test_ordinary_names_are_accepted(name):
    authority, _ = make()
    root = authority.mint(name, GRANT, name, ttl=300)
    child = authority.exchange(root, [READ], name, ttl=60)
    verified = authority.verify(child)
    assert verified.sub == name and verified.actors == (name, name)


def _too_many_capabilities() -> list[Any]:
    return [READ] * 257


def _too_many_constraints() -> list[Any]:
    return [{"tool": "read", "args": {f"arg{n}": {"any": True} for n in range(65)}}]


def _too_many_bytes() -> list[Any]:
    return [{"tool": "read", "args": {"path": {"in": [f"reports/{n}" for n in range(8000)]}}}]


def _too_many_bytes_in_total() -> list[Any]:
    one = {"tool": "read", "args": {"path": {"in": ["reports/" + "x" * 400]}}}
    return [one] * 200


@pytest.mark.parametrize(
    "request_",
    [_too_many_capabilities, _too_many_constraints, _too_many_bytes, _too_many_bytes_in_total],
)
def test_an_oversized_child_request_is_refused_before_the_attenuation_check(request_, monkeypatch):
    calls = []

    def spy(parent, child):
        calls.append(child)
        return check_attenuation(parent, child)

    monkeypatch.setattr("toolgate.tokens.check_attenuation", spy)
    authority, _ = make()
    root = authority.mint("u", GRANT, "a0", ttl=300)
    with pytest.raises(TokenError) as info:
        authority.exchange(root, request_(), "a1", ttl=60)
    assert info.value.code == "malformed"
    assert isinstance(info.value, ValueError)  # what an unreadable request has always raised
    assert calls == []
    # A request of ordinary size still reaches the check.
    authority.exchange(root, [READ], "a1", ttl=60)
    assert len(calls) == 1


def test_a_request_at_the_size_limits_is_still_checked():
    authority, _ = make()
    wide = {"tool": "wide", "args": {f"arg{n}": {"any": True} for n in range(64)}}
    root = authority.mint("u", Grant((Capability.from_dict(wide),), T0 + 300), "a0", ttl=300)
    child = authority.exchange(root, [wide], "a1", ttl=60)
    assert len(authority.verify(child).grant.capabilities[0].constraints) == 64
