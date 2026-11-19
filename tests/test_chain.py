"""Tests for offline attenuation with chained signatures (milestone M1b).

Most tests run twice, once per construction, through the `kit` fixture:

    hmac     HMAC-SHA256 chain, verified with the root key
    ed25519  Ed25519 chain, verified with the root public key only

The attack tests build the forged token the way an attacker would: start from
tokens they legitimately hold and rearrange the parts. They never use the
authority's key, because the attacker does not have it.

Set CAVEAT_EXAMPLES to change the number of Hypothesis cases (default 1000).
"""

from __future__ import annotations

import base64
import functools
import hashlib
import inspect
import json
import os
import random
from dataclasses import dataclass, replace
from itertools import combinations
from typing import Any, get_args

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from hypothesis import HealthCheck, find, given, settings
from hypothesis import strategies as st

from caveat import Call, Capability, Constraint, Decision, Grant
from caveat import chain as chain_module
from caveat.chain import (
    MAX_CAVEATS,
    MAX_TOKEN_CHARS,
    ArgCaveat,
    ChainError,
    ExpiryCaveat,
    HmacAuthority,
    HmacToken,
    KeyAuthority,
    KeyToken,
    ToolsCaveat,
    Verified,
    attenuate,
    authorize_public,
    decode_caveat,
    encode_caveat,
    seal,
    verify_public,
)
from strategies import EXPIRIES, TOOLS, calls_for, constraints, grants, times

EXAMPLES = int(os.environ.get("CAVEAT_EXAMPLES", "1000"))
NOW = 1000
ROOT_KEY = bytes(range(32))
OTHER_ROOT_KEY = bytes(range(1, 33))

GRANT = Grant(
    (
        Capability.from_dict({"tool": "read_file", "args": {"path": {"glob": "reports/*"}}}),
        Capability.from_dict(
            {
                "tool": "send_email",
                "args": {"to": {"in": ["ana@x.com", "ben@x.com"]}, "body": {"any": True}},
            }
        ),
    ),
    NOW + 3600,
)
READ_Q3 = Call("read_file", {"path": "reports/q3/a.txt"})
READ_Q1 = Call("read_file", {"path": "reports/q1/b.txt"})
SEND_ANA = Call("send_email", {"to": "ana@x.com", "body": "hi"})
SEND_BEN = Call("send_email", {"to": "ben@x.com", "body": "hi"})

ONLY_READ = ToolsCaveat(("read_file",))
ONLY_Q3 = ArgCaveat("read_file", Constraint("path", "glob", "reports/q3/*"))
ONLY_ANA = ArgCaveat("send_email", Constraint("to", "eq", "ana@x.com"))
SOON = ExpiryCaveat(NOW + 60)


# ---------------------------------------------------------------------------
# One interface over both constructions
# ---------------------------------------------------------------------------


@dataclass
class Kit:
    name: str
    authority: Any
    token_type: type

    def issue(self, identifier: str = "tok-1", grant: Grant = GRANT) -> Any:
        return self.authority.issue(identifier, grant)

    def verify(self, token: Any) -> Verified:
        return self.authority.verify(token)

    def authorize(self, token: Any, call: Call, now: float = NOW) -> Decision:
        return self.authority.authorize(token, call, now)

    def parse(self, text: str) -> Any:
        return self.token_type.parse(text)


def make_kit(name: str, root: bytes = ROOT_KEY) -> Kit:
    if name == "hmac":
        return Kit(name, HmacAuthority(root), HmacToken)
    return Kit(name, KeyAuthority(root), KeyToken)


@pytest.fixture(params=["hmac", "ed25519"])
def kit(request: pytest.FixtureRequest) -> Kit:
    return make_kit(request.param)


def chain(token: Any, *caveats: Any) -> Any:
    for caveat in caveats:
        token = attenuate(token, caveat)
    return token


def drop_block(token: Any, index: int) -> Any:
    """Remove caveat `index` (1-based) and everything that belongs to its block.

    The signature (HMAC) or the proof (Ed25519) stays as it was, because that
    is all the attacker has.
    """
    caveats = token.caveats[: index - 1] + token.caveats[index:]
    if type(token) is HmacToken:
        return replace(token, caveats=caveats)
    return replace(
        token,
        caveats=caveats,
        next_keys=token.next_keys[:index] + token.next_keys[index + 1 :],
        signatures=token.signatures[:index] + token.signatures[index + 1 :],
    )


def swap_blocks(token: Any, i: int, j: int) -> Any:
    """Exchange caveats i and j (1-based) together with their keys and signatures."""

    def swapped(items: tuple, offset: int) -> tuple:
        out = list(items)
        out[i - offset], out[j - offset] = out[j - offset], out[i - offset]
        return tuple(out)

    if type(token) is HmacToken:
        return replace(token, caveats=swapped(token.caveats, 1))
    return replace(
        token,
        caveats=swapped(token.caveats, 1),
        next_keys=swapped(token.next_keys, 0),
        signatures=swapped(token.signatures, 0),
    )


def assert_rejected(kit: Kit, token: Any) -> str:
    """The forged token must fail verify, and authorize must deny without raising."""
    with pytest.raises(ChainError) as info:
        kit.verify(token)
    decision = kit.authorize(token, READ_Q3)
    assert not decision.allowed
    assert decision.reason.startswith("invalid token")
    return str(info.value)


# ---------------------------------------------------------------------------
# The happy path: narrowing offline
# ---------------------------------------------------------------------------


def test_attenuate_takes_no_key_and_no_authority() -> None:
    """The whole point: the holder's operation needs the token and nothing else."""
    assert list(inspect.signature(attenuate).parameters) == ["token", "caveat"]


def test_holder_narrows_offline_and_the_result_verifies(kit: Kit) -> None:
    text = kit.issue().serialize()
    # From here on the "holder" has only the string. No authority object is touched
    # until the narrowed string comes back to be verified.
    narrowed = attenuate(kit.parse(text), ONLY_Q3).serialize()
    verified = kit.verify(narrowed)
    assert verified.identifier == "tok-1"
    assert verified.grant == GRANT
    assert verified.caveats == (ONLY_Q3,)


def test_narrowed_denies_what_the_caveat_forbids_and_original_still_allows(kit: Kit) -> None:
    original = kit.issue()
    narrowed = attenuate(original, ONLY_Q3)
    assert kit.authorize(narrowed, READ_Q3).allowed
    denied = kit.authorize(narrowed, READ_Q1)
    assert not denied.allowed
    assert denied.reason == "caveat 1: argument 'path' fails glob"
    assert kit.authorize(original, READ_Q1).allowed  # attenuate returned a new token


def test_attenuate_does_not_change_the_token_it_was_given(kit: Kit) -> None:
    original = kit.issue()
    before = original.serialize()
    attenuate(original, ONLY_READ)
    assert original.serialize() == before
    assert original.caveats == ()


def test_each_caveat_removes_authority_step_by_step(kit: Kit) -> None:
    calls = (READ_Q3, READ_Q1, SEND_ANA, SEND_BEN)
    token = kit.issue()
    expected = [
        (None, (True, True, True, True)),
        (ONLY_ANA, (True, True, True, False)),
        (ONLY_READ, (True, True, False, False)),
        (ONLY_Q3, (True, False, False, False)),
    ]
    for caveat, allowed in expected:
        if caveat is not None:
            token = attenuate(token, caveat)
        assert tuple(kit.authorize(token, c).allowed for c in calls) == allowed


def test_serialization_round_trips(kit: Kit) -> None:
    token = chain(kit.issue(), ONLY_ANA, ONLY_READ, ONLY_Q3, SOON)
    text = token.serialize()
    assert kit.parse(text) == token
    assert kit.parse(text).serialize() == text
    assert set(text) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.")


def test_tokens_grow_with_each_caveat(kit: Kit) -> None:
    token = kit.issue()
    sizes = [len(token.serialize())]
    for _ in range(3):
        token = attenuate(token, ONLY_Q3)
        sizes.append(len(token.serialize()))
    assert sizes == sorted(set(sizes))  # strictly growing: a stated limit of the design


def test_repr_does_not_show_the_secret_part(kit: Kit) -> None:
    token = kit.issue()
    secret = token.signature if kit.name == "hmac" else token.proof
    assert repr(secret) not in repr(token)
    assert secret.hex() not in repr(token)


# ---------------------------------------------------------------------------
# Caveat semantics
# ---------------------------------------------------------------------------


def test_tools_caveat() -> None:
    assert ONLY_READ.check(READ_Q1, NOW) is None
    assert ONLY_READ.check(SEND_ANA, NOW) is not None
    assert ToolsCaveat(()).check(READ_Q1, NOW) is not None  # empty list: nothing


def test_arg_caveat_only_binds_its_own_tool_and_missing_argument_fails() -> None:
    assert ONLY_Q3.check(READ_Q3, NOW) is None
    assert ONLY_Q3.check(READ_Q1, NOW) == "argument 'path' fails glob"
    assert ONLY_Q3.check(SEND_BEN, NOW) is None  # another tool: not this caveat's business
    assert ONLY_Q3.check(Call("read_file", {}), NOW) == "argument 'path' is missing"
    assert ONLY_Q3.check(Call("read_file", {"path": 7}), NOW) is not None


@pytest.mark.parametrize("now", [NOW + 60, NOW + 61, float("nan"), float("inf"), "0", None, True])
def test_expiry_caveat_denies_at_and_after_the_limit_and_on_bad_clocks(now: Any) -> None:
    assert SOON.check(READ_Q3, now) == "caveat expired"


def test_expiry_caveat_allows_strictly_before() -> None:
    assert SOON.check(READ_Q3, NOW + 59.999) is None


def test_expiry_caveat_and_base_expiry_the_earlier_one_wins(kit: Kit) -> None:
    base_end = GRANT.expires_at
    shorter = attenuate(kit.issue(), ExpiryCaveat(NOW + 60))
    assert kit.authorize(shorter, READ_Q3, NOW + 59).allowed
    late = kit.authorize(shorter, READ_Q3, NOW + 60)
    assert not late.allowed and late.reason == "caveat 1: caveat expired"
    assert kit.authorize(kit.issue(), READ_Q3, NOW + 60).allowed  # the original is unaffected

    # A caveat that names a LATER time cannot extend the base grant.
    longer = attenuate(kit.issue(), ExpiryCaveat(base_end + 10_000))
    assert kit.authorize(longer, READ_Q3, base_end - 1).allowed
    expired = kit.authorize(longer, READ_Q3, base_end)
    assert not expired.allowed and expired.reason == "grant expired"

    # Several expiry caveats: the effective expiry is the minimum of all of them.
    both = chain(
        kit.issue(), ExpiryCaveat(NOW + 500), ExpiryCaveat(NOW + 60), ExpiryCaveat(NOW + 90)
    )
    assert kit.authorize(both, READ_Q3, NOW + 59).allowed
    assert not kit.authorize(both, READ_Q3, NOW + 60).allowed


def test_a_caveat_cannot_open_an_argument_the_base_grant_does_not_name(kit: Kit) -> None:
    """Caveats are extra conditions, never extra permissions (closed-world base grant)."""
    token = attenuate(kit.issue(), ArgCaveat("read_file", Constraint("mode", "any")))
    assert not kit.authorize(token, Call("read_file", {"path": "reports/a", "mode": "w"})).allowed
    assert not kit.authorize(token, READ_Q3).allowed  # and now `mode` is required but refused


def test_authorize_denies_things_that_are_not_calls(kit: Kit) -> None:
    assert not kit.authorize(kit.issue(), {"tool": "read_file"}).allowed  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Canonical encoding of caveats
# ---------------------------------------------------------------------------


def test_caveat_encoding_is_sorted_compact_ascii() -> None:
    assert encode_caveat(ONLY_READ) == b'{"tools":["read_file"],"type":"tools"}'
    assert encode_caveat(SOON) == b'{"not_after":1060,"type":"expiry"}'
    assert encode_caveat(ONLY_Q3) == (
        b'{"constraint":{"arg":"path","op":"glob","value":"reports/q3/*"},'
        b'"tool":"read_file","type":"arg"}'
    )
    assert encode_caveat(ToolsCaveat(("café",))) == b'{"tools":["caf\\u00e9"],"type":"tools"}'


@pytest.mark.parametrize(
    "data",
    [
        b'{"tools": ["a"],"type":"tools"}',  # whitespace
        b'{"type":"tools","tools":["a"]}',  # keys not sorted
        b'{"tools":["a"],"tools":["a","b"],"type":"tools"}',  # duplicate key
        b'{"tools":["a"],"type":"tools","type":"tools"}',  # duplicate key, same value
        b'{"tools":["\\u0061"],"type":"tools"}',  # escaped ASCII: a second spelling of "a"
        b'{"tools":["a"],"type":"tools"}\n',  # trailing byte
        b'{"not_after":1060.0,"type":"expiry"}'[:-1],  # cut short
        b'{"not_after":1.50,"type":"expiry"}',  # second spelling of 1.5
        b'{"not_after":1E3,"type":"expiry"}',
        b'{"not_after":-0,"type":"expiry"}',
        b'{"not_after":NaN,"type":"expiry"}',
        b'{"not_after":Infinity,"type":"expiry"}',
        b'{"not_after":1e999,"type":"expiry"}',  # parses to infinity
        b'{"not_after":true,"type":"expiry"}',  # bool is not a time
        b'{"not_after":"1060","type":"expiry"}',
        b'{"not_after":null,"type":"expiry"}',
        b'{"tools":"read_file","type":"tools"}',  # a string is not a list of tools
        b'{"tools":[1],"type":"tools"}',
        b'{"tools":[""],"type":"tools"}',
        b'{"tools":["a","a"],"type":"tools"}',
        b'{"tools":["a"],"type":"tool"}',  # unknown type
        b'{"type":"allow_all"}',  # unknown type
        b'{"tools":["a"],"type":["tools"]}',  # type is not a string
        b'{"extra":1,"tools":["a"],"type":"tools"}',  # unknown key
        b'{"type":"tools"}',  # missing key
        b'{"constraint":{"arg":"p","op":"regex","value":"."},"tool":"t","type":"arg"}',
        b'{"constraint":{"arg":"p","op":"any","value":null},"tool":"t","type":"arg"}',
        b'{"constraint":{"arg":"p","op":"eq"},"tool":"t","type":"arg"}',
        b'{"constraint":{"arg":"p","op":"eq","value":[1]},"tool":"t","type":"arg"}',
        b'{"constraint":{"arg":"p","op":["eq"],"value":1},"tool":"t","type":"arg"}',
        b'{"constraint":{"arg":"p","op":"eq","value":1,"x":1},"tool":"t","type":"arg"}',
        b'{"constraint":["p","eq",1],"tool":"t","type":"arg"}',
        b'{"constraint":{"arg":"p","op":"eq","value":1},"tool":7,"type":"arg"}',
        b'["tools","a"]',
        b'"tools"',
        b"null",
        b"",
        b"\xff",
        '{"tools":["café"],"type":"tools"}'.encode(),  # raw non-ASCII
    ],
)
def test_decode_caveat_rejects_everything_but_the_canonical_form(data: bytes) -> None:
    with pytest.raises(ChainError):
        decode_caveat(data)


def test_decode_caveat_wants_bytes() -> None:
    with pytest.raises(ChainError):
        decode_caveat('{"tools":["a"],"type":"tools"}')  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "build",
    [
        lambda: ToolsCaveat("read_file"),  # a bare string would be split into letters
        lambda: ToolsCaveat(("a", "a")),
        lambda: ToolsCaveat(("",)),
        lambda: ToolsCaveat((1,)),
        lambda: ToolsCaveat({"a"}),
        lambda: ArgCaveat("", Constraint("p", "any")),
        lambda: ArgCaveat("t", {"arg": "p", "op": "any"}),
        lambda: ExpiryCaveat(True),
        lambda: ExpiryCaveat(float("nan")),
        lambda: ExpiryCaveat(float("inf")),
        lambda: ExpiryCaveat("10"),
    ],
)
def test_caveat_constructors_validate(build: Any) -> None:
    with pytest.raises(ChainError):
        build()


class LyingStr(str):
    """A str subclass that claims to equal everything (the M0 review attack)."""

    def __eq__(self, other: object) -> bool:
        return True

    __hash__ = str.__hash__


def test_subclassed_values_are_refused_in_caveats() -> None:
    with pytest.raises(ChainError):
        ToolsCaveat((LyingStr("read_file"),))
    with pytest.raises(ChainError):
        ArgCaveat(LyingStr("read_file"), Constraint("p", "any"))

    class LongLived(float):
        def __gt__(self, other: object) -> bool:
            return True

    with pytest.raises(ChainError):
        ExpiryCaveat(LongLived(1.0))


class GenerousCaveat(ToolsCaveat):
    """A caveat subclass that never objects. It must not be attachable or encodable."""

    def check(self, call: Call, now: float) -> None:
        return None


def test_caveat_subclasses_are_refused(kit: Kit) -> None:
    with pytest.raises(ChainError):
        encode_caveat(GenerousCaveat(("read_file",)))
    with pytest.raises(ChainError):
        attenuate(kit.issue(), GenerousCaveat(("read_file",)))
    with pytest.raises(ChainError):
        attenuate(kit.issue(), {"type": "tools", "tools": ["read_file"]})  # type: ignore[arg-type]


def caveat_strategy() -> st.SearchStrategy[Any]:
    names = st.text(min_size=1, max_size=5)
    numbers = st.one_of(st.integers(), st.floats(allow_nan=False, allow_infinity=False))
    return st.one_of(
        st.lists(names, unique=True, max_size=4).map(lambda t: ToolsCaveat(tuple(t))),
        st.builds(ArgCaveat, names, constraints()),
        numbers.map(ExpiryCaveat),
    )


@settings(max_examples=EXAMPLES, deadline=None)
@given(caveat_strategy())
def test_caveat_encoding_round_trips_exactly(caveat: Any) -> None:
    """decode(encode(c)) rebuilds c, and re-encoding gives the same bytes.

    Together with "decode rejects every non-canonical spelling", this makes the
    encoding one-to-one: no two byte strings mean the same caveat, so no two
    caveat lists share a signature input.
    """
    data = encode_caveat(caveat)
    back = decode_caveat(data)
    assert type(back) is type(caveat)
    assert back == caveat
    assert encode_caveat(back) == data
    assert data.isascii()


@settings(max_examples=EXAMPLES, deadline=None)
@given(st.lists(caveat_strategy(), max_size=4), st.lists(caveat_strategy(), max_size=4))
def test_different_caveat_lists_never_share_a_signature(a: list, b: list) -> None:
    """Canonicalization ambiguity check, on the HMAC chain where it would bite.

    Each caveat is MACed in its own step, so [c1, c2] can never be confused
    with one caveat whose bytes are c1 followed by c2. If two lists encode
    differently, their final signatures differ.
    """
    authority = HmacAuthority(ROOT_KEY)
    encoded_a = [encode_caveat(c) for c in a]
    encoded_b = [encode_caveat(c) for c in b]
    sig_a = chain(authority.issue("t", GRANT), *a).signature
    sig_b = chain(authority.issue("t", GRANT), *b).signature
    assert (sig_a == sig_b) == (encoded_a == encoded_b)


def test_concatenated_caveats_are_not_one_caveat() -> None:
    """Length-extension style: two caveats glued together are not a third caveat,
    and gluing does not give the signature of the two-step chain."""
    authority = HmacAuthority(ROOT_KEY)
    glued = encode_caveat(ONLY_READ) + encode_caveat(ONLY_Q3)
    with pytest.raises(ChainError):
        decode_caveat(glued)
    two_steps = chain(authority.issue("t", GRANT), ONLY_READ, ONLY_Q3)
    one_step = attenuate(authority.issue("t", GRANT), ONLY_READ)
    forged = chain_module._mac(authority.issue("t", GRANT).signature, glued)
    assert forged != two_steps.signature
    assert forged != one_step.signature


def test_identifier_and_grant_cannot_trade_bytes() -> None:
    """The root message is one JSON object, so moving characters from the
    identifier into the grant (or back) changes the message."""
    authority = HmacAuthority(ROOT_KEY)
    a = authority.issue('t","x":"', GRANT)
    b = authority.issue("t", GRANT)
    assert a.signature != b.signature
    assert authority.verify(a).identifier == 't","x":"'


def test_grant_encoding_keeps_what_grant_to_dict_would_lose(kit: Kit) -> None:
    """Two `max` constraints on one argument cannot go through Grant.to_dict."""
    cap = Capability("pay", (Constraint("x", "max", 5), Constraint("x", "max", 3)))
    grant = Grant((cap, Capability("read", (), 2)), 2.5)
    with pytest.raises(ValueError):
        grant.to_dict()
    token = kit.parse(kit.issue("t", grant).serialize())
    assert kit.verify(token).grant == grant
    assert type(kit.verify(token).grant.expires_at) is float


# ---------------------------------------------------------------------------
# Attacks on the chain, one test per attack
# ---------------------------------------------------------------------------


def test_removing_a_middle_caveat_fails(kit: Kit) -> None:
    token = chain(kit.issue(), ONLY_ANA, ONLY_READ, ONLY_Q3)
    forged = drop_block(token, 2)
    assert forged.caveats == (ONLY_ANA, ONLY_Q3)
    assert_rejected(kit, forged)


def test_removing_the_first_caveat_fails(kit: Kit) -> None:
    assert_rejected(kit, drop_block(chain(kit.issue(), ONLY_READ, ONLY_Q3), 1))


def test_removing_the_last_caveat_fails(kit: Kit) -> None:
    """Why the holder of the narrowed token cannot undo the last step.

    HMAC chain: the token holds sig2 = HMAC(sig1, caveat 2). A token with only
    caveat 1 must carry sig1. sig1 was the KEY of that HMAC, and HMAC cannot be
    run backwards to recover its key, so the holder can only present sig2,
    which the verifier does not arrive at when it stops after caveat 1.

    Ed25519 chain: blocks 0 and 1 and their signatures are still perfectly
    valid on their own. What is missing is the proof for the shortened chain:
    block 1 names public key pk2, and the matching private key sk2 was dropped
    when block 2 was appended. The holder only has sk3, which matches pk3.
    """
    token = chain(kit.issue(), ONLY_READ, ONLY_Q3)
    assert not kit.authorize(token, READ_Q1).allowed
    forged = drop_block(token, 2)
    assert forged.caveats == (ONLY_READ,)
    reason = assert_rejected(kit, forged)
    if kit.name == "hmac":
        assert "signature mismatch" in reason
    else:
        assert "private key does not match" in reason


def test_removing_every_caveat_fails(kit: Kit) -> None:
    token = chain(kit.issue(), ONLY_READ, ONLY_Q3)
    assert_rejected(kit, drop_block(drop_block(token, 2), 1))


def test_reordering_caveats_fails(kit: Kit) -> None:
    """The order is part of what is signed.

    HMAC: caveat N is MACed under a key that depends on caveats 1..N-1.
    Ed25519: block N is signed by the key block N-1 named, and its position is
    inside the signed bytes as well.
    """
    token = chain(kit.issue(), ONLY_ANA, ONLY_READ, ONLY_Q3)
    assert_rejected(kit, swap_blocks(token, 1, 2))
    assert_rejected(kit, swap_blocks(token, 2, 3))
    assert_rejected(kit, swap_blocks(token, 1, 3))


def test_reordering_the_serialized_segments_fails(kit: Kit) -> None:
    parts = chain(kit.issue(), ONLY_ANA, ONLY_READ).serialize().split(".")
    if kit.name == "hmac":  # prefix, root, caveat 1, caveat 2, signature
        parts[2], parts[3] = parts[3], parts[2]
    else:  # prefix, block 0, sig 0, block 1, sig 1, block 2, sig 2, marker, proof
        parts[3:5], parts[5:7] = parts[5:7], parts[3:5]
    with pytest.raises(ChainError):
        kit.verify(".".join(parts))


def test_editing_a_caveat_fails(kit: Kit) -> None:
    token = chain(kit.issue(), ONLY_READ, ONLY_Q3)
    wider = ArgCaveat("read_file", Constraint("path", "glob", "reports/*"))
    assert_rejected(kit, replace(token, caveats=(ONLY_READ, wider)))
    assert_rejected(kit, replace(token, caveats=(ToolsCaveat(("read_file", "pay")), ONLY_Q3)))


def test_editing_the_base_grant_fails(kit: Kit) -> None:
    token = attenuate(kit.issue(), ONLY_READ)
    wider = Grant(
        (Capability.from_dict({"tool": "read_file", "args": {"path": {"any": True}}}),), 1
    )
    assert_rejected(kit, replace(token, grant=wider))
    assert_rejected(kit, replace(token, grant=replace(GRANT, expires_at=GRANT.expires_at + 1)))
    assert_rejected(kit, replace(token, identifier="tok-2"))  # dodging a revocation lookup


def test_swapping_in_a_caveat_from_another_token_fails(kit: Kit) -> None:
    """Token B carries a harmless caveat. Its block is valid, but only in B's chain."""
    a = chain(kit.issue("tok-a"), ONLY_READ, ONLY_Q3)
    b = chain(kit.issue("tok-b"), ONLY_READ, SOON)
    if kit.name == "hmac":
        forged = replace(a, caveats=(ONLY_READ, SOON))
    else:
        forged = replace(
            a,
            caveats=(ONLY_READ, SOON),
            next_keys=a.next_keys[:2] + b.next_keys[2:],
            signatures=a.signatures[:2] + b.signatures[2:],
            proof=b.proof,
        )
    assert_rejected(kit, forged)


def test_splicing_another_tokens_whole_tail_fails(kit: Kit) -> None:
    """Take the base grant from a wide token and every caveat, signature and
    proof from a narrow one issued by the same authority."""
    wide = kit.issue("tok-wide")
    narrow_grant = Grant(GRANT.capabilities[:1], GRANT.expires_at)
    narrow = chain(kit.issue("tok-narrow", narrow_grant), SOON)
    forged = replace(narrow, identifier=wide.identifier, grant=wide.grant)
    assert_rejected(kit, forged)
    if kit.name == "ed25519":
        # Keep block 0 of the wide token intact (root signature included) and
        # attach the narrow token's later blocks: block 1 was signed by the
        # narrow chain's sk1, not by the key the wide block 0 names.
        forged = replace(
            narrow,
            identifier=wide.identifier,
            grant=wide.grant,
            next_keys=wide.next_keys[:1] + narrow.next_keys[1:],
            signatures=wide.signatures[:1] + narrow.signatures[1:],
        )
        assert "block 1: bad signature" in assert_rejected(kit, forged)


def test_truncating_the_serialized_token_fails(kit: Kit) -> None:
    text = chain(kit.issue(), ONLY_READ, ONLY_Q3).serialize()
    parts = text.split(".")
    for keep in range(len(parts)):
        with pytest.raises(ChainError):
            kit.verify(".".join(parts[:keep]))
    for cut in (1, 2, 3, 10, len(text) // 2):
        with pytest.raises(ChainError):
            kit.verify(text[:-cut])
    with pytest.raises(ChainError):
        kit.verify("")


def test_wrong_root_key_fails(kit: Kit) -> None:
    other = make_kit(kit.name, OTHER_ROOT_KEY)
    token = attenuate(kit.issue(), ONLY_READ)
    with pytest.raises(ChainError):
        other.verify(token)
    assert not other.authorize(token, READ_Q3).allowed
    assert kit.authorize(token, READ_Q3).allowed


def test_a_token_of_the_other_construction_is_refused(kit: Kit) -> None:
    other = make_kit("ed25519" if kit.name == "hmac" else "hmac")
    foreign = other.issue()
    assert_rejected(kit, foreign)
    assert_rejected(kit, foreign.serialize())


@pytest.mark.parametrize("junk", [None, 7, b"tgm1.x.y", ["tgm1"], object()])
def test_things_that_are_not_tokens_are_refused(kit: Kit, junk: Any) -> None:
    assert_rejected(kit, junk)
    with pytest.raises(ChainError):
        attenuate(junk, ONLY_READ)


def test_a_token_object_changed_in_place_is_caught(kit: Kit) -> None:
    """Frozen dataclasses can still be written with object.__setattr__ (M0 review).

    verify never reads authority from the live object: it serializes it and
    rebuilds everything from those bytes, so an in-place edit is just another
    forged token.
    """
    token = chain(kit.issue(), ONLY_READ)
    assert not kit.authorize(token, SEND_ANA).allowed
    object.__setattr__(token, "caveats", ())
    if kit.name == "ed25519":
        object.__setattr__(token, "next_keys", token.next_keys[:1])
        object.__setattr__(token, "signatures", token.signatures[:1])
    assert_rejected(kit, token)
    assert not kit.authorize(token, SEND_ANA).allowed


def test_a_lying_caveat_smuggled_into_a_token_object_is_caught(kit: Kit) -> None:
    token = chain(kit.issue(), ONLY_READ)
    object.__setattr__(token, "caveats", (GenerousCaveat(("read_file",)),))
    assert_rejected(kit, token)
    assert not kit.authorize(token, SEND_ANA).allowed


def test_a_caveat_edited_in_place_after_signing_is_caught(kit: Kit) -> None:
    token = chain(kit.issue(), ONLY_Q3)
    caveat = ArgCaveat("read_file", Constraint("path", "glob", "reports/q3/*"))
    object.__setattr__(token, "caveats", (caveat,))
    assert kit.authorize(token, READ_Q3).allowed
    object.__setattr__(caveat.constraint, "value", "*")
    assert_rejected(kit, token)


# --- construction 1 only ----------------------------------------------------


def test_hmac_issue_is_deterministic_and_bound_to_identifier_and_grant() -> None:
    authority = HmacAuthority(ROOT_KEY)
    assert authority.issue("t", GRANT).signature == authority.issue("t", GRANT).signature
    assert authority.issue("t", GRANT).signature != authority.issue("u", GRANT).signature
    other = replace(GRANT, expires_at=GRANT.expires_at + 1)
    assert authority.issue("t", GRANT).signature != authority.issue("t", other).signature


def test_hmac_signature_changes_at_every_step() -> None:
    token = HmacAuthority(ROOT_KEY).issue("t", GRANT)
    seen = {token.signature}
    for caveat in (ONLY_ANA, ONLY_READ, ONLY_Q3, ONLY_Q3):
        token = attenuate(token, caveat)
        assert token.signature not in seen
        seen.add(token.signature)


def test_hmac_root_and_caveat_messages_are_domain_separated() -> None:
    """A signature is the HMAC key of the next step. If the root step and the
    caveat step used the same message format, a token signature could be
    presented as a root key for a pretend authority, or a caveat MAC be read as
    an issue MAC. Different tags make the two kinds of message disjoint."""
    authority = HmacAuthority(ROOT_KEY)
    token = authority.issue("t", GRANT)
    pretend = HmacAuthority(token.signature)  # the holder plays authority with sig0 as key
    minted = pretend.issue("t", GRANT)
    assert_rejected(make_kit("hmac"), minted)
    assert_rejected(make_kit("hmac"), replace(token, signature=minted.signature))


def test_hmac_root_key_must_be_long_bytes() -> None:
    for bad in (b"short", b"k" * 31, "k" * 32, bytearray(32), None):
        with pytest.raises(ChainError):
            HmacAuthority(bad)  # type: ignore[arg-type]


def test_hmac_signature_must_be_32_bytes() -> None:
    kit = make_kit("hmac")
    token = kit.issue()
    for bad in (b"", token.signature[:-1], token.signature + b"\0", token.signature.hex()):
        assert_rejected(kit, replace(token, signature=bad))
        with pytest.raises(ChainError):
            attenuate(replace(token, signature=bad), ONLY_READ)


# --- construction 2 only ----------------------------------------------------


def test_public_verification_needs_only_the_public_key() -> None:
    """The point of construction 2. The verifier below never sees a private root key."""
    authority = KeyAuthority(ROOT_KEY)
    public = authority.public_key
    text = attenuate(authority.issue("tok-1", GRANT), ONLY_Q3).serialize()
    del authority

    assert type(public) is bytes and len(public) == 32
    assert verify_public(text, public).caveats == (ONLY_Q3,)
    assert authorize_public(text, public, READ_Q3, NOW).allowed
    assert not authorize_public(text, public, READ_Q1, NOW).allowed
    # The cryptography key object works as well as its raw bytes.
    key_object = Ed25519PrivateKey.from_private_bytes(ROOT_KEY).public_key()
    assert verify_public(text, key_object).identifier == "tok-1"


@pytest.mark.parametrize("bad", [None, b"", b"k" * 31, b"k" * 33, "k" * 32, 7])
def test_bad_root_public_keys_are_refused(bad: Any) -> None:
    token = KeyAuthority(ROOT_KEY).issue("t", GRANT)
    with pytest.raises(ChainError):
        verify_public(token, bad)
    assert not authorize_public(token, bad, READ_Q3, NOW).allowed


def test_key_authority_accepts_a_key_object_and_rejects_junk() -> None:
    key = Ed25519PrivateKey.generate()
    assert KeyAuthority(key).public_key == key.public_key().public_bytes_raw()
    for bad in (b"short", "k" * 32, None, key.public_key()):
        with pytest.raises(ChainError):
            KeyAuthority(bad)  # type: ignore[arg-type]


def test_every_issue_and_every_block_uses_a_fresh_key() -> None:
    authority = KeyAuthority(ROOT_KEY)
    a, b = authority.issue("t", GRANT), authority.issue("t", GRANT)
    assert a.next_keys != b.next_keys and a.proof != b.proof
    token = chain(a, ONLY_READ, ONLY_READ, ONLY_READ)
    assert len(set(token.next_keys)) == 4
    assert ROOT_KEY not in (token.proof, *token.next_keys)


def test_the_old_private_key_is_gone_after_appending() -> None:
    authority = KeyAuthority(ROOT_KEY)
    parent = authority.issue("t", GRANT)
    child = attenuate(parent, ONLY_READ)
    assert child.proof != parent.proof
    assert parent.proof not in child.serialize().encode()
    assert base64.urlsafe_b64encode(parent.proof).rstrip(b"=").decode() not in child.serialize()
    # And the new key does not let anyone speak for the shorter chain.
    with pytest.raises(ChainError):
        authority.verify(replace(parent, proof=child.proof))


def test_a_token_without_its_proof_is_refused() -> None:
    """Blocks and signatures alone are not a token. Otherwise cutting blocks off
    the end would always work, since every prefix of a valid chain is valid."""
    authority = KeyAuthority(ROOT_KEY)
    token = chain(authority.issue("t", GRANT), ONLY_READ)
    parts = token.serialize().split(".")
    with pytest.raises(ChainError):
        authority.verify(".".join(parts[:-2]))
    with pytest.raises(ChainError):
        authority.verify(replace(token, proof=bytes(32)))
    with pytest.raises(ChainError):
        authority.verify(replace(token, proof=Ed25519PrivateKey.generate().private_bytes_raw()))


def test_block_position_is_signed() -> None:
    """Rewrite the position inside a block and keep its signature: bad signature.
    Present a block at a position other than the one written in it: parse error."""
    authority = KeyAuthority(ROOT_KEY)
    parts = chain(authority.issue("t", GRANT), ONLY_READ, ONLY_Q3).serialize().split(".")

    def decode(segment: str) -> dict:
        return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))

    def encode(block: dict) -> str:
        raw = json.dumps(block, sort_keys=True, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    assert [decode(parts[i])["i"] for i in (1, 3, 5)] == [0, 1, 2]
    moved = decode(parts[5]) | {"i": 1}
    relabelled = [*parts[:3], encode(moved), parts[6], *parts[7:]]
    with pytest.raises(ChainError, match="block 1: bad signature"):
        authority.verify(".".join(relabelled))
    unlabelled = [*parts[:3], parts[5], parts[6], *parts[7:]]
    with pytest.raises(ChainError, match="out of position"):
        authority.verify(".".join(unlabelled))


def test_next_public_key_is_signed() -> None:
    """If the next key were not covered by the block signature, anyone could
    replace it with their own key and then append or drop blocks at will."""
    authority = KeyAuthority(ROOT_KEY)
    token = chain(authority.issue("t", GRANT), ONLY_READ)
    mine = Ed25519PrivateKey.generate()
    my_public = mine.public_key().public_bytes_raw()
    for index in (0, 1):
        keys = list(token.next_keys)
        keys[index] = my_public
        forged = replace(token, next_keys=tuple(keys), proof=mine.private_bytes_raw())
        with pytest.raises(ChainError, match=f"block {index}: bad signature"):
            authority.verify(forged)


def test_block_zero_must_be_signed_by_the_root() -> None:
    """A self-made chain: the attacker is their own root."""
    attacker = KeyAuthority(OTHER_ROOT_KEY)
    wide = Grant((Capability.from_dict({"tool": "pay", "args": {"amount": {"any": True}}}),), 1e12)
    with pytest.raises(ChainError, match="block 0: bad signature"):
        verify_public(attacker.issue("t", wide), KeyAuthority(ROOT_KEY).public_key)


def test_a_caveat_block_cannot_stand_in_for_block_zero() -> None:
    authority = KeyAuthority(ROOT_KEY)
    parts = chain(authority.issue("t", GRANT), ONLY_READ).serialize().split(".")
    with pytest.raises(ChainError):
        authority.verify(".".join([parts[0], *parts[3:]]))


def test_sealed_token_works_but_cannot_be_attenuated() -> None:
    authority = KeyAuthority(ROOT_KEY)
    token = chain(authority.issue("t", GRANT), ONLY_Q3)
    sealed = seal(token)
    assert sealed.sealed and len(sealed.proof) == 64
    assert token.proof not in sealed.serialize().encode()
    assert authority.authorize(sealed, READ_Q3, NOW).allowed
    assert not authority.authorize(sealed, READ_Q1, NOW).allowed
    assert KeyToken.parse(sealed.serialize()) == sealed
    with pytest.raises(ChainError, match="sealed"):
        attenuate(sealed, ONLY_READ)
    with pytest.raises(ChainError, match="sealed"):
        attenuate(KeyToken.parse(sealed.serialize()), ONLY_READ)
    with pytest.raises(ChainError, match="sealed"):
        seal(sealed)


def test_sealed_token_cannot_be_unsealed_or_shortened() -> None:
    authority = KeyAuthority(ROOT_KEY)
    token = chain(authority.issue("t", GRANT), ONLY_READ, ONLY_Q3)
    sealed = seal(token)
    # Pretend the seal is a private key (wrong length), or flip the marker.
    with pytest.raises(ChainError):
        authority.verify(replace(sealed, sealed=False))
    with pytest.raises(ChainError):
        authority.verify(replace(sealed, sealed=False, proof=sealed.proof[:32]))
    parts = sealed.serialize().split(".")
    parts[-2] = "k"
    with pytest.raises(ChainError):
        authority.verify(".".join(parts))
    # Drop the last block and keep the seal: it was made by sk3, block 1 names pk2.
    with pytest.raises(ChainError, match="seal: bad signature"):
        authority.verify(drop_block(sealed, 2))
    # The seal of one token does not seal another.
    other = seal(chain(authority.issue("t", GRANT), ONLY_READ, ONLY_Q3))
    with pytest.raises(ChainError, match="seal: bad signature"):
        authority.verify(replace(sealed, proof=other.proof))


def test_seal_and_block_signatures_are_domain_separated() -> None:
    """The last private key signs either a block or a seal. If the two messages
    could be confused, a seal could be replayed as a block signature (or the
    other way round). The tags make that impossible; this checks they differ
    and that a block signature is not accepted as a seal."""
    for block_tag in (chain_module._TAG_KEY_ROOT, chain_module._TAG_KEY_CAVEAT):
        assert block_tag != chain_module._TAG_KEY_SEAL
        assert not block_tag.startswith(chain_module._TAG_KEY_SEAL)
        assert not chain_module._TAG_KEY_SEAL.startswith(block_tag)
    authority = KeyAuthority(ROOT_KEY)
    parent = authority.issue("t", GRANT)
    child = attenuate(parent, ONLY_READ)
    # child.signatures[1] was made by the key that would seal `parent`.
    forged = replace(parent, proof=child.signatures[1], sealed=True)
    with pytest.raises(ChainError, match="seal: bad signature"):
        authority.verify(forged)


def test_a_degenerate_next_key_is_refused() -> None:
    """Key misuse by the holder, now refused outright.

    Ed25519 as implemented by OpenSSL accepts the identity point as a public
    key, and under that key the signature (identity, 0) verifies for every
    message. A holder who names it as "next" makes everything after their
    block forgeable by anyone. This test used to record that as accepted
    behaviour ("the same as publishing the token"). The security review showed
    it is worse: a bearer can also DROP later caveats and forge the seal (see
    test_small_order_next_key_truncation_exploit_is_refused), so a token
    naming a small-order key no longer verifies at all.
    """
    authority = KeyAuthority(ROOT_KEY)
    parent = attenuate(authority.issue("t", GRANT), ONLY_READ)
    identity = bytes([1]) + bytes(31)
    universal_signature = identity + bytes(32)
    signer = Ed25519PrivateKey.from_private_bytes(parent.proof)
    block = chain_module._block_bytes(2, chain_module._caveat_obj(SOON), identity)
    open_token = KeyToken(
        parent.identifier,
        parent.grant,
        (ONLY_READ, SOON),
        (*parent.next_keys, identity),
        (*parent.signatures, signer.sign(chain_module._TAG_KEY_CAVEAT + block)),
        universal_signature,
        True,
    )
    with pytest.raises(ChainError, match="small-order"):
        authority.verify(open_token)
    assert not authority.authorize(open_token, READ_Q3, NOW).allowed
    assert not authority.authorize(open_token, SEND_ANA, NOW).allowed
    # The forger still cannot get rid of the holder's own blocks.
    with pytest.raises(ChainError):
        authority.verify(replace(drop_block(open_token, 1), proof=universal_signature))


# ---------------------------------------------------------------------------
# Giant and malformed inputs
# ---------------------------------------------------------------------------


def test_caveat_count_is_capped(kit: Kit) -> None:
    token = kit.issue()
    for _ in range(MAX_CAVEATS):
        token = attenuate(token, ToolsCaveat(("read_file",)))
    assert kit.authorize(token, READ_Q3).allowed
    assert len(token.serialize()) <= MAX_TOKEN_CHARS
    with pytest.raises(ChainError, match="at most"):
        attenuate(token, ONLY_READ)


def test_oversized_tokens_are_refused_before_any_work(kit: Kit) -> None:
    text = kit.issue().serialize()
    with pytest.raises(ChainError, match="too long"):
        kit.verify(text + "A" * MAX_TOKEN_CHARS)
    with pytest.raises(ChainError):
        kit.verify(text + ".A" * (MAX_CAVEATS * 4))
    huge = ToolsCaveat(tuple(f"tool-{i:06d}" for i in range(4000)))
    with pytest.raises(ChainError, match="too long"):
        attenuate(kit.issue(), huge).serialize()
    with pytest.raises(ChainError):
        kit.issue("i" * 129)
    with pytest.raises(ChainError):
        kit.issue("")


def _segment(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.mark.parametrize(
    "payload",
    [
        b"[" * 5000 + b"]" * 5000,  # nesting deep enough to exhaust the recursion limit
        b'{"a":' * 3000 + b"1" + b"}" * 3000,
        b"9" * 5000,  # longer than Python's int parsing limit
        b"1e400",
        b"{}",
        b"[]",
        b'{"grant":{"capabilities":[],"expires_at":1},"id":"t","x":1}',
        b'{"grant":{"capabilities":{},"expires_at":1},"id":"t"}',
        b'{"grant":{"capabilities":[],"expires_at":true},"id":"t"}',
        b'{"grant":{"capabilities":[],"expires_at":1},"id":7}',
        b'{"grant":{"capabilities":[{"constraints":[],"max_calls":true,"tool":"t"}],'
        b'"expires_at":1},"id":"t"}',
        b'{"grant":{"capabilities":[{"constraints":{},"max_calls":null,"tool":"t"}],'
        b'"expires_at":1},"id":"t"}',
        b'{"grant":{"capabilities":[{"constraints":[],"max_calls":null,"tool":""}],'
        b'"expires_at":1},"id":"t"}',
    ],
)
def test_hostile_root_blocks_fail_cleanly(payload: bytes) -> None:
    """Every one of these must end in ChainError, never RecursionError, TypeError or a hang."""
    text = ".".join(["tgm1", _segment(payload), _segment(bytes(32))])
    with pytest.raises(ChainError):
        HmacToken.parse(text)
    assert not HmacAuthority(ROOT_KEY).authorize(text, READ_Q3, NOW).allowed
    key_text = ".".join(["tgk1", _segment(payload), _segment(bytes(64)), "k", _segment(bytes(32))])
    with pytest.raises(ChainError):
        KeyToken.parse(key_text)


@pytest.mark.parametrize(
    "mangle",
    [
        lambda t: t + "=",  # padding
        lambda t: t + "\n",
        lambda t: " " + t,
        lambda t: t.replace(".", "..", 1),  # empty segment
        lambda t: t + ".",
        lambda t: t.replace("-", "+").replace("_", "/") + "+",  # standard alphabet
        lambda t: t.upper(),
        lambda t: t.replace("tgm1", "tgm2").replace("tgk1", "tgk2"),
        lambda t: t.encode(),
    ],
)
def test_malformed_strings_are_refused(kit: Kit, mangle: Any) -> None:
    text = attenuate(kit.issue(), ONLY_READ).serialize()
    with pytest.raises(ChainError):
        kit.verify(mangle(text))


def test_base64_with_stray_trailing_bits_is_refused(kit: Kit) -> None:
    """ "QQ" and "QR" both decode to b"A" in a lenient decoder. Only one is accepted,
    so a token has exactly one string form."""
    assert base64.urlsafe_b64decode("QQ==") == base64.urlsafe_b64decode("QR==") == b"A"
    assert chain_module._b64decode("QQ") == b"A"
    with pytest.raises(ChainError):
        chain_module._b64decode("QR")
    text = kit.issue().serialize()
    last = text[-1]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    neighbour = alphabet[alphabet.index(last) ^ 1]  # differs only in the lowest bit
    with pytest.raises(ChainError):
        kit.verify(text[:-1] + neighbour)


# ---------------------------------------------------------------------------
# Byte flips anywhere in the serialized token
# ---------------------------------------------------------------------------


def _samples() -> list[tuple[str, str, Any]]:
    out = []
    for name in ("hmac", "ed25519"):
        kit = make_kit(name)
        tokens = [
            kit.issue(),
            chain(kit.issue(), ONLY_READ),
            chain(kit.issue(), ONLY_ANA, ONLY_Q3, SOON),
        ]
        if name == "ed25519":
            tokens.append(seal(tokens[-1]))
        out += [(name, t.serialize(), t) for t in tokens]
    return out


SAMPLES = _samples()


def _assert_change_is_harmless(name: str, original: Any, changed: str) -> None:
    kit = make_kit(name)
    try:
        parsed = kit.parse(changed)
    except ChainError:
        return
    if parsed == original:  # the same token under another spelling (none is known to exist)
        return
    with pytest.raises(ChainError):
        kit.verify(changed)
    assert not kit.authorize(changed, READ_Q3).allowed


@settings(max_examples=EXAMPLES, deadline=None)
@given(st.data())
def test_any_single_byte_change_is_caught(data: st.DataObject) -> None:
    name, text, original = data.draw(st.sampled_from(SAMPLES))
    position = data.draw(st.integers(0, len(text) - 1))
    replacement = chr(data.draw(st.integers(0, 255).filter(lambda n: chr(n) != text[position])))
    _assert_change_is_harmless(name, original, text[:position] + replacement + text[position + 1 :])


@settings(max_examples=EXAMPLES // 2, deadline=None)
@given(st.data())
def test_any_single_byte_insertion_or_deletion_is_caught(data: st.DataObject) -> None:
    name, text, original = data.draw(st.sampled_from(SAMPLES))
    position = data.draw(st.integers(0, len(text) - 1))
    if data.draw(st.booleans()):
        changed = text[:position] + text[position + 1 :]
    else:
        changed = text[:position] + chr(data.draw(st.integers(0, 127))) + text[position:]
    _assert_change_is_harmless(name, original, changed)


def test_every_single_bit_flip_of_one_hmac_token_is_caught() -> None:
    """Exhaustive, not sampled: all 8 bit flips at every position of one token."""
    name, text, original = SAMPLES[2]
    assert name == "hmac"
    authority = HmacAuthority(ROOT_KEY)
    raw = text.encode()
    for position in range(len(raw)):
        for bit in range(8):
            changed = bytearray(raw)
            changed[position] ^= 1 << bit
            flipped = changed.decode("latin-1")
            assert not authority.authorize(flipped, READ_Q3, NOW).allowed, (position, bit)


def test_every_position_of_one_key_token_resists_a_bit_flip() -> None:
    for name, text, _ in SAMPLES:
        if name != "ed25519":
            continue
        authority = KeyAuthority(ROOT_KEY)
        raw = text.encode()
        for position in range(len(raw)):
            changed = bytearray(raw)
            changed[position] ^= 1 << (position % 7)
            flipped = changed.decode("latin-1")
            assert not authority.authorize(flipped, READ_Q3, NOW).allowed, position


# ---------------------------------------------------------------------------
# Monotonicity: adding caveats never adds authority
# ---------------------------------------------------------------------------


@st.composite
def chain_cases(draw: st.DrawFn) -> tuple[Grant, list, Call, float]:
    """A grant, a call aimed at it, a time, and up to five caveats.

    About two caveats in three are written to hold for the drawn call, so that
    the full token allows the call often enough for the property to bite.
    """
    grant = draw(grants())
    call = draw(calls_for(grant))
    now = draw(times(grant))
    caveats = []
    for _ in range(draw(st.integers(0, 5))):
        kind = draw(st.sampled_from(("tools", "arg", "expiry", "holds", "holds", "holds")))
        if kind == "tools":
            caveats.append(ToolsCaveat(tuple(draw(st.lists(st.sampled_from(TOOLS), unique=True)))))
        elif kind == "arg":
            caveats.append(ArgCaveat(draw(st.sampled_from(TOOLS)), draw(constraints())))
        elif kind == "expiry":
            caveats.append(ExpiryCaveat(draw(st.sampled_from(EXPIRIES))))
        else:
            scalars = sorted(a for a, v in call.args.items() if type(v) in (bool, int, str))
            choice = draw(st.integers(0, 2))
            if choice == 0 and scalars:
                arg = draw(st.sampled_from(scalars))
                caveats.append(ArgCaveat(call.tool, Constraint(arg, "eq", call.args[arg])))
            elif choice == 1:
                caveats.append(ToolsCaveat((call.tool, *(t for t in TOOLS[:1] if t != call.tool))))
            else:
                caveats.append(ExpiryCaveat(1000))
    return grant, caveats, call, now


def _check_monotone(kit: Kit, case: tuple[Grant, list, Call, float]) -> bool:
    """Returns whether the full token allowed the call."""
    grant, caveats, call, now = case
    token = kit.issue("t", grant)
    decisions = [kit.authorize(token, call, now).allowed]
    for caveat in caveats:
        # Every step goes through the string form, as it would between two agents.
        token = kit.parse(attenuate(kit.parse(token.serialize()), caveat).serialize())
        decisions.append(kit.authorize(token, call, now).allowed)
    base = grant.allows(call, now)
    assert decisions[0] == base
    # The reference model: base grant AND every caveat so far.
    holds = [c.check(call, now) is None for c in caveats]
    for n, decision in enumerate(decisions):
        assert decision == (base and all(holds[:n]))
    # Monotone: once denied, denied for every longer caveat list.
    assert decisions == sorted(decisions, reverse=True)
    if decisions[-1]:
        assert all(decisions) and base
    return decisions[-1]


@settings(max_examples=EXAMPLES, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(chain_cases())
def test_adding_caveats_never_adds_authority_hmac(case: tuple) -> None:
    """If the attenuated token authorizes a call, so does the token with any
    PREFIX of its caveat list, and so does the base grant alone."""
    _check_monotone(make_kit("hmac"), case)


@settings(max_examples=EXAMPLES // 4, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(chain_cases())
def test_adding_caveats_never_adds_authority_ed25519(case: tuple) -> None:
    _check_monotone(make_kit("ed25519"), case)


def test_the_monotonicity_property_is_not_vacuous() -> None:
    """The strategy must be able to produce a call that survives three or more caveats,
    and one that the base grant allows but a caveat stops."""
    kit = make_kit("hmac")
    survivor = find(chain_cases(), lambda c: len(c[1]) >= 3 and _check_monotone(kit, c))
    assert len(survivor[1]) >= 3
    stopped = find(chain_cases(), lambda c: c[0].allows(c[2], c[3]) and not _check_monotone(kit, c))
    assert stopped[1]


def test_share_of_monotonicity_cases_that_end_in_allow() -> None:
    """Counts how often the property's interesting branch runs, with a fixed seed."""
    import random

    from hypothesis import Phase, seed

    kit = make_kit("hmac")
    allowed = 0
    total = 0

    @seed(0)
    @settings(max_examples=300, deadline=None, database=None, phases=[Phase.generate])
    @given(chain_cases())
    def count(case: tuple) -> None:
        nonlocal allowed, total
        total += 1
        allowed += bool(case[1]) and _check_monotone(kit, case)

    random.seed(0)
    count()
    assert total >= 300
    assert allowed / total > 0.05, f"only {allowed} of {total} cases ended in allow"


# ---------------------------------------------------------------------------
# Security review fixes
# ---------------------------------------------------------------------------

# --- 1. small-order Ed25519 public keys -------------------------------------
#
# Independent curve arithmetic, sharing nothing with the module: the curve is
# -x^2 + y^2 = 1 + d x^2 y^2 over GF(p), p = 2^255 - 19, d = -121665/121666.

ED_P = 2**255 - 19
ED_D = -121665 * pow(121666, -1, ED_P) % ED_P
ED_L = 2**252 + 27742317777372353535851937790883648493  # order of the prime subgroup
ED_IDENTITY = (0, 1)
Point = tuple[int, int]


def ed_add(a: Point, b: Point) -> Point:
    (x1, y1), (x2, y2) = a, b
    t = ED_D * x1 * x2 * y1 * y2 % ED_P
    x3 = (x1 * y2 + x2 * y1) * pow(1 + t, -1, ED_P) % ED_P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, -1, ED_P) % ED_P
    return x3, y3


def ed_mul(k: int, point: Point) -> Point:
    result = ED_IDENTITY
    while k:
        if k & 1:
            result = ed_add(result, point)
        point = ed_add(point, point)
        k >>= 1
    return result


def ed_decode(encoding: bytes) -> Point | None:
    """Lenient decoding, as OpenSSL does it: y is reduced modulo p, and the sign
    bit is tolerated when x is 0. None if no point has this y."""
    n = int.from_bytes(encoding, "little")
    sign, y = n >> 255, (n & (2**255 - 1)) % ED_P
    x2 = (y * y - 1) * pow(ED_D * y * y + 1, -1, ED_P) % ED_P
    x = pow(x2, (ED_P + 3) // 8, ED_P)
    if x * x % ED_P != x2:
        x = x * pow(2, (ED_P - 1) // 4, ED_P) % ED_P
    if x * x % ED_P != x2:
        return None
    if x & 1 != sign:
        x = (ED_P - x) % ED_P
    return x, y


def ed_encode(point: Point) -> bytes:
    x, y = point
    return (y | (x & 1) << 255).to_bytes(32, "little")


def is_small_order(encoding: bytes) -> bool:
    point = ed_decode(encoding)
    return point is not None and ed_mul(8, point) == ED_IDENTITY


@functools.cache
def _torsion_points() -> frozenset[Point]:
    """All points whose order divides 8, found without any hard-coded value:
    L * P kills the prime-order part of a random point P and leaves its
    small-order part."""
    rng = random.Random(20261117)
    found: set[Point] = set()
    while len(found) < 8:
        point = ed_decode(rng.randbytes(32))
        if point is not None:
            found.add(ed_mul(ED_L, point))
    return frozenset(found)


def _all_small_order_encodings() -> set[bytes]:
    """Every 32-byte string that decodes to a small-order point: each y of a
    torsion point, each way of writing it in 255 bits (y, and y + p if it
    fits), with the sign bit clear and set."""
    out = set()
    for _, y in _torsion_points():
        for y_field in (y, y + ED_P):
            if y_field < 2**255:
                out |= {(y_field | sign << 255).to_bytes(32, "little") for sign in (0, 1)}
    return out


SMALL_ORDER = sorted(_all_small_order_encodings())
KEY_SAMPLE = KeyAuthority(ROOT_KEY).issue("t", GRANT)


def module_rejects_as_root(encoding: bytes) -> bool:
    """True if the module refuses `encoding` as a root public key for being
    small-order. An ordinary wrong key gets as far as "bad signature"."""
    with pytest.raises(ChainError) as info:
        verify_public(KEY_SAMPLE, encoding)
    return "small-order" in str(info.value)


def module_rejects_as_next(encoding: bytes) -> bool:
    """True if the module refuses a token whose block 0 names `encoding`."""
    token = replace(KEY_SAMPLE, next_keys=(encoding,))
    try:
        token.serialize()
    except ChainError as exc:
        assert "small-order" in str(exc)
        return True
    return False


def test_the_small_order_set_is_complete_and_exact() -> None:
    """14 encodings: 8 canonical (one per point) and 6 non-canonical."""
    assert len(_torsion_points()) == 8
    assert {ed_mul(8, p) for p in _torsion_points()} == {ED_IDENTITY}
    assert len(SMALL_ORDER) == 14
    assert all(is_small_order(e) for e in SMALL_ORDER)
    canonical = {ed_encode(p) for p in _torsion_points()}
    assert len(canonical) == 8 and canonical < set(SMALL_ORDER)
    assert set(SMALL_ORDER) == chain_module._SMALL_ORDER_KEYS
    # Flipping any one bit of a small-order encoding leaves the set, unless it
    # lands on another member: the set has no near misses the module forgot.
    for encoding in SMALL_ORDER:
        for bit in range(256):
            flipped = (int.from_bytes(encoding, "little") ^ 1 << bit).to_bytes(32, "little")
            assert is_small_order(flipped) == (flipped in chain_module._SMALL_ORDER_KEYS)


@pytest.mark.parametrize("encoding", SMALL_ORDER, ids=lambda e: e.hex()[:8] + ".." + e.hex()[-2:])
def test_small_order_keys_are_refused_everywhere_a_key_enters(encoding: bytes) -> None:
    assert is_small_order(encoding)
    assert module_rejects_as_root(encoding)
    assert module_rejects_as_next(encoding)
    assert "small-order" in authorize_public(KEY_SAMPLE, encoding, READ_Q3, NOW).reason
    try:
        key_object = Ed25519PublicKey.from_public_bytes(encoding)
    except ValueError:
        key_object = None  # a stricter Ed25519 library refuses it before we do
    if key_object is not None:
        with pytest.raises(ChainError, match="small-order"):
            verify_public(KEY_SAMPLE, key_object)
        assert not authorize_public(KEY_SAMPLE, key_object, READ_Q3, NOW).allowed
    # As the next key of a later block, as the key a seal is checked with, and
    # on the holder's side (attenuate, seal, parse).
    token = attenuate(KeyAuthority(ROOT_KEY).issue("t", GRANT), ONLY_READ)
    named = replace(token, next_keys=(token.next_keys[0], encoding))
    for forged in (named, replace(named, proof=bytes(64), sealed=True)):
        with pytest.raises(ChainError, match="small-order"):
            KeyAuthority(ROOT_KEY).verify(forged)
        with pytest.raises(ChainError, match="small-order"):
            forged.serialize()
    with pytest.raises(ChainError, match="small-order"):
        attenuate(named, SOON)
    with pytest.raises(ChainError, match="small-order"):
        seal(named)
    parts = token.serialize().split(".")
    block = json.loads(base64.urlsafe_b64decode(parts[3] + "=" * (-len(parts[3]) % 4)))
    block["next"] = _segment(encoding)
    parts[3] = _segment(json.dumps(block, sort_keys=True, separators=(",", ":")).encode())
    with pytest.raises(ChainError, match="small-order"):
        KeyToken.parse(".".join(parts))
    with pytest.raises(ChainError, match="small-order"):
        chain_module._public_key(encoding, "seal")


def test_a_key_is_refused_exactly_when_eight_times_it_is_the_identity() -> None:
    """Rejected by the module iff 8 * P = identity, by this file's arithmetic.

    3000 honestly generated public keys (fixed seed), 1000 random decodable
    strings, and for good measure points of MIXED order (a real key plus a
    small-order point): those are not small-order, 8 * P is not the identity,
    and they must be accepted as keys like any other.
    """
    rng = random.Random(20261117)
    keys = [
        Ed25519PrivateKey.from_private_bytes(rng.randbytes(32)).public_key().public_bytes_raw()
        for _ in range(3000)
    ]
    assert len(set(keys)) == 3000
    strings: list[bytes] = []
    while len(strings) < 1000:
        candidate = rng.randbytes(32)
        if ed_decode(candidate) is not None:
            strings.append(candidate)
    mixed = [
        ed_encode(ed_add(ed_decode(key), torsion))
        for key in keys[:25]
        for torsion in sorted(_torsion_points() - {ED_IDENTITY})
    ]
    for encoding in keys:
        assert not is_small_order(encoding)
        assert not module_rejects_as_root(encoding)
        assert not module_rejects_as_next(encoding)
    for encoding in strings + mixed:
        assert not is_small_order(encoding)
        assert not module_rejects_as_next(encoding)
        assert not module_rejects_as_root(encoding)
    for encoding in SMALL_ORDER:
        assert is_small_order(encoding)
        assert module_rejects_as_root(encoding)
        assert module_rejects_as_next(encoding)


def test_small_order_next_key_truncation_exploit_is_refused() -> None:
    """The reviewer's exploit, end to end.

    A holder appends block 1 and names the identity point as its "next" key.
    The chain is then extended with a caveat (block 2) and sealed. Under the
    identity key the signature R = identity, S = 0 verifies for EVERY message
    in OpenSSL, so before the fix any bearer could cut block 2 off, put that
    fixed signature in as the seal, and be allowed what block 2 had denied.
    Now the token is refused as soon as the identity key is read.
    """
    authority = KeyAuthority(ROOT_KEY)
    issued = authority.issue("t", GRANT)
    identity = bytes([1]) + bytes(31)
    forged_signature = identity + bytes(32)  # R = identity, S = 0

    # Block 1, honestly signed by the key block 0 named, naming the identity.
    holder_key = Ed25519PrivateKey.from_private_bytes(issued.proof)
    block_1 = chain_module._block_bytes(1, chain_module._caveat_obj(ONLY_READ), identity)
    signature_1 = holder_key.sign(chain_module._TAG_KEY_CAVEAT + block_1)
    # Block 2 narrows to reports/q3 and names a real key, which seals the token.
    # Its signature must verify under the identity key: the fixed one does.
    last_key = Ed25519PrivateKey.generate()
    signatures = (*issued.signatures, signature_1, forged_signature)
    full = KeyToken(
        issued.identifier,
        issued.grant,
        (ONLY_READ, ONLY_Q3),
        (*issued.next_keys, identity, last_key.public_key().public_bytes_raw()),
        signatures,
        last_key.sign(chain_module._seal_bytes(signatures)),
        True,
    )
    # The bearer's forgery: drop block 2, seal with the fixed signature.
    truncated = KeyToken(
        issued.identifier,
        issued.grant,
        (ONLY_READ,),
        (*issued.next_keys, identity),
        (*issued.signatures, signature_1),
        forged_signature,
        True,
    )
    for token in (truncated, full):
        with pytest.raises(ChainError, match="small-order"):
            authority.verify(token)
        with pytest.raises(ChainError, match="small-order"):
            verify_public(token, authority.public_key)
        for call in (READ_Q1, READ_Q3):  # READ_Q1 is what block 2 denied
            decision = authority.authorize(token, call, NOW)
            assert not decision.allowed
            assert "small-order" in decision.reason


# --- 2. surrogates and the round-trip invariant -----------------------------

HIGH, LOW = chr(0xD83D), chr(0xDE00)
PAIR = HIGH + LOW  # two code points
ASTRAL = chr(0x1F600)  # the one character that pair stands for


def _grant_with(tool: str = "read_file", arg: str = "path", value: Any = "a") -> Grant:
    return Grant((Capability(tool, (Constraint(arg, "eq", value),)),), NOW + 3600)


@pytest.mark.parametrize("bad", [PAIR, HIGH, LOW, "a" + HIGH + "b", LOW + HIGH])
def test_strings_with_surrogates_are_refused_on_the_way_in(kit: Kit, bad: str) -> None:
    assert len(PAIR) == 2 and len(ASTRAL) == 1 and PAIR != ASTRAL
    for build in (
        lambda: kit.issue(bad, GRANT),
        lambda: kit.issue("t", _grant_with(tool=bad)),
        lambda: kit.issue("t", _grant_with(arg=bad)),
        lambda: kit.issue("t", _grant_with(value=bad)),
        lambda: attenuate(kit.issue(), ToolsCaveat(("read_file", bad))),
        lambda: attenuate(kit.issue(), ArgCaveat(bad, Constraint("path", "any"))),
        lambda: attenuate(kit.issue(), ArgCaveat("read_file", Constraint(bad, "any"))),
        lambda: attenuate(kit.issue(), ArgCaveat("read_file", Constraint("path", "eq", bad))),
        lambda: attenuate(
            kit.issue(), ArgCaveat("read_file", Constraint("path", "in", ("a", bad)))
        ),
        lambda: encode_caveat(ToolsCaveat((bad,))),
    ):
        with pytest.raises(ChainError, match="surrogate"):
            build()


def test_a_surrogate_pair_and_its_character_no_longer_share_an_encoding(kit: Kit) -> None:
    """Before the fix both of these were accepted and signed as the same bytes,
    so the object in hand (two code points) was not what the bytes said."""
    astral = attenuate(kit.issue(), ToolsCaveat((ASTRAL,)))
    assert kit.verify(astral.serialize()).caveats == (ToolsCaveat((ASTRAL,)),)
    assert encode_caveat(ToolsCaveat((ASTRAL,))) == b'{"tools":["\\ud83d\\ude00"],"type":"tools"}'
    with pytest.raises(ChainError, match="surrogate"):
        attenuate(kit.issue(), ToolsCaveat((PAIR,)))
    # The escaped pair in signed bytes is the astral character, never the pair.
    decoded = decode_caveat(b'{"tools":["\\ud83d\\ude00"],"type":"tools"}')
    assert decoded.tools == (ASTRAL,) and len(decoded.tools[0]) == 1


@pytest.mark.parametrize("escape", ["\\ud83d", "\\ude00", "\\ude00\\ud83d", "x\\udfffy"])
def test_lone_surrogates_are_refused_when_parsing(kit: Kit, escape: str) -> None:
    with pytest.raises(ChainError, match="surrogate"):
        decode_caveat(f'{{"tools":["{escape}"],"type":"tools"}}'.encode())
    root = f'{{"grant":{{"capabilities":[],"expires_at":1}},"id":"{escape}"}}'.encode()
    if kit.name == "hmac":
        text = ".".join(["tgm1", _segment(root), _segment(bytes(32))])
    else:
        next_key = _segment(KEY_SAMPLE.next_keys[0])
        block = b'{"body":' + root + b',"i":0,"next":"' + next_key.encode() + b'"}'
        text = ".".join(["tgk1", _segment(block), _segment(bytes(64)), "k", _segment(bytes(32))])
    with pytest.raises(ChainError, match="surrogate"):
        kit.parse(text)
    assert not kit.authorize(text, READ_Q3).allowed


def test_issue_and_attenuate_only_hand_out_tokens_that_round_trip(kit: Kit) -> None:
    """parse(serialize(token)) == token is checked before a token is returned.

    The objects below serialize without complaint but come back different (a
    list where the parsed form has a tuple), so the caller would hold an
    object that is not what was signed.
    """
    caveat = ToolsCaveat(("read_file",))
    object.__setattr__(caveat, "tools", ["read_file"])
    assert encode_caveat(caveat) == encode_caveat(ONLY_READ) and caveat != ONLY_READ
    with pytest.raises(ChainError, match="does not survive serialization"):
        attenuate(kit.issue(), caveat)
    grant = _grant_with()
    object.__setattr__(grant, "capabilities", list(grant.capabilities))
    with pytest.raises(ChainError, match="does not survive serialization"):
        kit.issue("t", grant)
    # Ordinary tokens are unaffected and equal to their parsed form.
    token = chain(kit.issue(), ONLY_ANA, SOON)
    assert kit.parse(token.serialize()) == token


# --- 3. authorize never raises ----------------------------------------------


def test_authorize_never_raises_on_objects_bent_out_of_shape(kit: Kit) -> None:
    """object.__setattr__ can put anything anywhere. These used to escape as
    TypeError from a function documented as never raising; now they are denies."""
    broken_grant = chain(kit.issue("t", _grant_with()), ONLY_READ)
    object.__setattr__(broken_grant.grant, "capabilities", None)
    with pytest.raises(TypeError):  # verify may raise; authorize may not
        kit.verify(broken_grant)
    decisions = [kit.authorize(broken_grant, READ_Q3)]
    if kit.name == "ed25519":
        decisions.append(authorize_public(broken_grant, kit.authority.public_key, READ_Q3, NOW))
    for decision in decisions:
        assert type(decision) is Decision and not decision.allowed
        assert decision.reason == "invalid token: unexpected TypeError"

    broken_call = Call("read_file", {"path": "reports/q3/a.txt"})
    object.__setattr__(broken_call, "args", None)
    decision = kit.authorize(kit.issue(), broken_call)
    assert type(decision) is Decision and not decision.allowed
    # A ChainError is still reported as before.
    assert kit.authorize("junk", READ_Q3).reason.startswith("invalid token: not a tg")


# --- 4. size limit at the point of narrowing ----------------------------------


def test_attenuate_fails_itself_when_the_result_would_be_too_long(kit: Kit) -> None:
    huge = ToolsCaveat(tuple(f"tool-{i:06d}" for i in range(4000)))
    token = kit.issue()
    with pytest.raises(ChainError, match="too long"):
        attenuate(token, huge)  # no .serialize(): the narrowing itself must fail
    # Whatever attenuate does return can always be serialized and verified.
    big = ToolsCaveat(("read_file", *(f"tool-{i:06d}" for i in range(700))))
    for _ in range(MAX_CAVEATS):
        try:
            token = attenuate(token, big)
        except ChainError as exc:
            assert "too long" in str(exc)
            break
        assert len(token.serialize()) <= MAX_TOKEN_CHARS
    else:
        pytest.fail("the size limit was never reached")
    assert token.caveats and kit.authorize(token, READ_Q3).allowed


# --- 5. every caveat type can only deny or abstain ---------------------------


def caveat_classes() -> list[type]:
    """Every class defined in the chain module that has a `check` method.

    Found by inspection, not listed, so a caveat type added later is covered
    by the property below without anyone remembering to add it.
    """
    return [
        obj
        for _, obj in inspect.getmembers(chain_module, inspect.isclass)
        if obj.__module__ == chain_module.__name__ and callable(getattr(obj, "check", None))
    ]


ODD_CLOCKS = (float("nan"), float("inf"), float("-inf"), None, "0", True, -1, 10**12)
_CAVEAT_STRATEGIES: dict[type, st.SearchStrategy[Any]] = {
    ToolsCaveat: st.lists(st.sampled_from(TOOLS), unique=True).map(lambda t: ToolsCaveat(tuple(t))),
    ArgCaveat: st.builds(ArgCaveat, st.sampled_from(TOOLS), constraints()),
    ExpiryCaveat: st.sampled_from((*EXPIRIES, 0, -5, 1e12)).map(ExpiryCaveat),
}


def caveats_of(kind: type) -> st.SearchStrategy[Any]:
    """Instances of one caveat class. A class this file has never heard of is
    built from its type hints, so it is still exercised."""
    known = _CAVEAT_STRATEGIES.get(kind)
    return st.builds(kind) if known is None else known


def test_caveat_discovery_finds_every_caveat_type() -> None:
    found = caveat_classes()
    assert set(found) == set(get_args(chain_module.Caveat))
    assert {ToolsCaveat, ArgCaveat, ExpiryCaveat} <= set(found)


@pytest.mark.parametrize("kind", caveat_classes(), ids=lambda k: k.__name__)
@settings(max_examples=EXAMPLES, deadline=None)
@given(data=st.data())
def test_a_caveat_check_can_only_deny_or_abstain(kind: type, data: st.DataObject) -> None:
    """Monotonicity, pinned per caveat type.

    check returns None (no objection) or a non-empty reason string (deny).
    Nothing it returns is ever read as "allow": with the caveat attached, the
    decision is the base grant's own when the caveat abstains and a deny when
    it objects. So a call the base grant denies stays denied.
    """
    grant = data.draw(grants())
    call = data.draw(calls_for(grant))
    now = data.draw(st.one_of(times(grant), times(grant), st.sampled_from(ODD_CLOCKS)))
    caveat = data.draw(caveats_of(kind))
    assert type(caveat) is kind

    verdict = caveat.check(call, now)
    assert verdict is None or (type(verdict) is str and verdict)

    base = chain_module._decide(grant, (), call, now)
    narrowed = chain_module._decide(grant, (caveat,), call, now)
    assert base.allowed == grant.allows(call, now)
    if verdict is None:
        assert narrowed == base
    else:
        assert not narrowed.allowed
    assert base.allowed or not narrowed.allowed
    assert Verified("t", grant, (caveat,)).decide(call, now) == narrowed


def test_the_deny_or_abstain_property_sees_both_outcomes() -> None:
    """Each caveat type must be able to abstain on an allowed call and to deny one."""
    for kind in caveat_classes():
        for want_deny in (False, True):

            def hit(case: tuple, want_deny: bool = want_deny) -> bool:
                grant, call, now, caveat = case
                return grant.allows(call, now) and (
                    (caveat.check(call, now) is not None) == want_deny
                )

            find(
                grants().flatmap(
                    lambda g, kind=kind: st.tuples(
                        st.just(g), calls_for(g), times(g), caveats_of(kind)
                    )
                ),
                hit,
            )


# --- 6. domain separation of root and caveat blocks --------------------------


def test_root_and_caveat_blocks_are_signed_under_different_tags() -> None:
    """Block 0 and the caveat blocks no longer rely on the index inside the
    block alone: a signature made for one role is not accepted in the other."""
    tags = (
        chain_module._TAG_KEY_ROOT,
        chain_module._TAG_KEY_CAVEAT,
        chain_module._TAG_KEY_SEAL,
        chain_module._TAG_HMAC_ROOT,
        chain_module._TAG_HMAC_CAVEAT,
    )
    for a, b in combinations(tags, 2):
        assert a != b and not a.startswith(b) and not b.startswith(a)

    authority = KeyAuthority(ROOT_KEY)
    root_key = Ed25519PrivateKey.from_private_bytes(ROOT_KEY)
    issued = authority.issue("t", GRANT)
    block_0 = chain_module._block_bytes(0, chain_module._root_obj("t", GRANT), issued.next_keys[0])
    # The same block 0, signed by the real root key but under the caveat tag.
    wrong_role = replace(
        issued, signatures=(root_key.sign(chain_module._TAG_KEY_CAVEAT + block_0),)
    )
    with pytest.raises(ChainError, match="block 0: bad signature"):
        authority.verify(wrong_role)
    right_role = replace(issued, signatures=(root_key.sign(chain_module._TAG_KEY_ROOT + block_0),))
    assert authority.verify(right_role).identifier == "t"

    # A caveat block signed by the right key but under the root tag.
    child = attenuate(issued, ONLY_READ)
    holder_key = Ed25519PrivateKey.from_private_bytes(issued.proof)
    block_1 = chain_module._block_bytes(1, chain_module._caveat_obj(ONLY_READ), child.next_keys[1])
    wrong_role = replace(
        child,
        signatures=(child.signatures[0], holder_key.sign(chain_module._TAG_KEY_ROOT + block_1)),
    )
    with pytest.raises(ChainError, match="block 1: bad signature"):
        authority.verify(wrong_role)
    assert authority.verify(child).caveats == (ONLY_READ,)


def test_hmac_token_bytes_are_pinned() -> None:
    """Known answer for construction 1 (fixed key, fixed grant). The Ed25519
    tags changed in the security review; these bytes must not."""
    token = chain(HmacAuthority(ROOT_KEY).issue("tok-1", GRANT), ONLY_ANA, ONLY_READ, ONLY_Q3, SOON)
    digest = hashlib.sha256(token.serialize().encode()).hexdigest()
    assert digest == "6fa38bb5e9cad98d73dc7ab2b2c9538c6b038da6bb882ffada10b6f3d95898d0"


# --- 7. a documented limit, shown --------------------------------------------


def test_a_long_hmac_root_key_is_equivalent_to_its_sha256_digest() -> None:
    """Why a SHA-256 fingerprint of the root key must never be published:
    HMAC-SHA256 hashes any key longer than 64 bytes first, so the digest IS a
    working root key."""
    long_key = bytes(range(65))
    digest = hashlib.sha256(long_key).digest()
    token = attenuate(HmacAuthority(long_key).issue("t", GRANT), ONLY_READ)
    assert HmacAuthority(digest).verify(token).caveats == (ONLY_READ,)
    assert HmacAuthority(digest).issue("t", GRANT) == HmacAuthority(long_key).issue("t", GRANT)
    exactly_64 = bytes(range(64))
    with pytest.raises(ChainError):
        HmacAuthority(hashlib.sha256(exactly_64).digest()).verify(
            HmacAuthority(exactly_64).issue("t", GRANT)
        )
