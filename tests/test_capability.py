"""Capabilities and grants: fail-closed decisions and (de)serialization."""

import json

import pytest

from caveat.capability import (
    DECISION_CODES,
    MAX_ARG_NODES,
    MAX_ARGS_PER_LEVEL,
    MAX_INT_BITS,
    MAX_NAME_LENGTH,
    Call,
    Capability,
    Decision,
    Grant,
)
from caveat.constraints import Constraint

NAN = float("nan")
INF = float("inf")


def send_email_cap():
    return Capability(
        "send_email",
        (
            Constraint("to", "in", ["a@x.com", "b@x.com"]),
            Constraint("subject", "any"),
            Constraint("size", "max", 100),
        ),
    )


def ok_args(**overrides):
    args = {"to": "a@x.com", "subject": "hi", "size": 10}
    args.update(overrides)
    return args


# --- Capability construction ------------------------------------------------


@pytest.mark.parametrize("tool", ["", None, 1, ["t"]])
def test_capability_rejects_bad_tool_name(tool):
    with pytest.raises(ValueError):
        Capability(tool)


@pytest.mark.parametrize("max_calls", [0, -1, 1.0, 2.5, True, False, "3", [1]])
def test_capability_rejects_bad_max_calls(max_calls):
    with pytest.raises(ValueError):
        Capability("t", (), max_calls)


@pytest.mark.parametrize("max_calls", [None, 1, 1000])
def test_capability_accepts_max_calls(max_calls):
    assert Capability("t", (), max_calls).max_calls == max_calls


def test_capability_rejects_non_constraint_objects():
    with pytest.raises(ValueError):
        Capability("t", ({"x": {"eq": 1}},))
    with pytest.raises(ValueError):
        Capability("t", (("x", "eq", 1),))


def test_capability_normalizes_constraints_to_tuple_and_arg_names():
    cap = Capability("t", [Constraint("x", "eq", 1), Constraint("y", "any")])
    assert isinstance(cap.constraints, tuple)
    assert cap.arg_names == frozenset({"x", "y"})
    assert Capability("t").arg_names == frozenset()


# --- Capability.decide ------------------------------------------------------


def test_decide_allows_matching_call():
    d = send_email_cap().decide(Call("send_email", ok_args()))
    assert d == Decision(True, "ok")
    assert bool(d) is True
    assert d.capability is None  # the index is only set by Grant.decide


def test_decide_wrong_tool():
    d = send_email_cap().decide(Call("delete_email", ok_args()))
    assert not d
    assert d.allowed is False
    assert d.reason == "tool 'delete_email' is not 'send_email'"


@pytest.mark.parametrize("tool", ["Send_Email", "send_email ", "send_emai", "send_email\x00"])
def test_decide_tool_name_is_exact(tool):
    assert not send_email_cap().permits(Call(tool, ok_args()))


@pytest.mark.parametrize("missing", ["to", "subject", "size"])
def test_decide_missing_argument(missing):
    args = ok_args()
    del args[missing]
    d = send_email_cap().decide(Call("send_email", args))
    assert not d
    assert d.reason == f"argument {missing!r} is missing"


def test_decide_any_still_requires_the_argument_to_be_present():
    cap = Capability("t", (Constraint("x", "any"),))
    assert not cap.permits(Call("t", {}))
    assert not cap.permits(Call("t"))


def test_decide_extra_argument_is_denied():
    d = send_email_cap().decide(Call("send_email", ok_args(bcc="evil@y.com")))
    assert not d
    assert d.reason == "argument 'bcc' is not permitted"


def test_decide_extra_argument_reports_first_in_sorted_order():
    d = send_email_cap().decide(Call("send_email", ok_args(zz=1, bcc=2, cc=3)))
    assert d.reason == "argument 'bcc' is not permitted"


def test_decide_extra_argument_denied_even_when_value_is_none():
    assert not send_email_cap().permits(Call("send_email", ok_args(bcc=None)))


def test_call_with_non_string_argument_name_cannot_be_built():
    with pytest.raises(ValueError):
        Call("t", {"x": 1, 1: 2})


def test_decide_any_admits_an_argument_with_any_value():
    cap = send_email_cap()
    for subject in ["hi", "", 0, None, True, ["a"], {"k": "v"}]:
        assert cap.permits(Call("send_email", ok_args(subject=subject)))


def test_any_cannot_admit_a_non_finite_float_because_no_such_call_exists():
    for subject in [NAN, INF, -INF]:
        with pytest.raises(ValueError):
            Call("send_email", ok_args(subject=subject))


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"to": "c@x.com"}, "argument 'to' fails in"),
        ({"to": ["a@x.com"]}, "argument 'to' fails in"),
        ({"to": None}, "argument 'to' fails in"),
        ({"size": 101}, "argument 'size' fails max"),
        ({"size": "10"}, "argument 'size' fails max"),
        ({"size": True}, "argument 'size' fails max"),
        ({"size": 1e308}, "argument 'size' fails max"),
        ({"size": None}, "argument 'size' fails max"),
    ],
)
def test_decide_failing_constraint(overrides, reason):
    d = send_email_cap().decide(Call("send_email", ok_args(**overrides)))
    assert not d
    assert d.reason == reason


def test_decide_strict_equality():
    cap = Capability("t", (Constraint("n", "eq", 1),))
    assert cap.permits(Call("t", {"n": 1}))
    assert cap.permits(Call("t", {"n": 1.0}))
    assert not cap.permits(Call("t", {"n": True}))
    assert not cap.permits(Call("t", {"n": "1"}))
    d = cap.decide(Call("t", {"n": True}))
    assert d.reason == "argument 'n' fails eq"


def test_decide_reports_first_failing_constraint_in_declaration_order():
    cap = Capability("t", (Constraint("a", "eq", 1), Constraint("b", "eq", 2)))
    assert cap.decide(Call("t", {"a": 9, "b": 9})).reason == "argument 'a' fails eq"
    assert cap.decide(Call("t", {"a": 1, "b": 9})).reason == "argument 'b' fails eq"


def test_decide_all_constraints_on_one_argument_must_hold():
    cap = Capability("t", (Constraint("p", "glob", "reports/*"), Constraint("p", "glob", "*.csv")))
    assert cap.permits(Call("t", {"p": "reports/q3.csv"}))
    assert not cap.permits(Call("t", {"p": "reports/q3.txt"}))
    assert not cap.permits(Call("t", {"p": "other/q3.csv"}))


def test_capability_without_constraints_permits_only_a_call_without_arguments():
    cap = Capability("ping")
    assert cap.permits(Call("ping"))
    assert cap.permits(Call("ping", {}))
    d = cap.decide(Call("ping", {"host": "x"}))
    assert not d
    assert d.reason == "argument 'host' is not permitted"


@pytest.mark.parametrize("args", [None, ["a@x.com"], "to=a@x.com", 5, [("to", "a@x.com")]])
def test_call_with_non_mapping_args_cannot_be_built(args):
    # The gateway treats this ValueError as deny: no Call, no decision to allow.
    with pytest.raises(ValueError):
        Call("send_email", args)


@pytest.mark.parametrize("tool", ["", None, 5, ["send_email"]])
def test_call_with_bad_tool_name_cannot_be_built(tool):
    with pytest.raises(ValueError):
        Call(tool, {})


class _Str(str):
    pass


class _Dict(dict):
    pass


@pytest.mark.parametrize(
    "args",
    [
        {"x": {1, 2}},
        {"x": b"bytes"},
        {"x": object()},
        {"x": 1j},
        {"x": _Str("a")},  # subclasses of builtins are refused
        {"x": _Dict()},
        {"x": [1, {"k": _Str("a")}]},
        {_Str("x"): 1},
        {"x": {"nested": {2: "non-string key"}}},
    ],
)
def test_call_rejects_arguments_that_are_not_plain_json(args):
    with pytest.raises(ValueError):
        Call("t", args)


def test_call_rejects_dict_subclass_and_str_subclass_tool():
    with pytest.raises(ValueError):
        Call("t", _Dict(x=1))
    with pytest.raises(ValueError):
        Call(_Str("t"), {})


def test_call_rejects_arguments_nested_too_deeply():
    deep = "leaf"
    for _ in range(40):
        deep = [deep]
    with pytest.raises(ValueError):
        Call("t", {"x": deep})


# --- every Call that can be built can be recorded ---------------------------
# The audit log writes canonical JSON (ASCII, no NaN). A Call it could not
# write would be an attempt with no record, so Call refuses such data itself.

SURROGATES = ["\ud800", "\udbff", "\udc00", "\udfff", "a\ud83db", "\ud83d\ude00"]
INT_LIMIT = 2**MAX_INT_BITS


def recordable(call):
    """Can the audit log's encoding (canonical JSON, then UTF-8) carry this call?"""
    plain = json.loads(json.dumps({"tool": call.tool, "args": _thaw(call.args)}, allow_nan=False))
    json.dumps(plain, ensure_ascii=False).encode("utf-8")
    return True


def _thaw(value):
    if isinstance(value, tuple):
        return [_thaw(v) for v in value]
    if hasattr(value, "items"):
        return {k: _thaw(v) for k, v in value.items()}
    return value


def test_limits_are_the_documented_ones():
    assert (MAX_INT_BITS, MAX_NAME_LENGTH, MAX_ARGS_PER_LEVEL, MAX_ARG_NODES) == (
        4096,
        256,
        256,
        10_000,
    )
    # the integer bound must stay below Python's default 4300-digit str limit
    assert len(str(INT_LIMIT)) < 4300


@pytest.mark.parametrize("bad", [NAN, INF, -INF])
@pytest.mark.parametrize(
    "wrap",
    [
        lambda v: {"x": v},
        lambda v: {"x": [1, v]},
        lambda v: {"x": {"k": v}},
        lambda v: {"x": [{"k": [[v]]}]},
        lambda v: {"a": 1, "b": "s", "c": (v,)},
    ],
)
def test_call_rejects_non_finite_floats_at_any_depth(bad, wrap):
    with pytest.raises(ValueError):
        Call("t", wrap(bad))


@pytest.mark.parametrize("x", [0.0, -0.0, 1e308, -1e308, 5e-324, 2.5])
def test_call_accepts_finite_floats(x):
    assert recordable(Call("t", {"x": x, "nested": [x, {"k": x}]}))


@pytest.mark.parametrize("bad", SURROGATES)
def test_call_rejects_surrogates_in_every_string_position(bad):
    for build in (
        lambda: Call(bad, {}),
        lambda: Call("t" + bad, {}),
        lambda: Call("t", {bad: 1}),
        lambda: Call("t", {"x": bad}),
        lambda: Call("t", {"x": ["ok", bad]}),
        lambda: Call("t", {"x": {"k": bad}}),
        lambda: Call("t", {"x": {bad: 1}}),
        lambda: Call("t", {"x": [{"k": [{bad: None}]}]}),
    ):
        with pytest.raises(ValueError):
            build()


@pytest.mark.parametrize(
    "text", ["", "\x00", "é", "中", "\ud7ff", "\ue000", "\U0001f600", "\U0010ffff"]
)
def test_call_accepts_every_other_code_point(text):
    assert recordable(Call("t" + text, {"k" + text: text, "n": [text, {text: text}]}))


@pytest.mark.parametrize(
    "n",
    [INT_LIMIT, -INT_LIMIT, INT_LIMIT + 1, 2**5000, -(10**4300)],
    ids=["limit", "minus_limit", "limit_plus_1", "2_pow_5000", "minus_10_pow_4300"],
)
def test_call_rejects_integers_at_or_above_the_bound(n):
    for args in ({"x": n}, {"x": [n]}, {"x": {"k": n}}):
        with pytest.raises(ValueError):
            Call("t", args)


@pytest.mark.parametrize("n", [INT_LIMIT - 1, -(INT_LIMIT - 1), 10**400, -(2**63), 0])
def test_call_accepts_integers_below_the_bound(n):
    call = Call("t", {"x": n, "nested": [n]})
    assert call.args["x"] == n
    assert recordable(call)


def test_call_name_length_limit():
    longest = "n" * MAX_NAME_LENGTH
    call = Call(longest, {longest: {longest: 1}})
    assert recordable(call)
    too_long = longest + "n"
    for build in (
        lambda: Call(too_long, {}),
        lambda: Call("t", {too_long: 1}),
        lambda: Call("t", {"x": {too_long: 1}}),
        lambda: Call("t", {"x": [[{too_long: 1}]]}),
    ):
        with pytest.raises(ValueError):
            build()
    # the limit is on names: a long string VALUE is still plain data
    assert Call("t", {"x": too_long * 10}).args["x"] == too_long * 10


def test_call_argument_count_limit_per_level():
    full = {f"a{i}": i for i in range(MAX_ARGS_PER_LEVEL)}
    assert len(Call("t", full).args) == MAX_ARGS_PER_LEVEL
    assert len(Call("t", {"x": dict(full)}).args["x"]) == MAX_ARGS_PER_LEVEL
    over = dict(full, one_more=1)
    for args in (over, {"x": over}, {"x": [over]}):
        with pytest.raises(ValueError):
            Call("t", args)
    # the limit is on named arguments: a longer LIST is bounded by the node limit
    assert len(Call("t", {"x": list(range(1000))}).args["x"]) == 1000


def test_call_total_node_limit():
    # Nodes: the arguments object (1), the list (1) and its items.
    at_limit = {"x": [0] * (MAX_ARG_NODES - 2)}
    assert len(Call("t", at_limit).args["x"]) == MAX_ARG_NODES - 2
    with pytest.raises(ValueError):
        Call("t", {"x": [0] * (MAX_ARG_NODES - 1)})
    # Containers count too, and the total is across all levels and branches.
    with pytest.raises(ValueError):
        Call("t", {"x": [[]] * MAX_ARG_NODES})
    wide = {f"a{i}": [[0] * 9] * 9 for i in range(200)}  # 1 + 200 * (1 + 9 * 10) nodes
    with pytest.raises(ValueError):
        Call("t", wide)
    assert Call("t", {k: wide[k] for k in list(wide)[:100]})


def test_call_node_limit_stops_a_shared_sublist_from_expanding():
    # 14 levels of [x, x] is 2**14 leaves when copied, built from 15 objects.
    bomb = 0
    for _ in range(14):
        bomb = [bomb, bomb]
    with pytest.raises(ValueError):
        Call("t", {"x": bomb})


def test_every_refusal_is_a_value_error():
    # ValueError, never another exception type: the gateway maps ValueError to deny.
    for args in ({"x": NAN}, {"x": "\ud800"}, {"x": INT_LIMIT}, {"n" * 257: 1}):
        with pytest.raises(ValueError):
            Call("t", args)


# --- constraint literals a Call cannot carry never match ---------------------
# Constraint values are not limited like Call values. That opens no escalation
# path: a literal no Call can carry is a literal no Call can equal.


def _probe_calls():
    values = ["", "a", "*", "a*", "\ud7ff", "\ue000", "\U0001f600", "x" * 300]
    values += [0, 1, -1, INT_LIMIT - 1, -(INT_LIMIT - 1), 1e308, -1e308, 2.0**1023, True, False]
    values += [None, ["a"], {"k": "v"}]
    return [Call("t", {"x": v}) for v in values]


@pytest.mark.parametrize("literal", SURROGATES)
def test_constraint_with_a_surrogate_literal_matches_no_constructible_call(literal):
    caps = [
        Capability("t", (Constraint("x", "eq", literal),)),
        Capability("t", (Constraint("x", "in", [literal, literal + literal]),)),
        Capability("t", (Constraint("x", "glob", literal),)),
        # a starred pattern still requires its literal part, surrogate included
        Capability("t", (Constraint("x", "glob", literal + "*"),)),
        Capability("t", (Constraint("x", "glob", "*" + literal + "*"),)),
        Capability("t", (Constraint("x", "glob", "a*" + literal),)),
    ]
    for cap in caps:
        for call in _probe_calls():
            assert not cap.permits(call), (cap, call)
        # the only values that would match cannot be put in a Call at all
        for text in (literal, literal + literal, literal + "z", "a" + literal, "ab" + literal):
            with pytest.raises(ValueError):
                Call("t", {"x": text})
    # a surrogate in the constraint's argument NAME: no call can name that argument
    named = Capability("t", (Constraint(literal, "any"),))
    assert not named.permits(Call("t", {}))
    with pytest.raises(ValueError):
        Call("t", {literal: 1})
    # and a capability for a tool with a surrogate name can never be called
    with pytest.raises(ValueError):
        Call("t" + literal, {})


@pytest.mark.parametrize(
    "literal",
    [INT_LIMIT, -INT_LIMIT, 2**5000, -(2**5000)],
    ids=["limit", "minus_limit", "2_pow_5000", "minus_2_pow_5000"],
)
def test_constraint_with_a_huge_int_literal_matches_no_constructible_call(literal):
    caps = [
        Capability("t", (Constraint("x", "eq", literal),)),
        Capability("t", (Constraint("x", "in", [literal, literal * 2]),)),
    ]
    for cap in caps:
        for call in _probe_calls():
            assert not cap.permits(call), (cap, call)
        with pytest.raises(ValueError):
            Call("t", {"x": literal})
    # No finite float equals it either: the largest float is below 2**1024.
    assert 1.7976931348623157e308 < 2**1024 < INT_LIMIT


def test_huge_max_ceiling_is_only_a_ceiling():
    # `max` with a huge ceiling admits every number a Call can carry and nothing
    # else. That is what the grant says, not a way around it.
    cap = Capability("t", (Constraint("x", "max", 2**5000),))
    assert cap.permits(Call("t", {"x": INT_LIMIT - 1}))
    assert not cap.permits(Call("t", {"x": "a"}))
    low = Capability("t", (Constraint("x", "max", -(2**5000)),))
    for call in _probe_calls():
        assert not low.permits(call)


def test_call_takes_a_private_read_only_copy_of_its_arguments():
    inner = {"k": [1, 2]}
    args = {"x": "a", "nested": inner}
    call = Call("t", args)
    args["x"] = "changed"
    args["bcc"] = "evil"
    inner["k"].append(3)
    assert dict(call.args) == {"x": "a", "nested": {"k": (1, 2)}}
    with pytest.raises(TypeError):
        call.args["x"] = "b"
    with pytest.raises(TypeError):
        call.args["nested"]["k"] = ()


def test_call_default_args_is_empty():
    assert dict(Call("ping").args) == {}


@pytest.mark.parametrize("not_a_call", [None, {"tool": "ping", "args": {}}, ("ping", {}), "ping"])
def test_decide_refuses_anything_that_is_not_a_call(not_a_call):
    d = Capability("ping").decide(not_a_call)
    assert d == Decision(False, "not a Call")
    assert not Capability("ping").permits(not_a_call)
    assert Grant((Capability("ping"),), 1000).decide(not_a_call, now=0) == Decision(
        False, "not a Call"
    )


def test_decide_refuses_a_call_subclass():
    class LooseCall(Call):
        pass

    assert Capability("ping").decide(LooseCall("ping")) == Decision(False, "not a Call")


def test_decide_ignores_call_budget():
    cap = Capability("ping", (), max_calls=1)
    assert cap.permits(Call("ping"))
    assert cap.permits(Call("ping"))


def test_decision_truthiness_and_default_index():
    assert bool(Decision(True, "ok")) is True
    assert bool(Decision(False, "no")) is False
    assert Decision(False, "no").capability is None


# --- Grant ------------------------------------------------------------------


def two_cap_grant():
    return Grant(
        (
            Capability("read", (Constraint("path", "glob", "reports/*"),)),
            Capability("read", (Constraint("path", "eq", "notes.txt"),)),
            send_email_cap(),
        ),
        expires_at=1000,
    )


@pytest.mark.parametrize("expires_at", [None, "1000", True, False, NAN, INF, -INF, [1]])
def test_grant_rejects_bad_expiry(expires_at):
    with pytest.raises(ValueError):
        Grant((), expires_at)


def test_grant_rejects_non_capability_objects():
    with pytest.raises(ValueError):
        Grant(({"tool": "t"},), 1000)


def test_grant_normalizes_capabilities_to_tuple():
    assert isinstance(Grant([Capability("t")], 1).capabilities, tuple)


def test_grant_decide_returns_index_of_permitting_capability():
    g = two_cap_grant()
    assert g.decide(Call("read", {"path": "reports/q3"}), now=0) == Decision(True, "ok", 0)
    assert g.decide(Call("read", {"path": "notes.txt"}), now=0) == Decision(True, "ok", 1)
    assert g.decide(Call("send_email", ok_args()), now=0) == Decision(True, "ok", 2)


def test_grant_decide_returns_first_permitting_capability():
    g = Grant(
        (
            Capability("read", (Constraint("path", "glob", "*"),)),
            Capability("read", (Constraint("path", "eq", "a"),)),
        ),
        1000,
    )
    assert g.decide(Call("read", {"path": "a"}), 0).capability == 0


def test_grant_unknown_tool():
    d = two_cap_grant().decide(Call("delete", {"path": "reports/q3"}), now=0)
    assert not d
    assert d.reason == "no capability for tool 'delete'"
    assert d.capability is None


def test_grant_with_no_capabilities_denies_everything():
    g = Grant((), 1000)
    d = g.decide(Call("ping"), now=0)
    assert not d
    assert d.reason == "no capability for tool 'ping'"
    assert not g.allows(Call("ping"), now=0)


def test_grant_denial_reason_comes_from_a_capability_for_the_same_tool():
    g = two_cap_grant()
    d = g.decide(Call("read", {"path": "secrets.txt"}), now=0)
    assert not d
    assert d.capability is None
    # the last capability for the tool supplies the reason
    assert d.reason == "argument 'path' fails eq"
    assert g.decide(Call("read", {}), now=0).reason == "argument 'path' is missing"
    d = g.decide(Call("read", {"path": "reports/q3", "mode": "w"}), now=0)
    assert d.reason == "argument 'mode' is not permitted"
    d = g.decide(Call("send_email", ok_args(bcc="x")), now=0)
    assert d.reason == "argument 'bcc' is not permitted"


def test_grant_does_not_combine_arguments_across_capabilities():
    g = Grant(
        (
            Capability("t", (Constraint("a", "eq", 1),)),
            Capability("t", (Constraint("b", "eq", 2),)),
        ),
        1000,
    )
    assert g.allows(Call("t", {"a": 1}), 0)
    assert g.allows(Call("t", {"b": 2}), 0)
    assert not g.allows(Call("t", {"a": 1, "b": 2}), 0)


def test_grant_expiry_boundary():
    g = two_cap_grant()
    call = Call("read", {"path": "reports/q3"})
    assert g.allows(call, now=999)
    assert g.allows(call, now=999.999)
    # now == expires_at is already expired
    d = g.decide(call, now=1000)
    assert d == Decision(False, "grant expired")
    assert not g.allows(call, now=1000.001)
    assert not g.allows(call, now=5000)


def test_grant_expired_wins_over_other_reasons():
    assert two_cap_grant().decide(Call("delete"), now=2000).reason == "grant expired"


@pytest.mark.parametrize("now", [NAN, INF, -INF, None, "0", True, False, [0]])
def test_grant_invalid_now_is_denied(now):
    d = two_cap_grant().decide(Call("read", {"path": "reports/q3"}), now=now)
    assert d == Decision(False, "invalid time")


def test_grant_allows_matches_decide():
    g = two_cap_grant()
    for call in [
        Call("read", {"path": "reports/q3"}),
        Call("read", {"path": "x"}),
        Call("nope"),
        Call("send_email", ok_args()),
    ]:
        assert g.allows(call, 0) is g.decide(call, 0).allowed


# --- from_dict / to_dict ----------------------------------------------------


def test_capability_from_dict():
    cap = Capability.from_dict(
        {
            "tool": "send_email",
            "args": {
                "to": {"in": ["a@x.com", "b@x.com"]},
                "subject": {"any": True},
                "size": {"max": 100},
            },
        }
    )
    assert cap == send_email_cap()


def test_capability_from_dict_defaults():
    cap = Capability.from_dict({"tool": "ping"})
    assert cap == Capability("ping")
    assert cap.max_calls is None
    assert Capability.from_dict({"tool": "ping", "args": {}}) == Capability("ping")


def test_capability_from_dict_several_operators_on_one_argument():
    cap = Capability.from_dict(
        {"tool": "t", "args": {"p": {"glob": "reports/*", "any": True}}, "max_calls": 3}
    )
    assert cap.constraints == (Constraint("p", "glob", "reports/*"), Constraint("p", "any"))
    assert cap.max_calls == 3


@pytest.mark.parametrize(
    "data",
    [
        {"tool": "ping", "args": {}},
        {"tool": "ping", "args": {}, "max_calls": 5},
        {"tool": "t", "args": {"x": {"eq": "a"}}},
        {"tool": "t", "args": {"x": {"eq": True}}},
        {"tool": "t", "args": {"x": {"in": ["a", 1, False]}}},
        {"tool": "t", "args": {"x": {"max": 10.5}}},
        {"tool": "t", "args": {"x": {"glob": "reports/*"}}},
        {"tool": "t", "args": {"x": {"any": True}}},
        {"tool": "t", "args": {"x": {"max": 10, "any": True}, "y": {"eq": "b"}}, "max_calls": 1},
    ],
)
def test_capability_dict_round_trip(data):
    cap = Capability.from_dict(data)
    assert cap.to_dict() == data
    assert Capability.from_dict(cap.to_dict()) == cap


def test_capability_to_dict_omits_absent_max_calls_and_lists_in_values():
    out = Capability("t", (Constraint("x", "in", ("a", "b")),)).to_dict()
    assert out == {"tool": "t", "args": {"x": {"in": ["a", "b"]}}}
    assert isinstance(out["args"]["x"]["in"], list)


def test_capability_to_dict_refuses_two_constraints_with_same_operator_on_one_argument():
    cap = Capability("t", (Constraint("p", "glob", "a*"), Constraint("p", "glob", "*b")))
    with pytest.raises(ValueError):
        cap.to_dict()


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        "send_email",
        {},  # no tool
        {"tool": ""},
        {"tool": None},
        {"tool": 5},
        {"tool": "t", "arguments": {}},  # unknown key
        {"tool": "t", "args": {}, "expires_at": 5},  # unknown key
        {"tool": "t", "constraints": []},  # unknown key
        {"tool": "t", "args": None},
        {"tool": "t", "args": [["x", {"eq": 1}]]},
        {"tool": "t", "args": {"x": {}}},  # no operator
        {"tool": "t", "args": {"x": "a"}},  # bare value instead of operator mapping
        {"tool": "t", "args": {"x": ["eq", 1]}},
        {"tool": "t", "args": {"x": None}},
        {"tool": "t", "args": {"x": {"regex": ".*"}}},  # unknown operator
        {"tool": "t", "args": {"x": {"min": 1}}},
        {"tool": "t", "args": {"x": {"max_calls": 1}}},
        {"tool": "t", "args": {"x": {"eq": 1, "prefix": "a"}}},
        {"tool": "t", "args": {"x": {"any": False}}},
        {"tool": "t", "args": {"x": {"any": None}}},
        {"tool": "t", "args": {"x": {"any": 1}}},
        {"tool": "t", "args": {"x": {"any": "true"}}},
        {"tool": "t", "args": {"x": {"eq": None}}},
        {"tool": "t", "args": {"x": {"eq": [1]}}},
        {"tool": "t", "args": {"x": {"in": []}}},
        {"tool": "t", "args": {"x": {"in": "abc"}}},
        {"tool": "t", "args": {"x": {"in": [None]}}},
        {"tool": "t", "args": {"x": {"max": "10"}}},
        {"tool": "t", "args": {"x": {"max": True}}},
        {"tool": "t", "args": {"x": {"max": NAN}}},
        {"tool": "t", "args": {"x": {"glob": 1}}},
        {"tool": "t", "args": {"": {"eq": 1}}},
        {"tool": "t", "args": {1: {"eq": 1}}},
        {"tool": "t", "max_calls": 0},
        {"tool": "t", "max_calls": -1},
        {"tool": "t", "max_calls": 1.5},
        {"tool": "t", "max_calls": "1"},
        {"tool": "t", "max_calls": True},
    ],
)
def test_capability_from_dict_rejects(data):
    with pytest.raises(ValueError):
        Capability.from_dict(data)


def test_grant_dict_round_trip():
    data = {
        "capabilities": [
            {"tool": "read", "args": {"path": {"glob": "reports/*"}}},
            {
                "tool": "send_email",
                "args": {"to": {"in": ["a@x.com"]}, "subject": {"any": True}},
                "max_calls": 2,
            },
        ],
        "expires_at": 1700000000.5,
    }
    g = Grant.from_dict(data)
    assert g.expires_at == 1700000000.5
    assert g.capabilities[0] == Capability("read", (Constraint("path", "glob", "reports/*"),))
    assert g.capabilities[1].max_calls == 2
    assert g.to_dict() == data
    assert Grant.from_dict(g.to_dict()) == g


def test_grant_round_trip_from_objects():
    g = two_cap_grant()
    assert Grant.from_dict(g.to_dict()) == g


def test_grant_from_dict_empty_capabilities():
    g = Grant.from_dict({"capabilities": [], "expires_at": 10})
    assert g == Grant((), 10)
    assert g.to_dict() == {"capabilities": [], "expires_at": 10}


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        "grant",
        {},
        {"expires_at": 10},  # no capabilities
        {"capabilities": []},  # no expiry
        {"capabilities": [], "expires_at": None},
        {"capabilities": [], "expires_at": "10"},
        {"capabilities": [], "expires_at": True},
        {"capabilities": [], "expires_at": NAN},
        {"capabilities": [], "expires_at": INF},
        {"capabilities": None, "expires_at": 10},
        {"capabilities": {"tool": "t"}, "expires_at": 10},
        {"capabilities": "t", "expires_at": 10},
        {"capabilities": ["t"], "expires_at": 10},
        {"capabilities": [None], "expires_at": 10},
        {"capabilities": [{"tool": "t", "bogus": 1}], "expires_at": 10},
        {"capabilities": [{"tool": "t", "args": {"x": {"regex": "a"}}}], "expires_at": 10},
        {"capabilities": [{"args": {}}], "expires_at": 10},
        {"capabilities": [], "expires_at": 10, "chain": []},  # unknown key
        {"capabilities": [], "expires_at": 10, "not_before": 0},  # unknown key
    ],
)
def test_grant_from_dict_rejects(data):
    with pytest.raises(ValueError):
        Grant.from_dict(data)


# ------------------------------------------------- machine-readable decision codes


def test_decisions_carry_a_code_from_a_closed_set():
    read = Capability.from_dict({"tool": "read", "args": {"path": {"glob": "reports/*"}}})
    grant = Grant((read,), 1000)
    hostile = "password=hunter2 <script>"
    cases = [
        (Call("read", {"path": "reports/a"}), 0, "ok"),
        (Call(hostile, {}), 0, "no_capability"),
        (Call("read", {"path": "reports/a", hostile: 1}), 0, "argument_not_permitted"),
        (Call("read", {}), 0, "argument_missing"),
        (Call("read", {"path": hostile}), 0, "constraint_failed"),
        (Call("read", {"path": "reports/a"}), 1000, "expired"),
        (Call("read", {"path": "reports/a"}), float("nan"), "invalid_time"),
        ("read", 0, "not_a_call"),
    ]
    for call, now, code in cases:
        decision = grant.decide(call, now)
        assert decision.code == code, (call, decision)
        assert decision.code in DECISION_CODES
        assert decision.allowed is (code == "ok")
        assert hostile not in decision.code
    assert read.decide(Call("write", {})).code == "wrong_tool"
    # The reason still tells a person what was wrong, in the caller's own words.
    assert hostile in grant.decide(Call(hostile, {}), 0).reason
    # The code is not part of equality, so a Decision built without one compares as before.
    assert grant.decide(Call("read", {"path": "reports/a"}), 0) == Decision(True, "ok", 0)
    assert Decision(False, "no").code == ""
