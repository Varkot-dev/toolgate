"""Capabilities and grants: fail-closed decisions and (de)serialization."""

import pytest

from toolgate.capability import Call, Capability, Decision, Grant
from toolgate.constraints import Constraint

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
    for subject in ["hi", "", 0, None, True, NAN, ["a"], {"k": "v"}]:
        assert cap.permits(Call("send_email", ok_args(subject=subject)))


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"to": "c@x.com"}, "argument 'to' fails in"),
        ({"to": ["a@x.com"]}, "argument 'to' fails in"),
        ({"to": None}, "argument 'to' fails in"),
        ({"size": 101}, "argument 'size' fails max"),
        ({"size": "10"}, "argument 'size' fails max"),
        ({"size": True}, "argument 'size' fails max"),
        ({"size": NAN}, "argument 'size' fails max"),
        ({"size": INF}, "argument 'size' fails max"),
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
