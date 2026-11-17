"""Policy engine: loading, matching, precedence and the missing-argument loophole."""

from __future__ import annotations

from itertools import product
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from toolgate.capability import Call
from toolgate.constraints import Constraint
from toolgate.policy import (
    MAX_POLICY_BYTES,
    Policy,
    PolicyDecision,
    PolicyError,
    Rule,
    evaluate,
)

EXAMPLE = Path(__file__).resolve().parent.parent / "config" / "policy.example.yaml"
RANK = {"allow": 0, "approve": 1, "deny": 2}  # higher is more restrictive


def policy(*rules: dict) -> Policy:
    return Policy.from_dict({"version": 1, "rules": list(rules)})


def rule(rule_id: str, effect: str, tools: list[str] | None = None, **extra: object) -> dict:
    return {"id": rule_id, "effect": effect, "tools": tools or ["t"], **extra}


def effect_of(p: Policy, tool: str = "t", **args: object) -> str:
    return p.decide(Call(tool, args)).effect


# ---------------------------------------------------------------- decision order


@pytest.mark.parametrize("effects", [c for n in (1, 2, 3) for c in product(RANK, repeat=n)])
def test_precedence_every_combination_and_order(effects: tuple[str, ...]) -> None:
    p = policy(*(rule(f"r{i}", e) for i, e in enumerate(effects)))
    decision = p.decide(Call("t", {}))
    winner = max(effects, key=RANK.__getitem__)
    assert decision.effect == winner
    assert decision.rule_id == f"r{effects.index(winner)}"  # first of the winning effect


def test_default_deny() -> None:
    assert policy().decide(Call("t", {})) == PolicyDecision(
        "deny", None, "no rule matched (default deny)"
    )
    p = policy(rule("a", "allow", ["other"]))
    assert p.decide(Call("t", {})).rule_id is None
    assert effect_of(p) == "deny"


def test_file_order_tie_break_and_reason() -> None:
    p = policy(
        rule("a1", "allow"),
        rule("d1", "deny", when={"x": {"eq": 1}}, reason="first"),
        rule("d2", "deny", reason="second"),
    )
    assert p.decide(Call("t", {"x": 1})) == PolicyDecision("deny", "d1", "first")
    assert p.decide(Call("t", {"x": 2})) == PolicyDecision("deny", "d2", "second")
    assert policy(rule("a1", "allow")).decide(Call("t", {})).reason == "matched rule 'a1'"


def test_not_a_call_is_denied() -> None:
    p = policy(rule("a", "allow", ["*"]))
    assert p.decide({"tool": "t"}).effect == "deny"  # type: ignore[arg-type]


def test_tool_globs() -> None:
    p = policy(rule("a", "allow", ["send_*", "read"]))
    assert effect_of(p, "send_email") == "allow"
    assert effect_of(p, "send_") == "allow"
    assert effect_of(p, "read") == "allow"
    assert effect_of(p, "reader") == "deny"
    assert effect_of(p, "resend_email") == "deny"
    assert effect_of(policy(rule("a", "allow", ["*"])), "anything") == "allow"


# ------------------------------------------------------------- operators in when


@pytest.mark.parametrize(
    ("ops", "good", "bad"),
    [
        ({"eq": "a"}, "a", "b"),
        ({"eq": 3}, 3.0, 4),
        ({"eq": True}, True, False),
        ({"in": ["a", "b"]}, "b", "c"),
        ({"max": 10}, 10, 11),
        ({"glob": "reports/*"}, "reports/q3", "secrets/x"),
        ({"max": 10, "in": [5, 50]}, 5, 50),  # several operators are a conjunction
    ],
)
def test_each_operator(ops: dict, good: object, bad: object) -> None:
    for effect in RANK:
        p = policy(rule("r", effect, when={"x": ops}))
        assert effect_of(p, x=good) == effect
        assert effect_of(p, x=bad) == "deny"
        assert p.decide(Call("t", {"x": bad})).rule_id is None
        # open world: an argument the rule does not mention is ignored
        assert effect_of(p, x=good, other="whatever") == effect


def test_any_is_a_presence_test_for_every_effect() -> None:
    for effect in RANK:
        p = policy(rule("r", effect, when={"x": {"any": True}}))
        assert p.decide(Call("t", {"x": None})).rule_id == "r"
        assert p.decide(Call("t", {"x": [1]})).rule_id == "r"
        assert p.decide(Call("t", {})).rule_id is None


def test_absent() -> None:
    for effect in RANK:
        p = policy(rule("r", effect, absent=["bcc", "cc"]))
        assert p.decide(Call("t", {"to": "a"})).rule_id == "r"
        assert p.decide(Call("t", {"cc": None})).rule_id is None
        assert p.decide(Call("t", {"bcc": "x", "to": "a"})).rule_id is None


# ------------------------------------------------- the missing-argument loophole

EVIL = {"to": {"glob": "*@evil.com"}}
# NaN and infinity cannot reach the policy: Call refuses them at construction.
ODD_VALUES = [["x@evil.com"], {"addr": "x@evil.com"}, None, 5, True, 1.5]


def loophole_policy(effect: str) -> Policy:
    return policy(rule("allow-send", "allow", ["send"]), rule("guard", effect, ["send"], when=EVIL))


@pytest.mark.parametrize("effect", ["deny", "approve"])
def test_restrictive_rule_is_not_bypassed_by_missing_argument(effect: str) -> None:
    p = loophole_policy(effect)
    assert effect_of(p, "send", to="x@evil.com") == effect
    assert effect_of(p, "send", to="x@good.com") == "allow"  # proven false: rule is off
    assert p.decide(Call("send", {})) == PolicyDecision(effect, "guard", "matched rule 'guard'")
    assert effect_of(p, "send", body="hi") == effect


@pytest.mark.parametrize("effect", ["deny", "approve"])
@pytest.mark.parametrize("value", ODD_VALUES)
def test_restrictive_rule_is_not_bypassed_by_wrong_type(effect: str, value: object) -> None:
    assert effect_of(loophole_policy(effect), "send", to=value) == effect


@pytest.mark.parametrize("value", ODD_VALUES)
def test_allow_rule_never_matches_on_missing_or_wrong_type(value: object) -> None:
    p = policy(rule("a", "allow", when={"to": {"glob": "*"}}))
    assert effect_of(p, to="anyone") == "allow"
    assert effect_of(p) == "deny"
    assert effect_of(p, to=value) == "deny"


@pytest.mark.parametrize(
    ("ops", "value", "expected"),
    [
        ({"eq": True}, "true", "deny"),  # a string where a bool is expected: unknown
        ({"eq": True}, 1, "deny"),
        ({"eq": True}, False, "allow"),  # comparable and different: proven false
        ({"eq": 5}, "5", "deny"),
        ({"eq": 5}, 6, "allow"),
        ({"in": ["a", 1]}, 2, "allow"),
        ({"in": ["a", 1]}, False, "deny"),
        ({"max": 10}, "11", "deny"),
        ({"max": 10}, 11, "allow"),
        ({"max": 10}, [1], "deny"),
        ({"max": 10}, True, "deny"),
    ],
)
def test_wrong_type_is_unknown_for_each_operator(ops: dict, value: object, expected: str) -> None:
    p = policy(rule("a", "allow"), rule("d", "deny", when={"x": ops}))
    assert effect_of(p, x=value) == expected


def test_any_next_to_a_value_operator_means_only_if_present() -> None:
    p = policy(
        rule("a", "allow", ["send"]),
        rule("d", "deny", ["send"], when={"to": {"any": True, "glob": "*@evil.com"}}),
    )
    assert effect_of(p, "send") == "allow"  # the author opted out of the pessimism
    assert effect_of(p, "send", to="x@evil.com") == "deny"
    assert effect_of(p, "send", to=["x@evil.com"]) == "deny"  # still pessimistic on type


def test_one_proven_false_condition_switches_a_deny_rule_off() -> None:
    p = policy(
        rule("a", "allow"),
        rule("d", "deny", when={"to": {"glob": "*@evil.com"}, "attach": {"eq": True}}),
    )
    assert effect_of(p, to="x@good.com") == "allow"
    assert effect_of(p, to="x@evil.com") == "deny"
    assert effect_of(p, attach=False) == "allow"
    assert effect_of(p, attach=True) == "deny"


def test_evaluate_three_values() -> None:
    c = Constraint("x", "max", 3)
    assert evaluate(c, {"x": 3}) is True
    assert evaluate(c, {"x": 4}) is False
    assert evaluate(c, {}) is None
    assert evaluate(c, {"x": "4"}) is None
    assert evaluate(Constraint("x", "any"), {}) is False


# ------------------------------------------------------------------------ unless


def test_unless_on_restrictive_rule_needs_proof() -> None:
    p = policy(
        rule("a", "allow", ["send"]),
        rule("ext", "approve", ["send"], unless={"to": {"glob": "*@example.com"}}),
    )
    assert effect_of(p, "send", to="a@example.com") == "allow"
    assert effect_of(p, "send", to="a@evil.com") == "approve"
    assert effect_of(p, "send") == "approve"
    assert effect_of(p, "send", to=["a@example.com"]) == "approve"


def test_unless_with_several_conditions_needs_all_of_them() -> None:
    p = policy(
        rule("a", "allow"),
        rule("d", "deny", unless={"x": {"eq": 1}, "y": {"eq": 2}}),
    )
    assert effect_of(p, x=1, y=2) == "allow"
    assert effect_of(p, x=1) == "deny"
    assert effect_of(p, x=1, y=3) == "deny"


def test_unless_on_allow_rule_needs_proof_the_exception_is_off() -> None:
    p = policy(rule("a", "allow", unless={"path": {"glob": "secrets/*"}}))
    assert effect_of(p, path="reports/x") == "allow"
    assert effect_of(p, path="secrets/x") == "deny"
    assert effect_of(p) == "deny"
    assert effect_of(p, path=["secrets/x"]) == "deny"


def test_when_and_unless_together() -> None:
    p = policy(
        rule("a", "allow"),
        rule("d", "deny", when={"n": {"max": 5}}, unless={"who": {"eq": "admin"}}),
    )
    assert effect_of(p, n=3, who="admin") == "allow"
    assert effect_of(p, n=3, who="bob") == "deny"
    assert effect_of(p, n=9, who="bob") == "allow"
    assert effect_of(p, who="admin") == "allow"
    assert effect_of(p) == "deny"


# ------------------------------------------------------------ load-time validation

GOOD = """
version: 1
rules:
  - id: r1
    effect: allow
    tools: ["t"]
"""


def test_good_policy_loads() -> None:
    p = Policy.from_yaml(GOOD)
    assert [r.id for r in p.rules] == ["r1"]
    assert Policy.from_yaml("version: 1\nrules: []\n").rules == ()


BAD_YAML = {
    "not a mapping": "- 1\n- 2\n",
    "empty": "",
    "unknown top key": GOOD + "extra: 1\n",
    "missing version": "rules: []\n",
    "wrong version": "version: 2\nrules: []\n",
    "version as float": "version: 1.0\nrules: []\n",
    "version as bool": "version: true\nrules: []\n",
    "version as text": 'version: "1"\nrules: []\n',
    "missing rules": "version: 1\n",
    "rules null": "version: 1\nrules:\n",
    "rules a mapping": "version: 1\nrules: {a: 1}\n",
    "rule not a mapping": "version: 1\nrules: [x]\n",
    "duplicate top key": GOOD + "version: 1\n",
    "two documents": GOOD + "---\n" + GOOD,
    "syntax error": "version: 1\nrules: [\n",
    "python tag": "version: 1\nrules: !!python/object/apply:os.system ['true']\n",
    "too deep": "[" * 5000,
}


@pytest.mark.parametrize("text", BAD_YAML.values(), ids=BAD_YAML.keys())
def test_bad_documents_raise(text: str) -> None:
    with pytest.raises(PolicyError):
        Policy.from_yaml(text)


def one_rule(body: str) -> str:
    return "version: 1\nrules:\n  - " + body.strip().replace("\n", "\n    ") + "\n"


BAD_RULES = {
    "unknown key": "id: r\neffect: allow\ntools: [t]\nwhne: {x: {eq: 1}}",
    "unknown effect": "id: r\neffect: permit\ntools: [t]",
    "effect case": "id: r\neffect: Allow\ntools: [t]",
    "effect list": "id: r\neffect: [allow]\ntools: [t]",
    "missing id": "effect: allow\ntools: [t]",
    "empty id": 'id: ""\neffect: allow\ntools: [t]',
    "numeric id": "id: 7\neffect: allow\ntools: [t]",
    "missing effect": "id: r\ntools: [t]",
    "missing tools": "id: r\neffect: allow",
    "tools a string": "id: r\neffect: allow\ntools: t",
    "tools empty": "id: r\neffect: allow\ntools: []",
    "tools empty string": 'id: r\neffect: allow\ntools: [""]',
    "tools non string": "id: r\neffect: allow\ntools: [3]",
    "tools repeated": "id: r\neffect: allow\ntools: [t, t]",
    "when null": "id: r\neffect: allow\ntools: [t]\nwhen:",
    "when empty": "id: r\neffect: allow\ntools: [t]\nwhen: {}",
    "when a list": "id: r\neffect: allow\ntools: [t]\nwhen: [x]",
    "when arg not mapping": "id: r\neffect: allow\ntools: [t]\nwhen: {x: 1}",
    "when arg empty ops": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {}}",
    "unknown operator": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {regex: a}}",
    "provenance operator not yet": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {source_in: [u]}}",
    "any false": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {any: false}}",
    "max needs number": 'id: r\neffect: allow\ntools: [t]\nwhen: {x: {max: "3"}}',
    "max infinity": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {max: .inf}}",
    "glob needs string": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {glob: 3}}",
    "in needs list": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {in: a}}",
    "in empty": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {in: []}}",
    "eq null": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {eq: null}}",
    "eq date": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {eq: 2026-11-17}}",
    "unless unknown operator": "id: r\neffect: deny\ntools: [t]\nunless: {x: {not: 1}}",
    "unless empty": "id: r\neffect: deny\ntools: [t]\nunless: {}",
    "absent a string": "id: r\neffect: allow\ntools: [t]\nabsent: bcc",
    "absent empty": "id: r\neffect: allow\ntools: [t]\nabsent: []",
    "absent non string": "id: r\neffect: allow\ntools: [t]\nabsent: [1]",
    "absent repeated": "id: r\neffect: allow\ntools: [t]\nabsent: [a, a]",
    "absent and when clash": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {eq: 1}}\nabsent: [x]",
    "reason not text": "id: r\neffect: allow\ntools: [t]\nreason: [a]",
    "duplicate rule key": "id: r\neffect: deny\neffect: allow\ntools: [t]",
    "duplicate operator key": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {max: 1, max: 9}}",
    "duplicate argument key": "id: r\neffect: deny\ntools: [t]\nwhen: {x: {eq: 1}, x: {eq: 2}}",
    "non string key": "id: r\neffect: allow\ntools: [t]\n1: x",
    "null key": "id: r\neffect: allow\ntools: [t]\n~: x",
    "complex key": "id: r\neffect: allow\ntools: [t]\n? [a, b]\n: x",
    "anchor": "id: r\neffect: allow\ntools: &t [t]",
    "merge key": "id: r\neffect: deny\ntools: [t]\n<<: {effect: allow}",
    # the Norway problem and its relatives: refuse, do not reinterpret
    "id no": "id: no\neffect: allow\ntools: [t]",
    "effect on": "id: r\neffect: on\ntools: [t]",
    "tool yes": "id: r\neffect: allow\ntools: [yes]",
    "value NO": "id: r\neffect: deny\ntools: [t]\nwhen: {country: {eq: NO}}",
    "value in list off": "id: r\neffect: deny\ntools: [t]\nwhen: {mode: {in: [off, low]}}",
    "value True": "id: r\neffect: deny\ntools: [t]\nwhen: {x: {eq: True}}",
    "octal": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {max: 010}}",
    "hex": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {max: 0x10}}",
    "sexagesimal": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {max: 1:30}}",
    "underscore": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {max: 1_000}}",
    "plus sign": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {max: +5}}",
    "nan": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {eq: .nan}}",
    "bare dot float": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {max: 1.}}",
    "huge int": "id: r\neffect: allow\ntools: [t]\nwhen: {x: {max: " + "9" * 5000 + "}}",
}


@pytest.mark.parametrize("body", BAD_RULES.values(), ids=BAD_RULES.keys())
def test_bad_rules_raise(body: str) -> None:
    with pytest.raises(PolicyError):
        Policy.from_yaml(one_rule(body))


def test_the_rule_template_itself_is_valid() -> None:
    body = 'id: r\neffect: deny\ntools: [t]\nwhen: {country: {eq: "NO"}, n: {max: -1.5}}'
    p = Policy.from_yaml(one_rule(body))
    assert effect_of(p, country="NO", n=-2) == "deny"
    assert p.rules[0].when[0].value == "NO"


def test_duplicate_rule_ids_raise() -> None:
    with pytest.raises(PolicyError, match="duplicate rule id"):
        policy(rule("same", "allow"), rule("same", "deny"))
    with pytest.raises(PolicyError, match="duplicate rule id"):
        Policy((Rule("a", "allow", ("t",)), Rule("a", "deny", ("t",))))


def test_alias_cannot_smuggle_a_rule() -> None:
    text = "version: 1\nrules:\n  - &r {id: r, effect: allow, tools: [t]}\n  - *r\n"
    with pytest.raises(PolicyError, match="anchors"):
        Policy.from_yaml(text)


def test_oversized_and_non_text_input() -> None:
    with pytest.raises(PolicyError, match="larger"):
        Policy.from_yaml(GOOD + "#" * MAX_POLICY_BYTES)
    with pytest.raises(PolicyError):
        Policy.from_yaml(GOOD.encode())  # type: ignore[arg-type]


def test_error_names_the_line() -> None:
    with pytest.raises(PolicyError, match="line 3.*'no' is ambiguous"):
        Policy.from_yaml("version: 1\nrules:\n  - id: no\n    effect: allow\n    tools: [t]\n")


def test_rule_objects_are_validated_directly() -> None:
    with pytest.raises(PolicyError):
        Rule("r", "maybe", ("t",))
    with pytest.raises(PolicyError):
        Rule("r", "allow", ())
    with pytest.raises(PolicyError):
        Rule("r", "allow", ("t",), when=("x",))  # type: ignore[arg-type]
    with pytest.raises(PolicyError):
        Policy(("not a rule",))  # type: ignore[arg-type]


def test_from_file(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text(GOOD)
    assert Policy.from_file(path).rules[0].id == "r1"
    assert Policy.from_file(str(path)).rules[0].id == "r1"
    with pytest.raises(PolicyError):
        Policy.from_file(tmp_path / "missing.yaml")
    path.write_bytes(b"version: 1\nrules: []\n# \xff\n")
    with pytest.raises(PolicyError):
        Policy.from_file(path)
    path.write_bytes(b"#" * (MAX_POLICY_BYTES + 5))
    with pytest.raises(PolicyError, match="larger"):
        Policy.from_file(path)


# ------------------------------------------------------------------ example file

EXAMPLE_CASES = [
    ("delete_file", {"path": "drafts/a.txt"}, "deny", "deny-file-delete"),
    ("read_file", {"path": "reports/q3.txt"}, "allow", "allow-file-reads"),
    ("read_file", {"path": "secrets/key.pem"}, "deny", "deny-secret-paths"),
    ("read_file", {}, "deny", "deny-secret-paths"),
    ("write_file", {"path": "drafts/note.md", "content": "x"}, "allow", "allow-file-writes"),
    (
        "write_file",
        {"path": "reports/q3.txt", "content": "x"},
        "approve",
        "approve-writes-outside-drafts",
    ),
    ("send_email", {"to": "ana@example.com", "body": "hi"}, "allow", "allow-email-send"),
    ("send_email", {"to": "x@evil.com", "body": "hi"}, "approve", "approve-external-email"),
    ("send_email", {"to": ["ana@example.com"]}, "approve", "approve-external-email"),
    ("send_email", {"body": "hi"}, "approve", "approve-external-email"),
    ("send_email", {"to": "ana@example.com", "bcc": "x@evil.com"}, "deny", "deny-bcc"),
    ("send_sms", {"to": "ana@example.com"}, "deny", None),
    # P5: only the recipient arguments the policy has reasoned about pass on their own
    ("send_email", {"to": "a@example.com", "cc": "evil@x.com"}, "approve", "approve-cc"),
    ("send_email", {"to": "a@example.com", "cc": None}, "approve", "approve-cc"),
    ("send_email", {"to": "x@evil.com", "cc": "a@example.com"}, "approve", "approve-cc"),
    ("send_email", {"to": "a@example.com", "cc": "b@example.com", "bcc": ""}, "deny", "deny-bcc"),
    ("search_email", {"query": "invoice"}, "allow", "allow-email-read"),
    ("list_events", {"days": 7}, "allow", "allow-calendar-read"),
    ("create_event", {"title": "focus", "duration_minutes": 60}, "allow", "allow-personal-events"),
    ("create_event", {"title": "focus", "duration_minutes": 600}, "approve", "approve-long-events"),
    ("create_event", {"title": "focus"}, "approve", "approve-long-events"),
    (
        "create_event",
        {"title": "sync", "duration_minutes": 30, "attendees": ["ben@example.com"]},
        "approve",
        "approve-invites",
    ),
    ("update_event", {"id": "e1", "duration_minutes": 30}, "allow", "allow-event-update"),
    ("delete_event", {"id": "e1"}, "approve", "approve-calendar-delete"),
    ("transfer_money", {"amount": 1}, "deny", None),
]


@pytest.mark.parametrize(("tool", "args", "effect", "rule_id"), EXAMPLE_CASES)
def test_example_policy(tool: str, args: dict, effect: str, rule_id: str | None) -> None:
    decision = Policy.from_file(EXAMPLE).decide(Call(tool, args))
    assert (decision.effect, decision.rule_id) == (effect, rule_id)


def test_example_policy_has_no_em_dash_and_uses_every_effect() -> None:
    p = Policy.from_file(EXAMPLE)
    assert {r.effect for r in p.rules} == set(RANK)
    assert chr(0x2014) not in EXAMPLE.read_text()


# -------------------------------------------------------------------- properties

TOOLS = ("read", "send", "pay")
ARGS = ("x", "y")
VALUES = st.sampled_from(["", "a", "ab", "b/a", 0, 1, 2, 5, True, False, None, 1.5]) | st.lists(
    st.sampled_from(["a", 1]), max_size=2
)
SCALARS = st.sampled_from(["a", "ab", "b/a", 0, 1, 2, 5, True, False])
PATTERNS = st.sampled_from(["*", "a*", "*a", "b/*", "ab", "re*", "s*d", "pay"])


@st.composite
def operator_maps(draw: st.DrawFn) -> dict:
    op = draw(st.sampled_from(["eq", "in", "max", "glob", "any"]))
    if op == "eq":
        return {"eq": draw(SCALARS)}
    if op == "in":
        return {"in": draw(st.lists(SCALARS, min_size=1, max_size=3))}
    if op == "max":
        return {"max": draw(st.sampled_from([0, 1, 2.5]))}
    if op == "glob":
        return {"glob": draw(PATTERNS)}
    return {"any": True}


CONDITIONS = st.dictionaries(st.sampled_from(ARGS), operator_maps(), min_size=1, max_size=2)


@st.composite
def rule_dicts(draw: st.DrawFn, effect: str | None = None) -> dict:
    out: dict = {
        "id": "placeholder",
        "effect": effect or draw(st.sampled_from(sorted(RANK))),
        "tools": draw(
            st.lists(st.sampled_from(TOOLS) | PATTERNS, min_size=1, max_size=2, unique=True)
        ),
    }
    if draw(st.booleans()):
        out["when"] = draw(CONDITIONS)
    if draw(st.booleans()):
        out["unless"] = draw(CONDITIONS)
    if draw(st.integers(0, 3)) == 0:
        free = [a for a in ARGS if a not in out.get("when", {})]
        if free:
            out["absent"] = [draw(st.sampled_from(free))]
    return out


def numbered(rules: list[dict]) -> Policy:
    return policy(*({**r, "id": f"r{i}"} for i, r in enumerate(rules)))


RULE_LISTS = st.lists(rule_dicts(), max_size=6)
CALLS = st.builds(
    Call, st.sampled_from(TOOLS), st.dictionaries(st.sampled_from(ARGS), VALUES, max_size=2)
)


@settings(max_examples=1500, deadline=None)
@given(RULE_LISTS, rule_dicts(effect="deny"), st.integers(0, 6), CALLS)
def test_adding_a_deny_rule_never_permits_more(
    rules: list[dict], extra: dict, position: int, call: Call
) -> None:
    before = numbered(rules).decide(call).effect
    position = min(position, len(rules))
    after = numbered(rules[:position] + [extra] + rules[position:]).decide(call).effect
    assert RANK[after] >= RANK[before]
    if before == "deny":
        assert after == "deny"


@settings(max_examples=1500, deadline=None)
@given(RULE_LISTS, st.integers(0, 5), CALLS)
def test_removing_an_allow_rule_never_permits_more(
    rules: list[dict], index: int, call: Call
) -> None:
    allows = [i for i, r in enumerate(rules) if r["effect"] == "allow"]
    if not allows:
        return
    drop = allows[index % len(allows)]
    before = numbered(rules).decide(call).effect
    after = numbered(rules[:drop] + rules[drop + 1 :]).decide(call).effect
    assert RANK[after] >= RANK[before]


@settings(max_examples=1000, deadline=None)
@given(RULE_LISTS, CALLS, st.randoms(use_true_random=False))
def test_decide_is_deterministic_and_order_only_changes_the_rule_id(
    rules: list[dict], call: Call, rng: object
) -> None:
    p = numbered(rules)
    first = p.decide(call)
    assert p.decide(call) == first
    assert numbered(rules).decide(Call(call.tool, dict(call.args))) == first
    shuffled = list(rules)
    rng.shuffle(shuffled)  # type: ignore[attr-defined]
    assert numbered(shuffled).decide(call).effect == first.effect


@settings(max_examples=1000, deadline=None)
@given(rule_dicts(), CALLS, st.sampled_from(ARGS))
def test_dropping_an_argument_never_escapes_a_restrictive_rule(
    spec: dict, call: Call, name: str
) -> None:
    """A deny or approve rule without `any`, `absent` or `unless` cannot be dodged by omission."""
    if spec["effect"] == "allow" or any("any" in ops for ops in spec.get("when", {}).values()):
        return
    spec = {k: v for k, v in spec.items() if k not in ("absent", "unless")}
    restrictive = Rule.from_dict({**spec, "id": "r"})
    fewer = Call(call.tool, {k: v for k, v in call.args.items() if k != name})
    if restrictive.matches(call):
        assert restrictive.matches(fewer)


# ------------------------------------------------------- security review findings


def test_p1_oversized_file_with_multibyte_text_is_refused_not_truncated(tmp_path: Path) -> None:
    # An allow "*" rule, a long comment of two-byte characters crossing the limit, then a
    # deny rule. Reading MAX + 1 bytes and counting characters dropped the deny rule.
    head = "version: 1\nrules:\n  - {id: a, effect: allow, tools: ['*']}\n#"
    head += " " * ((MAX_POLICY_BYTES + 1 - len(head)) % 2)  # the cut lands between characters
    tail = "\n  - {id: d, effect: deny, tools: [delete_file]}\n"
    path = tmp_path / "big.yaml"
    path.write_bytes((head + "\u00e9" * 600_000 + tail).encode("utf-8"))
    assert path.stat().st_size > MAX_POLICY_BYTES
    with pytest.raises(PolicyError, match="larger"):
        Policy.from_file(path)
    # the same rules in a file under the limit keep the deny
    path.write_bytes((head + "\u00e9" * 10 + tail).encode("utf-8"))
    assert effect_of(Policy.from_file(path), "delete_file") == "deny"


def test_p1_size_limit_counts_bytes_not_characters() -> None:
    text = GOOD + "# " + "\u00e9" * (MAX_POLICY_BYTES // 2)
    assert len(text) < MAX_POLICY_BYTES < len(text.encode())
    with pytest.raises(PolicyError, match="larger"):
        Policy.from_yaml(text)


AMBIGUOUS_NUMBERS = [
    "1e3",
    "1E3",
    "1.5e3",
    "1e-3",
    "1.5e+3",
    "1e+3",
    "-1e3",
    ".5e3",
    "0o17",
    "0O17",
    "08",
    "0.1e-400",
    "9007199254740993.0",
    "0.1000000000000000055",
]


@pytest.mark.parametrize("text", AMBIGUOUS_NUMBERS)
@pytest.mark.parametrize("where", ["when: {x: {eq: %s}}", "when: {x: {in: [a, %s]}}", "id2: %s"])
def test_p2_unquoted_numeric_looking_scalars_are_refused(text: str, where: str) -> None:
    body = "id: r\neffect: deny\ntools: [t]\n" + where % text
    with pytest.raises(PolicyError, match="quote it"):
        Policy.from_yaml(one_rule(body))


def test_p2_quoted_text_and_plain_decimals_still_load() -> None:
    body = "id: r\neffect: allow\ntools: [t]\nwhen: {x: {in: ['1e3', \"0o17\", 1000, 1.5, -0.25]}}"
    p = Policy.from_yaml(one_rule(body))
    for value in ("1e3", "0o17", 1000, 1.5, -0.25):
        assert effect_of(p, x=value) == "allow"
    assert effect_of(p, x=1000.5) == "deny"
    plain = "id: v1.2.3\neffect: allow\ntools: [t]\nwhen: {x: {eq: 3rd}}"
    assert Policy.from_yaml(one_rule(plain)).rules[0].id == "v1.2.3"


@pytest.mark.parametrize(
    "directive", ["%YAML 1.2\n---\n", "%YAML 1.1\n---\n", "%TAG ! tag:example.com,2000:\n---\n"]
)
def test_p2_directives_are_refused(directive: str) -> None:
    with pytest.raises(PolicyError, match="directives"):
        Policy.from_yaml(directive + GOOD)


BAD_TOOL_PATTERNS = [
    " read",
    "read ",
    "read file",
    "read\tfile",
    "read\nfile",
    "a\u00a0b",
    "a\x00b",
]
BAD_TOOL_PATTERNS += ["a\u200bb", "a\x7fb", "a\u2028b"]


@pytest.mark.parametrize("pattern", BAD_TOOL_PATTERNS)
def test_p3_tool_patterns_with_whitespace_or_control_characters_are_refused(pattern: str) -> None:
    with pytest.raises(PolicyError, match="whitespace or a control character"):
        policy(rule("r", "deny", [pattern]))
    with pytest.raises(PolicyError, match="whitespace or a control character"):
        Rule("r", "deny", (pattern,))


def test_p3_multi_line_plain_scalar_under_tools_is_refused() -> None:
    body = "id: r\neffect: deny\ntools:\n  - read_file\n    write_file"
    with pytest.raises(PolicyError, match="list dash is missing"):
        Policy.from_yaml(one_rule(body))
    quoted = 'id: r\neffect: deny\ntools: [" read_file"]'
    with pytest.raises(PolicyError, match="whitespace"):
        Policy.from_yaml(one_rule(quoted))


@pytest.mark.parametrize("effect", sorted(RANK))
def test_p3_absent_and_unless_on_the_same_argument_is_refused(effect: str) -> None:
    body = f"id: r\neffect: {effect}\ntools: [t]\nunless: {{x: {{eq: 1}}}}\nabsent: [x]"
    with pytest.raises(PolicyError, match="both absent and unless"):
        Policy.from_yaml(one_rule(body))
    other = f"id: r\neffect: {effect}\ntools: [t]\nunless: {{x: {{eq: 1}}}}\nabsent: [y]"
    assert Policy.from_yaml(one_rule(other)).rules[0].absent == ("y",)


def test_p4_warnings_for_presence_tests_on_restrictive_rules() -> None:
    p = policy(
        rule("ap", "approve", ["transfer"], absent=["confirmation"]),
        rule("dn", "deny", when={"bcc": {"any": True}}),
        rule("al", "allow", absent=["x"], when={"y": {"any": True}}),
        rule("ok", "deny", when={"to": {"glob": "*@evil.com"}}, unless={"z": {"any": True}}),
    )
    assert isinstance(p.warnings, tuple) and len(p.warnings) == 2
    assert "'ap'" in p.warnings[0] and "absent" in p.warnings[0]
    assert "'confirmation'" in p.warnings[0]
    assert "'dn'" in p.warnings[1] and "any" in p.warnings[1] and "'bcc'" in p.warnings[1]
    # the trap the warning describes: the caller switches the approve rule off
    q = policy(rule("ap", "approve", absent=["confirmation"]), rule("al", "allow"))
    assert effect_of(q, amount=5) == "approve"
    assert effect_of(q, amount=5, confirmation=None) == "allow"


def test_p4_warning_for_exact_deny_next_to_allow_star() -> None:
    p = policy(rule("all", "allow", ["*"]), rule("no-delete", "deny", ["delete_file", "rm_*"]))
    assert len(p.warnings) == 1
    assert "'no-delete'" in p.warnings[0] and "'delete_file'" in p.warnings[0]
    assert "'all'" in p.warnings[0]
    assert effect_of(p, "Delete_File") == "allow"  # the fragility being warned about
    assert policy(rule("all", "allow", ["*"]), rule("d", "deny", ["rm_*"])).warnings == ()
    assert policy(rule("some", "allow", ["read_*"]), rule("d", "deny", ["rm"])).warnings == ()
    assert policy(rule("all", "approve", ["*"]), rule("d", "deny", ["rm"])).warnings == ()


def test_p4_warnings_do_not_change_decisions_or_equality() -> None:
    assert policy().warnings == ()
    assert Policy.from_yaml(GOOD).warnings == ()
    rules = (Rule("d", "deny", ("t",), absent=("x",)),)
    assert Policy(rules) == Policy(rules) and Policy(rules).warnings
    example = Policy.from_file(EXAMPLE)
    assert all(type(w) is str for w in example.warnings)
    assert any("'deny-bcc'" in w for w in example.warnings)
    assert not any("allow-email-send" in w for w in example.warnings)


def test_p5_example_policy_documents_the_two_layers() -> None:
    text = EXAMPLE.read_text()
    assert "closed-world" in text and "canonical" in text
    p = Policy.from_file(EXAMPLE)
    for extra in ("cc", "bcc"):
        for value in ("evil@x.com", None, "", ["evil@x.com"]):
            call = Call("send_email", {"to": "a@example.com", extra: value})
            assert p.decide(call).effect != "allow"
