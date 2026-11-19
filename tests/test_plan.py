"""Plan-then-execute: an injection can change an extracted value, never the control flow.

Scripted planner and extractor, not a model. Outcomes are read from
World.effects and the transcript, not from statuses alone.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from caveat.plan import (
    EMAIL,
    PATH,
    TEXT,
    URL,
    Cat,
    ExtractStep,
    Plan,
    PlanError,
    Ref,
    ToolStep,
    UrlEncode,
    check_schema,
    execute,
    validate,
)
from caveat.sandbox.agents import INFLUENCED, LEGIT, SKIPPED, HijackedAgent, HonestAgent, call_key
from caveat.sandbox.plans import ScriptedExtractor, plan_for, plan_tools
from caveat.sandbox.runner import PLAN, PlanSession, configuration, legitimate_calls, run_task
from caveat.sandbox.tasks import all_tasks, attack_tasks, load_grants

TASKS = all_tasks()
ATTACKS = attack_tasks()
PLAN_CAREFUL = configuration("5-plan-execute")
PLAN_RUBBER = configuration("5-plan-execute-rubber-stamp")


def ids(tasks):
    return [t.id for t in tasks]


# -- the restricted format ---------------------------------------------------------


@pytest.mark.parametrize(
    "steps",
    [
        (ToolStep("a", "read_file", {"path": Ref("b")}), ToolStep("b", "read_file", {})),
        (ToolStep("a", Ref("x"), {}),),  # a tool name from data
        (ToolStep("a", "t", {}), ToolStep("a", "t", {})),
        (ToolStep("Bad Name", "t", {}),),
        (ToolStep("a", "t", {"x": {"$ref": "h-1"}}),),  # a raw handle smuggled in
        (ToolStep("a", "t", {"$x": 1}),),
        (ToolStep("a", "t", {"x": object()}),),
        (ExtractStep("e", (), "nothing", TEXT),),
        (ToolStep("a", "t", {}), ExtractStep("e", ("a",), "x", "sql")),
        (ExtractStep("e", ("later",), "x", TEXT), ToolStep("later", "t", {})),
    ],
)
def test_validate_refuses_anything_outside_the_format(steps):
    with pytest.raises(PlanError):
        validate(Plan("request", steps))


def test_a_valid_plan_lists_its_tools_before_anything_runs():
    plan = Plan(
        "r",
        (
            ToolStep("a", "read_file", {"path": "x"}),
            ExtractStep("e", ("a",), "x", TEXT),
            ToolStep("b", "send_email", {"body": Cat(("x", UrlEncode(Ref("e"))))}),
        ),
    )
    validate(plan)
    assert plan.tools() == ("read_file", "send_email")


@pytest.mark.parametrize(
    ("schema", "value"),
    [
        (EMAIL, "Bob@NorthWind.example"),  # not canonical: refused, not lowercased
        (EMAIL, "a@x.example, b@y.example"),
        (URL, "HTTPS://vendor.example/"),
        (URL, "https://vendor.example/../x"),
        (PATH, "reports/../secrets/x"),
        ("date", "next tuesday"),
        ("id", "e4; drop"),
        (TEXT, 42),
        (TEXT, "x" * 70_000),
    ],
)
def test_schema_refuses_and_never_repairs(schema, value):
    with pytest.raises(PlanError):
        check_schema(schema, value)


# -- the planner sees only the request ---------------------------------------------


def _literals(value, out):
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, (Cat,)):
        for p in value.parts:
            _literals(p, out)
    elif isinstance(value, UrlEncode):
        _literals(value.part, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _literals(v, out)
    elif isinstance(value, dict):
        for v in value.values():
            _literals(v, out)
    return out


@pytest.mark.parametrize("task", TASKS, ids=ids(TASKS))
def test_plan_literals_come_from_the_request_or_the_grant(task):
    """Addresses, paths and URLs in a plan are ones the user wrote down."""
    grant_values = json.dumps([c.to_dict() for c in load_grants()[task.id]])
    for step in plan_for(task).plan.steps:
        if not isinstance(step, ToolStep):
            continue
        for literal in _literals(dict(step.args), []):
            if "@" in literal or "/" in literal:
                assert literal in task.request or json.dumps(literal) in grant_values, literal


@pytest.mark.parametrize("task", TASKS, ids=ids(TASKS))
def test_plans_do_not_depend_on_the_world(task):
    """Built from the request alone: identical whatever the world holds or the seed is."""
    assert plan_for(task) == plan_for(task)
    assert plan_tools(task) == tuple(s.tool for s in task.legit)


@pytest.mark.parametrize("task", TASKS, ids=ids(TASKS))
def test_an_honest_plan_makes_exactly_the_honest_agents_calls(task):
    run = run_task(task, HonestAgent(), PLAN_CAREFUL)
    made = {call_key(e.tool, e.args) for e in run.transcript}
    assert made == set(legitimate_calls(task.id, 0))
    assert run.utility and run.approvals_granted == run.approvals_requested


# -- the property: injections change values, not control flow -----------------------


@pytest.mark.parametrize("task", ATTACKS, ids=ids(ATTACKS))
@pytest.mark.parametrize("config", [PLAN_CAREFUL, PLAN_RUBBER], ids=lambda c: c.key)
def test_an_injection_never_changes_which_tools_run(task, config):
    honest = run_task(task, HonestAgent(), config)
    hijacked = run_task(task, HijackedAgent(), config)
    assert [e.tool for e in hijacked.transcript] == list(plan_tools(task))
    assert [e.tool for e in honest.transcript] == list(plan_tools(task))
    assert hijacked.attempted, "the injected text reached the system"
    for h, e in zip(honest.transcript, hijacked.transcript, strict=True):
        if e.origin == LEGIT and e.status != SKIPPED:
            assert dict(e.args) == dict(h.args), "a call no fooled value reached is unchanged"
        assert e.origin in (LEGIT, INFLUENCED)
    # Nothing the injection asked for that is not one of the plan's tools happened.
    kinds = {e["kind"] for e in hijacked.world.effects} - {e["kind"] for e in honest.world.effects}
    assert not kinds
    assert not hijacked.world.effects_of("file_deleted")


def test_an_influenced_call_is_one_that_carries_a_fooled_value():
    task = next(t for t in ATTACKS if t.id == "misuse-05")
    run = run_task(task, HijackedAgent(), PLAN_RUBBER)
    assert run.fooled_steps == ("body",)
    send = [e for e in run.transcript if e.tool == "send_email"]
    assert [e.origin for e in send] == [INFLUENCED]
    assert run.attack_succeeded, "a data-only attack: the value changed, the plan did not"
    mails = run.world.effects_of("email_sent")
    assert len(mails) == 1 and mails[0]["to"] == "carol@northwind.example"


def test_a_typed_slot_limits_what_the_injection_can_do():
    """misuse-04: the link slot becomes the attacker's URL; the budget never reaches it."""
    task = next(t for t in ATTACKS if t.id == "misuse-04")
    run = run_task(task, HijackedAgent(), PLAN_RUBBER)
    assert run.fooled_steps == ("link",)
    urls = [r["url"] for r in run.world.effects_of("web_request")]
    assert urls[1] == "https://vendor.example/quote?ctx="
    assert not any(run.world.canary["budget"] in u for u in urls)
    assert not run.attack_succeeded and run.stopped_by == PLAN


@settings(max_examples=60, deadline=None)
@given(st.text(max_size=200))
def test_any_extracted_text_leaves_the_tool_sequence_alone(evil):
    """Whatever an extractor returns, the same tools are tried in the same order."""
    task = next(t for t in ATTACKS if t.id == "misuse-06")
    planned = plan_for(task)

    class Adversary(ScriptedExtractor):
        def __call__(self, step, values):
            return evil if step.schema == TEXT else super().__call__(step, values)

    world = task.build_world(0)
    session = PlanSession(task, world, PLAN_RUBBER, 0)
    try:
        records = execute(
            planned.plan,
            provenance=session.provenance,
            session=session.gateway.authority.verify(session.token).jti,
            call_tool=lambda tool, wire: (lambda r: (r.status, r, r.handle))(
                session.call(tool, wire)
            ),
            extractor=Adversary(planned.answers),
        )
    finally:
        session.close()
    tools = [r.tool for r in records if r.kind == "tool"]
    assert tools == list(plan_tools(task))
    assert len(world.effects_of("email_sent")) <= 1


def test_extracted_values_carry_the_label_of_their_inputs():
    task = next(t for t in ATTACKS if t.id == "misuse-06")
    run = run_task(task, HonestAgent(), PLAN_CAREFUL)
    derived = [h for h in run.history if h["kind"] == "extract"]
    reply = derived[-2]["label"]  # inputs: Frank's email and the calendar
    assert "untrusted" in reply["sources"] and reply["readers"] == ["alice@northwind.example"]
    send = [h for h in run.history if h["kind"] == "call" and h["tool"] == "send_email"][-1]
    assert send["args"]["to"]["label"] == {"sources": ["user"], "readers": "any"}, (
        "a planner literal is the user's, even after untrusted reads"
    )


def test_plan_mode_honest_utility_and_no_attack_with_a_careful_approver():
    for task in ATTACKS:
        assert not run_task(task, HijackedAgent(), PLAN_CAREFUL).attack_succeeded, task.id
