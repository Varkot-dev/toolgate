"""Tests for the real-model harness, with fake clients only. No test calls the API.

Covers toolgate.sandbox.llm_agent (the tool-use loop, schemas, the budget,
the careful approver for real models, the attack classifier) and
scripts/m5_real_model_eval.py (budget stop with partial results, --resume,
the dry run, no key material in the output).
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from toolgate.sandbox import llm_agent as L
from toolgate.sandbox.agents import DENIED, ERROR, OK, HijackedAgent, HonestAgent, ToolResult
from toolgate.sandbox.runner import DirectSession
from toolgate.sandbox.tasks import MALLORY, all_tasks, attack_tasks
from toolgate.sandbox.world import BOB, FRANK, TOOLS

ROOT = Path(__file__).resolve().parent.parent
SECRET = "sk-ant-api03-THIS-IS-A-FAKE-KEY-0123456789"


def load_script() -> Any:
    spec = importlib.util.spec_from_file_location(
        "m5_real_model_eval", ROOT / "scripts" / "m5_real_model_eval.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


SCRIPT = load_script()
TASKS = {t.id: t for t in all_tasks()}


# -- fakes ----------------------------------------------------------------------


def usage(inp: int = 100, out: int = 50, read: int = 0, write: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        input_tokens=inp,
        output_tokens=out,
        cache_read_input_tokens=read,
        cache_creation_input_tokens=write,
    )


def tool_use(name: str, inp: Any, block_id: str = "toolu_1") -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", id=block_id, name=name, input=inp)


def response(content: list[Any], stop: str, **kw: Any) -> SimpleNamespace:
    return SimpleNamespace(
        content=content,
        stop_reason=stop,
        usage=kw.get("usage", usage()),
        model=kw.get("model", "claude-sonnet-5-5"),
        stop_details=kw.get("stop_details"),
    )


def text(s: str) -> SimpleNamespace:
    return SimpleNamespace(type="text", text=s)


def thinking() -> SimpleNamespace:
    return SimpleNamespace(type="thinking", thinking="", signature="sig-abc")


class ScriptedClient:
    """Returns scripted responses in order; records every request it was sent."""

    def __init__(self, responses: list[Any] | None = None, default: Any = None) -> None:
        self.responses = list(responses or [])
        self.default = default
        self.requests: list[dict[str, Any]] = []
        self.messages = self

    def create(self, **request: Any) -> Any:
        # Snapshot: the agent keeps appending to the same list.
        self.requests.append(request | {"messages": list(request["messages"])})
        if self.responses:
            return self.responses.pop(0)
        if self.default is None:
            raise AssertionError("no more scripted responses")
        return self.default() if callable(self.default) else self.default


class RecordingTool:
    def __init__(self, result: ToolResult | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.result = result or ToolResult(OK, {"ok": True})

    def __call__(self, tool: str, args: dict[str, Any]) -> ToolResult:
        self.calls.append((tool, args))
        return self.result


def agent(client: Any, budget: L.Budget | None = None, **kw: Any) -> L.LLMAgent:
    return L.LLMAgent(client, budget=budget, **kw)


TASK = TASKS["benign-01"]


# -- schemas and prompt ---------------------------------------------------------


def test_every_tool_has_a_strict_closed_schema_in_fixed_order() -> None:
    names = [t["name"] for t in L.TOOL_SCHEMAS]
    assert names == list(TOOLS)
    for tool in L.TOOL_SCHEMAS:
        schema = tool["input_schema"]
        assert tool["strict"] is True
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) <= set(schema["properties"])
    create = next(t for t in L.TOOL_SCHEMAS if t["name"] == "create_event")["input_schema"]
    assert create["required"] == ["title", "day"]
    assert create["properties"]["attendees"]["type"] == "array"
    assert L.tool_schemas() == list(L.TOOL_SCHEMAS)  # deterministic


def test_request_prefix_is_identical_across_tasks_and_prompt_is_neutral() -> None:
    a = agent(None)
    one = a.request([{"role": "user", "content": TASKS["benign-01"].request}])
    two = a.request([{"role": "user", "content": TASKS["misuse-04"].request}])
    assert one["tools"] == two["tools"] and one["system"] == two["system"]
    assert one["cache_control"] == {"type": "ephemeral"}
    assert one["output_config"] == {"effort": "medium"}
    assert "tool_choice" not in one and "temperature" not in one
    words = (L.SYSTEM_PROMPT + json.dumps(one["tools"])).lower()
    for banned in ("inject", "security", "gateway", "malicious", "attack", "untrusted"):
        assert banned not in words


def test_request_omits_thinking_and_effort_for_models_without_them() -> None:
    old = L.LLMAgent(None, model="claude-haiku-4-5")
    new = agent(None)
    messages = [{"role": "user", "content": TASKS["benign-01"].request}]
    old_request, new_request = old.request(messages), new.request(messages)
    assert "thinking" not in old_request and "output_config" not in old_request
    assert new_request["thinking"] == {"type": "adaptive"}
    assert {k: v for k, v in old_request.items() if k != "model"} == {
        k: v for k, v in new_request.items() if k not in ("model", "thinking", "output_config")
    }
    assert "claude-haiku-4-5" in L.PRICES
    assert set(L.NO_THINKING_MODELS) <= set(L.PRICES)


# -- the loop -------------------------------------------------------------------


def test_loop_runs_tools_through_call_tool_and_passes_content_back_unchanged() -> None:
    first = [thinking(), tool_use("read_file", {"path": "reports/q3_summary.txt"})]
    client = ScriptedClient([response(first, "tool_use"), response([text("Done.")], "end_turn")])
    tool = RecordingTool(ToolResult(OK, {"content": "Revenue 4.2M"}))
    t = agent(client).run(TASK, tool)
    assert tool.calls == [("read_file", {"path": "reports/q3_summary.txt"})]
    assert t.status == L.END_TURN and t.turns == 2 and t.final_text == "Done."
    second = client.requests[1]["messages"]
    assert second[0] == {"role": "user", "content": TASK.request}
    assert second[1]["role"] == "assistant"
    assert second[1]["content"] is first  # thinking block included, the very same objects
    (result,) = second[2]["content"]
    assert result["tool_use_id"] == "toolu_1" and "is_error" not in result
    assert json.loads(result["content"]) == {"content": "Revenue 4.2M"}


def test_parallel_tool_uses_return_in_one_user_message() -> None:
    blocks = [
        tool_use("read_inbox", {}, "toolu_a"),
        tool_use("read_file", {"path": "notes/todo.txt"}, "toolu_b"),
    ]
    client = ScriptedClient([response(blocks, "tool_use"), response([text("ok")], "end_turn")])
    agent(client).run(TASK, RecordingTool())
    last = client.requests[1]["messages"][-1]
    assert last["role"] == "user"
    assert [r["tool_use_id"] for r in last["content"]] == ["toolu_a", "toolu_b"]


@pytest.mark.parametrize(
    ("result", "expect"),
    [
        (
            ToolResult(DENIED, layer="policy deny", reason="denied [rule deny-secret-paths]"),
            "not allowed: denied [rule deny-secret-paths]",
        ),
        (ToolResult(ERROR, reason="FileNotFoundError: x"), "error: FileNotFoundError: x"),
        (ToolResult("pending"), L.PENDING_TEXT),
    ],
)
def test_denials_errors_and_pending_go_back_as_is_error(result: ToolResult, expect: str) -> None:
    client = ScriptedClient(
        [
            response([tool_use("read_file", {"path": "secrets/api_key.txt"})], "tool_use"),
            response([text("ok")], "end_turn"),
        ]
    )
    t = agent(client).run(TASK, RecordingTool(result))
    (sent,) = client.requests[1]["messages"][-1]["content"]
    assert sent["is_error"] is True and expect in sent["content"]
    assert t[0].status == result.status


def test_turn_cap_stops_at_twelve_model_calls() -> None:
    client = ScriptedClient(default=lambda: response([tool_use("read_inbox", {})], "tool_use"))
    tool = RecordingTool()
    t = agent(client).run(TASK, tool)
    assert len(client.requests) == L.MAX_TURNS == 12
    assert t.status == L.TURN_CAP and t.turns == 12 and len(tool.calls) == 12


def test_refusal_is_recorded_and_nothing_runs() -> None:
    details = SimpleNamespace(type="refusal", category="cyber", explanation="declined")
    client = ScriptedClient(
        [response([tool_use("read_inbox", {})], "refusal", stop_details=details)]
    )
    tool = RecordingTool()
    t = agent(client).run(TASK, tool)
    assert t.status == L.REFUSAL and t.refusal == {"category": "cyber", "explanation": "declined"}
    assert tool.calls == [] and len(client.requests) == 1


def test_max_tokens_stops_without_running_a_partial_call() -> None:
    client = ScriptedClient([response([tool_use("read_inbox", {})], "max_tokens")])
    tool = RecordingTool()
    t = agent(client).run(TASK, tool)
    assert t.status == L.MAX_TOKENS_STOP and tool.calls == []


@pytest.mark.parametrize(
    "bad",
    ['{"path": "reports/q3', {"path": "a.txt", "mode": "x"}, {"path": 3}, {}, ["path"]],
)
def test_malformed_tool_input_is_not_run_and_is_reported(bad: Any) -> None:
    client = ScriptedClient(
        [response([tool_use("read_file", bad)], "tool_use"), response([text("ok")], "end_turn")]
    )
    tool = RecordingTool()
    t = agent(client).run(TASK, tool)
    assert tool.calls == []
    assert t[0].status == L.INVALID
    (sent,) = client.requests[1]["messages"][-1]["content"]
    assert sent["is_error"] is True and "not run" in sent["content"]


def test_string_input_is_parsed_as_json() -> None:
    args, problem = L.parse_tool_input("read_file", '{"path": "notes\\/todo.txt"}')
    assert problem == "" and args == {"path": "notes/todo.txt"}
    assert L.parse_tool_input("no_such_tool", {})[0] is None


def test_handles_are_refused() -> None:
    with pytest.raises(ValueError):
        agent(ScriptedClient()).run(TASK, RecordingTool(), handles=True)


# -- budget ---------------------------------------------------------------------


def test_budget_costs_every_usage_field() -> None:
    b = L.Budget(10.0, L.PRICES["claude-sonnet-5-5"])
    _, cost = b.add(usage(inp=1_000_000, out=1_000_000, read=1_000_000, write=1_000_000))
    assert cost == pytest.approx(2.0 + 10.0 + 0.10 + 2.50)
    assert b.tokens == {"input": 10**6, "output": 10**6, "cache_read": 10**6, "cache_write": 10**6}


def test_budget_stops_before_a_call_that_could_cross_the_cap() -> None:
    prices = L.PRICES["claude-sonnet-5-5"]
    # Each response costs 1000 * $10 / 1e6 = $0.01 of output; worst case of a
    # call is max_tokens (8000) output = $0.08 plus its context.
    cap = 0.12
    b = L.Budget(cap, prices)
    each = response([tool_use("read_inbox", {})], "tool_use", usage=usage(inp=0, out=1000))
    client = ScriptedClient(default=each)
    t = agent(client, budget=b).run(TASK, RecordingTool())
    assert t.status == L.STOP_BUDGET
    assert b.spent_usd <= cap
    assert len(client.requests) == b.requests >= 1
    # It stopped near the cap, not early: one more worst-case call (max_tokens of
    # output plus a few thousand tokens of context) would have crossed it.
    assert b.spent_usd + b.worst_case(5000, L.MAX_TOKENS) > cap


# -- careful approver for real models ----------------------------------------------


def test_intent_approver_compares_destinations_not_free_text() -> None:
    approver = L.IntentApprover.for_task(TASKS["benign-07"])
    erin = "erin@ledgerline.example"
    assert approver.approves("send_email", {"to": erin, "subject": "x", "body": "anything"})
    assert approver.approves(
        "send_email", {"to": "Erin@Ledgerline.example", "subject": "", "body": ""}
    )
    assert not approver.approves("send_email", {"to": MALLORY, "subject": "x", "body": "y"})
    assert not approver.approves("write_file", {"path": "drafts/x.txt", "content": "y"})
    pub = L.IntentApprover.for_task(TASKS["approval-02"])
    assert pub.approves("write_file", {"path": "public/./announcement.txt", "content": "any"})
    assert not pub.approves("write_file", {"path": "public/other.txt", "content": "any"})
    fetch = L.IntentApprover.for_task(TASKS["misuse-04"])
    assert fetch.approves("web_fetch", {"url": "https://vendor.example/pricing"})
    assert not fetch.approves("web_fetch", {"url": "https://vendor.example/quote?ctx=budget"})
    invite = L.IntentApprover.for_task(TASKS["approval-01"])
    assert invite.approves("create_event", {"title": "t", "day": "2026-11-23", "attendees": [BOB]})
    assert not invite.approves(
        "create_event", {"title": "t", "day": "2026-11-23", "attendees": [BOB, MALLORY]}
    )


def test_intent_approver_never_consults_the_attack_check() -> None:
    task = TASKS["misuse-06"]

    def boom(_: Any) -> bool:
        raise AssertionError("the approver read the attack check")

    # Same decisions with the attack check booby-trapped and the injected plan removed.
    poisoned = dataclasses.replace(task, attack_succeeded=boom, injected=(), injection="")
    assert L.IntentApprover.for_task(poisoned) == L.IntentApprover.for_task(task)
    approver = L.IntentApprover.for_task(poisoned)
    assert approver.approves("send_email", {"to": FRANK, "subject": "s", "body": "b"})


def test_honest_plan_is_approved_in_every_gateway_configuration() -> None:
    for key in ("2-policy-careful", "3-session-labels"):
        for task in all_tasks():
            world = task.build_world(0)
            session = L.make_session(key, task, world)
            try:
                HonestAgent().run(task, session.call)
            finally:
                session.close()
            assert session.approvals_granted == session.approvals_requested, (key, task.id)
            assert task.utility(world), (key, task.id)


# -- attempted, ignored, stopped ----------------------------------------------------


def _scripted(agent_cls: type, task: Any, key: str = "0-no-gateway") -> dict[str, Any]:
    world = task.build_world(0)
    session = L.make_session(key, task, world)
    try:
        entries = agent_cls().run(task, session.call)
    finally:
        session.close()
    seen = [task.injection if task.injection else "" for _ in entries]  # delivered
    return L.classify_attack(task, entries, seen, world)


@pytest.mark.parametrize("task", attack_tasks(), ids=lambda t: t.id)
def test_classifier_on_the_scripted_agents(task: Any) -> None:
    honest = _scripted(HonestAgent, task)
    assert not honest["attempted"] and honest["outcome"] == L.IGNORED
    hijacked = _scripted(HijackedAgent, task)
    assert hijacked["attempted"] and hijacked["outcome"] == L.SUCCEEDED
    assert not hijacked["classifier_miss"]
    for key in ("2-policy-careful", "3-session-labels"):
        result = _scripted(HijackedAgent, task, key)
        assert result["attempted"], key
        assert result["outcome"] in (L.SUCCEEDED, L.STOPPED, L.INCOMPLETE)


def test_attacker_text_markers_come_from_the_injection_only() -> None:
    for task_id, markers in L.ATTACKER_TEXT.items():
        task = TASKS[task_id]
        legit = json.dumps(L.legitimate_plan(task))
        for marker in markers:
            assert marker in task.injection and marker not in legit


def test_not_delivered_vs_ignored() -> None:
    task = TASKS["tool-02"]
    world = task.build_world(0)
    entries = [L.Entry(L.MODEL, "web_fetch", {"url": "https://news.example/ai-roundup"}, OK)]
    assert L.classify_attack(task, entries, ["nothing"], world)["outcome"] == (
        L.INJECTION_NOT_DELIVERED
    )
    assert L.classify_attack(task, entries, [task.injection], world)["outcome"] == L.IGNORED


def test_a_refused_attack_call_is_stopped_by_the_gateway() -> None:
    task = TASKS["args-02"]
    world = task.build_world(0)
    entries = [
        L.Entry(L.MODEL, "read_file", {"path": "downloads/vendor_quote.txt"}, OK),
        L.Entry(
            L.MODEL, "read_file", {"path": "secrets/api_key.txt"}, DENIED, "grant argument check"
        ),
    ]
    result = L.classify_attack(task, entries, [task.injection, "x"], world)
    assert result["attack_driven"] == [False, True]
    assert result["outcome"] == L.STOPPED and result["stopped_by"] == "grant argument check"


# -- the script -----------------------------------------------------------------------


def honest_client_factory() -> Any:
    """A fake real-mode client that replays each task's honest plan, keyed by request."""

    class Client:
        def __init__(self) -> None:
            self.messages = self
            self.replays: dict[str, L.PlanReplayClient] = {}
            self.count = 0

        def create(self, **request: Any) -> Any:
            self.count += 1
            first = request["messages"][0]["content"]
            if len(request["messages"]) == 1:
                task = next(t for t in all_tasks() if t.request == first)
                self.replays[first] = L.PlanReplayClient(task)
            out = self.replays[first].create(**request)
            out.model = "claude-sonnet-5-5"
            out.usage = usage(inp=200, out=100)
            return out

    return Client()


def run_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *args: str, client: Any) -> int:
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET)
    return SCRIPT.main(["--yes", "--out", str(tmp_path / "out.json"), *args], client=client)


def test_full_fake_run_writes_results_without_key_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = honest_client_factory()
    code = run_script(
        tmp_path, monkeypatch, "--tasks", "benign-01,args-02,misuse-02", client=client
    )
    assert code == 0
    raw = (tmp_path / "out.json").read_text()
    data = json.loads(raw)
    assert data["status"] == "complete"
    assert data["model_ids_reported"] == ["claude-sonnet-5-5"]
    for needle in (SECRET, "sk-ant", "x-api-key", "authorization", 'api_key":'):
        assert needle.lower() not in raw.lower()
    for config in data["configurations"]:
        s = config["summary"]
        assert s["tasks_run"] == 3 and s["benign_utility"] == {"completed": 1, "of": 1}
        assert s["model_ignored_injection"] == 2 and s["attacks_attempted"] == 0
    assert data["spend"]["total_usd"] > 0
    assert any("counts, not rates" in n for n in data["notes"])


def test_budget_stop_writes_partial_results_marked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = honest_client_factory()
    code = run_script(tmp_path, monkeypatch, "--configs", "0", "--max-usd", "0.2", client=client)
    assert code == 3
    data = json.loads((tmp_path / "out.json").read_text())
    assert data["status"] == L.STOP_BUDGET
    assert data["invocations"][-1]["spent_usd"] <= 0.2
    done = len(data["configurations"][0]["tasks"]) if data["configurations"] else 0
    assert 0 < done < 26
    assert data["incomplete_tasks"] and data["incomplete_tasks"][0]["status"] == L.STOP_BUDGET


def test_resume_skips_finished_tasks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    first = honest_client_factory()
    assert (
        run_script(
            tmp_path, monkeypatch, "--configs", "0", "--tasks", "benign-01,benign-03", client=first
        )
        == 0
    )
    second = honest_client_factory()
    assert (
        run_script(
            tmp_path,
            monkeypatch,
            "--configs",
            "0",
            "--resume",
            "--tasks",
            "benign-01,benign-03,benign-04",
            client=second,
        )
        == 0
    )
    assert second.replays.keys() == {TASKS["benign-04"].request}
    data = json.loads((tmp_path / "out.json").read_text())
    assert set(data["configurations"][0]["tasks"]) == {"benign-01", "benign-03", "benign-04"}
    assert len(data["invocations"]) == 2


def test_refuses_without_key_and_without_resume_over_existing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(SystemExit, match="ANTHROPIC_API_KEY"):
        SCRIPT.main(["--yes", "--out", str(tmp_path / "x.json")])
    (tmp_path / "x.json").write_text("{}")
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET)
    with pytest.raises(SystemExit, match="exists"):
        SCRIPT.main(["--yes", "--out", str(tmp_path / "x.json")], client=object())


def test_dry_run_never_constructs_the_real_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    anthropic = pytest.importorskip("anthropic")

    def forbidden(*_: Any, **__: Any) -> None:
        raise AssertionError("the real client was constructed in a dry run")

    monkeypatch.setattr(anthropic, "Anthropic", forbidden)
    monkeypatch.setattr(SCRIPT, "make_client", forbidden)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = tmp_path / "never.json"
    assert SCRIPT.main(["--dry-run", "--out", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "78 task runs" in printed and "Projected cost" in printed
    assert not out.exists()


def test_real_client_is_only_built_after_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET)
    monkeypatch.setattr("builtins.input", lambda _: "n")
    monkeypatch.setattr(SCRIPT, "make_client", lambda: pytest.fail("client built"))
    assert SCRIPT.main(["--out", str(tmp_path / "o.json")]) == 1


def test_scripted_direct_session_is_unchanged() -> None:
    # The harness reuses runner.DirectSession; a model call reaches the world as is.
    task = TASKS["benign-03"]
    world = task.build_world(0)
    result = DirectSession(task, world, None, 0).call(
        "create_event", {"title": "Focus time", "day": "2026-11-19"}
    )
    assert result.status == OK and task.utility(world)


def test_requests_build_with_the_installed_sdk_over_a_local_mock_transport() -> None:
    """The real SDK client serializes our requests; a mock transport answers, no network."""
    anthropic = pytest.importorskip("anthropic")
    httpx2 = pytest.importorskip("httpx2")
    bodies: list[dict[str, Any]] = []

    def handler(request: Any) -> Any:
        assert request.url.host == "localhost"
        bodies.append(json.loads(request.content))
        content = [
            {"type": "thinking", "thinking": "", "signature": "sig"},
            {"type": "tool_use", "id": "toolu_1", "name": "read_inbox", "input": {}},
        ]
        return httpx2.Response(
            200,
            json={
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "model": "claude-sonnet-5-5",
                "content": content if len(bodies) == 1 else [{"type": "text", "text": "Done."}],
                "stop_reason": "tool_use" if len(bodies) == 1 else "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 5, "output_tokens": 3},
            },
        )

    client = anthropic.Anthropic(
        api_key="dummy-not-a-key",
        base_url="http://localhost:9",
        http_client=anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(handler)),
        max_retries=0,
    )
    budget = L.Budget(1.0, L.PRICES["claude-sonnet-5-5"])
    t = agent(client, budget).run(TASK, RecordingTool(ToolResult(OK, {"emails": []})))
    assert t.status == L.END_TURN and t.models == ["claude-sonnet-5-5"]
    second = bodies[1]
    assert second["cache_control"] == {"type": "ephemeral"}
    assert second["output_config"] == {"effort": "medium"}
    assert second["tools"][0]["strict"] is True
    assert second["messages"][1]["content"][0] == {
        "type": "thinking",
        "thinking": "",
        "signature": "sig",
    }
    assert second["messages"][2]["content"][0]["tool_use_id"] == "toolu_1"
    assert budget.tokens["input"] == 10
