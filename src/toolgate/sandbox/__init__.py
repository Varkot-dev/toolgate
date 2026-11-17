"""A deterministic, model-free test bed for the gateway.

Three parts: a sandbox world with tools (`world`), a task suite with ground
truth (`tasks`), and scripted agents that stand in for a model (`agents`).
`runner` puts them together. Scripted agents, not a language model.
"""

from toolgate.sandbox.agents import Approver, HijackedAgent, HonestAgent, ToolResult
from toolgate.sandbox.runner import CONFIGURATIONS, evaluate, run_task
from toolgate.sandbox.tasks import Task, all_tasks, attack_tasks, benign_tasks
from toolgate.sandbox.world import TOOLS, World, base_world, result_is_untrusted

__all__ = [
    "CONFIGURATIONS",
    "TOOLS",
    "Approver",
    "HijackedAgent",
    "HonestAgent",
    "Task",
    "ToolResult",
    "World",
    "all_tasks",
    "attack_tasks",
    "base_world",
    "benign_tasks",
    "evaluate",
    "result_is_untrusted",
    "run_task",
]
