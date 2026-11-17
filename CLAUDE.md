# CLAUDE.md

## What this project is
An authorization gateway for LLM agents: it sits between an agent and its tools, issues short-lived narrowly scoped permission tokens, lets an agent hand a weaker token to a sub-agent, checks every tool call against policy, pauses sensitive calls for human approval, and keeps a tamper-evident audit log.

The research, design and milestone plan is in `docs/PLAN.md`. Read it fully before doing anything.

## Who you are working with
Varshith owns this repo. He is building it to learn the material deeply and to show it publicly, so he must be able to explain every design decision in a technical conversation without notes.

## How to work
1. One milestone at a time, in the order in `docs/PLAN.md`. Do not start the next until the current one meets its "done when" criteria.
2. Teach before you build. At the start of each milestone, explain the concepts it needs with intuition and math together and two or three worked examples, using plain text math (no LaTeX). Then build.
3. After each milestone, quiz him on it one question at a time, waiting for each answer. Use the question list at the end of the plan and add your own.
4. Keep `docs/PLAN.md` current: tick off milestones, and record changed decisions and why in a "Decision log" section at the bottom.
5. The plan was written in November 2026. Before using any library API, dataset location or package name from it, check the current documentation. If something changed, follow the current docs and note it in the decision log.

## Commits
- Commit as the work actually happens: one commit per logical step (a module, its tests, a figure) with a plain message. Several small commits per milestone, pushed when that milestone's tests pass. Never one giant commit.
- Do not add AI co-author trailers or "Generated with" lines to commits or pull requests. This is the owner's standing instruction.
- Never alter commit dates or rewrite history to change when work appears to have happened.

## Honesty rules
- No number, chart or claim goes in the README unless a script in this repo produced it and the output is saved under `results/`.
- If something is untested, unfinished or only works on toy data, the README says so.
- Numbers from papers or other tools are quoted with their source and never blended with ours.

## Visuals
Every milestone that produces a result also produces a figure or demo under `assets/`, made by a script under `scripts/`. The README opens with one strong visual, then three sentences of explanation, then results. One consistent style. The plan lists the visuals.

## Engineering conventions
Python 3.11+, `pyproject.toml`, `ruff`, `pytest`, GitHub Actions running lint and tests on every push. Type hints on public functions. Fixed, recorded seeds. Config in files. Keep the repo private until the final milestone's checklist is done.
