# Running the sandbox evaluation with a real model

This runs the 26 sandbox tasks with a real model (`claude-sonnet-5-5`) as the agent, under three configurations: no gateway (0), grant plus policy with the careful approver (2), and configuration 2 plus session labels (3). It writes `results/real_model_sonnet.json`; the Claude Haiku 4.5 run in `results/real_model_haiku.json` was made the same way with `--model` and `--out` set. It spends real money on your Anthropic API key, capped in code.

How the harness works, and the exact rules for "attempted", "ignored" and "stopped", are in the docstring of `src/caveat/sandbox/llm_agent.py`.

## 1. Set up

```bash
git clone https://github.com/Varkot-dev/caveat
cd caveat                                 # everything is on main
python3.11 -m venv .venv                  # 3.11 or newer
source .venv/bin/activate
pip install -e ".[dev,llm]"
```

## 2. Protect the key first

1. In the Anthropic Console, set a monthly spending limit on the workspace or key you will use (for example $20). The script has its own cap, but the Console limit is the one that holds even if something goes wrong.
2. Put the key in the environment of this shell only:

   ```bash
   export ANTHROPIC_API_KEY=...   # paste it here, not into any file in the repo
   ```

   Never commit the key, never write it into `.env` files inside the repo, and do not paste it into an issue or chat.

## 3. Dry run (free)

```bash
python scripts/eval_real_model.py --dry-run
```

This uses a fake client that replays each task's legitimate plan through the real gateway. It needs no key, makes no network call and writes nothing. It prints the number of task runs (78 by default), a projected cost range and a projected time. The projection counts tokens roughly, as characters divided by 4, not with the API's token counter. On this repository it printed: low $1.91, high $13.40, about 22 to 84 minutes. The high end assumes no caching, 3 extra turns per task and 2000 output tokens per turn, so the real cost should be well below it, but the default cap ($12) can stop a run before the end; continue it with `--resume`.

## 4. The real run

```bash
python scripts/eval_real_model.py --max-usd 12
```

It prints a one-line warning and asks for confirmation (`--yes` skips the question). After every task it prints the task's status, cost and the running spend, and rewrites the results file, so nothing finished is lost.

Spending control: before every request the script computes the worst case of that call (its whole context at the cache-write rate plus `max_tokens` of output) and stops cleanly if the spend could cross `--max-usd`. The file is then marked `"status": "stopped: budget"`. The cap applies to one invocation; the file's `spend.total_usd` adds up all invocations.

Useful options: `--configs 0,2` (a subset), `--tasks benign-01,args-02` (a subset), `--out PATH`.

## 5. Resume a stopped run

```bash
python scripts/eval_real_model.py --resume --max-usd 6
```

Tasks already in the file are skipped and not paid for again. A task that was cut off by the budget is run again from the start (its partial cost stays recorded under `incomplete_tasks`). The script refuses to resume a file written for a different model, and refuses to overwrite an existing file without `--resume`.

## 6. Send the results back

Either commit the one file on a branch of your own and push it:

```bash
git switch -c real-model-run
git add results/real_model_sonnet.json
git commit -m "Real-model sandbox run"
git push -u origin real-model-run
```

or attach `results/real_model_sonnet.json` to a message. Check with `git status` that nothing else is staged.

The results file contains no secrets: the script never writes the key, request headers or the client configuration. It holds the task transcripts (tool calls, arguments, gateway decisions; not the model's thinking), the model's final reply text, token counts, costs, the model id the API reported, the SDK version and the date. A test (`tests/test_llm_agent.py`) runs the script with a fake key in the environment and checks that neither the key nor any header name appears in the file. The arguments contain the sandbox's fake canary strings (for example a fake API key), which are made up and harmless.

## What the numbers are and are not

One pass with one model; temperature cannot be set on this model, so a second run will give different counts. 26 hand-written tasks in a toy world: counts, not rates. The careful approver is an automated stand-in for a person and does not read email bodies. The `notes` field in the file says this too.
