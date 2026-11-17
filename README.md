# toolgate

<p align="center">
  <img src="assets/hero.svg" width="900" alt="One sub-agent token makes two calls through the gateway: read_file is allowed and runs, delete_file is denied by policy, and both decisions appear as hash-chained audit entries">
</p>
<p align="center"><sub>Animated SVG. Also as <a href="assets/hero.gif">GIF</a> and as a <a href="assets/hero_poster.png">still image</a>. Drawn from one real run recorded in <a href="results/m6_hero.json">results/m6_hero.json</a>.</sub></p>

toolgate is an authorization gateway that sits between an LLM agent and its tools and checks every tool call against a short-lived, narrowly scoped grant and an operator policy, outside the model. An agent can hand a sub-agent a weaker token but never a stronger one, sensitive calls wait for a person, and every decision is written to a hash-chained audit log before anything runs. The model does not decide what it is allowed to do.

| Result | Value | Source |
|---|---|---|
| Violations of "child allows implies parent allows" | 0 in 20,000 generated cases | `results/m0_invariant.json` |
| Attenuation rules proven by Z3 (escalation query unsat) | 19 of 19 lemmas | `results/m0b_rules.json` |
| Attacks that succeeded, scripted agents, 18 attacks | 18 of 18 with no gateway; 0 of 17 with value labels and 0 of 18 with plan-then-execute (careful approver) | `results/m5_scripted.json` |
| Benign tasks completed, scripted agents | 8 of 8 in every configuration | `results/m5_scripted.json` |
| Added latency per allowed call, median (reused token, audit fsync on) | 448 us | `results/m6_latency.json` |

Protection numbers come from **scripted agents** on 26 hand-written tasks, not from a language model; see [Protection](#2-protection-scripted-agents).

## The problem

An agent that calls tools usually holds one broad, long-lived credential. That creates four problems:

1. **Confused deputy.** A document or tool result can contain instructions, and the agent may carry them out with the user's authority.
2. **Standing access wider than the task.** The task needs "read one folder"; the credential allows everything, indefinitely.
3. **Unlimited delegation.** An orchestrator passes its full credential to every sub-agent.
4. **No record of who authorized what.** Afterwards nobody can reconstruct which person or agent allowed an action.

toolgate applies ordinary least-privilege access control to agents: a separate component checks every call against an explicit grant.

## How a call is decided

`Gateway.handle_call` in [src/toolgate/gateway.py](src/toolgate/gateway.py) is the only way a tool runs. The HTTP server and the MCP proxy are thin adapters over it. Each step fails closed.

1. **Canonicalize.** Rewrite each argument the operator has typed (path, email, URL) to one spelling, or refuse it if it is ambiguous. In value-label mode, resolve handle references and label every argument.
2. **Build the call.** A read-only plain-JSON copy of the arguments; this copy is what is checked, hashed, stored for approval and passed to the tool.
3. **Verify the token** once (Ed25519 signature, issuer, audience, expiry, revocation of the token and every ancestor) and ask its grant, without spending budget.
4. **Grant check.** Closed-world: every argument must be named by a constraint and every constraint must hold.
5. **Policy.** Deny beats approve beats allow; no matching rule means deny.
6. **Approval if needed.** The call is parked, bound to the exact request, and nothing runs. When a person approves, steps 3 to 9 run again on the stored call with a fresh clock.
7. **Budget charge** along the signed delegation path: the call is charged to its own capability and to every ancestor capability in one atomic store operation.
8. **Audit before acting.** The entry is written and fsynced; if it cannot be written, the charge is refunded and the tool does not run.
9. **Recheck** expiry and revocation (cheap, no signature), then **run** the tool on the canonical copy. A tool that started is never refunded.

Why each step is where it is: [Decision log in docs/PLAN.md](docs/PLAN.md#decision-log).

## Results

Every number below was written by a script in this repo; the file and key are named next to it. `scripts/reproduce_all.sh` regenerates all of them.

### 1. Security invariant

The invariant: if the attenuation check accepts a child grant, every call the child allows is also allowed by the parent.

| Measure | Value | Key in `results/m0_invariant.json` |
|---|---|---|
| Generated (parent, child, call) cases, seed 0 | 20,000 | `cases_generated` |
| Child grants the check accepted | 13,057 | `children_accepted` |
| Cases where the accepted child allows the call (the invariant has something to prove) | 4,987 | `calls_allowed_by_accepted_child` |
| Violations | 0 | `violations` |
| Deliberately broken versions of the check caught by the same generators | 13 of 13 | `mutants_killed`, `mutants_tried` |

Random testing samples the space; the solver searches all of it. Each rule of the checker is a Z3 query over symbolic parameters: "given the rule's side condition, is there a value the child accepts and the parent rejects?"

| Measure | Value | Key in `results/m0b_rules.json` |
|---|---|---|
| Lemmas answered unsat (no escalation) | 19 of 19 | `summary.lemmas_unsat` |
| Of those, checked within a stated bound | 6 | `summary.lemmas_bounded` |
| Deliberately wrong rules answered sat, with a counterexample | 12 of 12 | `summary.wrong_variants_sat` |
| Lemma premises satisfiable on their own (no vacuous proof) | 19 of 19 | `summary.premise_checks_sat` |

The bounds are listed per lemma in the file (for example, the glob prefix lemma is checked for 0 to 4 child stars, capability composition for 3 argument names). The solver proves the rules as modeled; the Python checker is tied to the model by differential tests, not by proof.

The check is sound by design and deliberately incomplete. The completeness gap was measured exhaustively on every ordered pair of a 125-constraint universe:

![Completeness gap: for every parent and child operator, how many pairs are safe and accepted, safe but rejected, and unsafe and rejected](assets/completeness_gap.png)

| All 15,625 pairs (`results/m0b_completeness.json`, `exhaustive_constraints`) | Before the star-free rule | After |
|---|---|---|
| Safe and accepted | 648 | 1,016 |
| Safe but rejected (the gap) | 576 | 208 |
| Accepted but unsafe | 0 | 0 |
| Solver gave no answer | 0 | 0 |

"Before" is `previous_rule_set.outcomes`, "after" is `outcomes`. The one added rule (a child `glob` with no `*` is checked like `eq`) closed 368 pairs (`rule_a.gap_pairs_closed`). Collapsing repeated stars would close 115 more (`what_if_extensions`); it was not added. These counts describe this enumerated universe, not real workloads.

### 2. Protection (scripted agents)

Read this first: these numbers come from **scripted agents** on **26 hand-written tasks** (8 benign, 18 attacks in five classes) in one in-memory toy world, not from a language model. The hijacked scripted agent obeys every injected instruction and retries twice when refused, so the numbers measure the defence layers, not how often a model is hijacked. They are counts, not rates. A test asserts that every attack succeeds with no gateway.

From `results/m5_scripted.json`, `configurations[].summary`:

| Configuration | Attacks succeeded | Benign tasks completed | Approvals requested (honest runs, all 26 tasks) |
|---|---|---|---|
| 0. No gateway | 18 of 18 | 8 of 8 | 0 |
| 1. Grant only (allow-all policy) | 10 of 18 | 8 of 8 | 0 |
| 1c. Grant plus canonicalization | 9 of 18 | 8 of 8 | 0 |
| 2. Grant plus policy, careful approver | 4 of 18 | 8 of 8 | 8 |
| 2. Grant plus policy, rubber-stamp approver | 9 of 18 | 8 of 8 | 8 |
| 3. Plus session labels, careful | 0 of 18 | 8 of 8 | 27 |
| 3. Plus session labels, rubber-stamp | 8 of 18 | 8 of 8 | 27 |
| 4. Plus value labels (handles), careful | 0 of 17 | 8 of 8 | 19 |
| 4. Plus value labels (handles), rubber-stamp | 7 of 17 | 8 of 8 | 19 |
| 5. Plan-then-execute, careful | 0 of 18 | 8 of 8 | 15 |
| 5. Plan-then-execute, rubber-stamp | 4 of 18 | 8 of 8 | 15 |

Columns: `attacks_succeeded` of `attacks_attempted`, `benign_utility_honest`, `approvals_requested.honest.total`. Notes:

- The careful approver is an oracle that approves only the exact call the honest agent would make; the rubber-stamp approver approves everything. Real people are in between, and the rubber-stamp rows show that the approval layer is only as good as the person.
- In configuration 4 one attack (args-03) was never attempted: label creep had already denied the fetch that would have delivered the injection, which is why the denominator is 17.
- In configuration 4 the honest agent had 2 calls denied (`calls_denied.honest`) and still completed all its tasks.
- Class d attacks stay inside every argument constraint of the grant; argument constraints alone cannot stop them, which is what the provenance configurations (3 to 5) are for.

Stronger tracking asks a person more often. Label creep is the reason: once the agent has read untrusted content, every literal it writes is treated as untrusted.

![Label creep: attacks that succeeded and approvals per task for each configuration, and the share of values labeled untrusted by step within a task](assets/label_creep.png)

From `results/m4b_label_creep.json`, `configurations.*.by_step`: with session labels, 100% of values are untrusted from the third call of a task on; with value labels the share reaches 85.71% at step 5; with plan-then-execute it stays between 41.67% and 56.92% after step 1. Scripted agents, scripted planner and scripted extractor.

![Provenance graph of task misuse-04 under value labels: every argument and result colored by its sources, with the injected fetch blocked by rule deny-non-public-data-in-url](assets/provenance_graph.png)

One class d attack (task misuse-04: leak the budget through the URL of a fetch to an allowed host), hijacked scripted agent, value labels. Every label drawn is the one the gateway recorded (`results/m4b_provenance_graph.json`): the injected fetch is denied by `deny-non-public-data-in-url`, and the later legitimate fetch is denied too, which is label creep in one picture.

### 3. Cost

From `results/m6_latency.json`, `pipeline.<config>.added` (time of `Gateway.handle_call` for an allowed call to a no-op tool, minus a direct call of that tool; 10,000 calls each; in-process, memory store):

| Token | Audit fsync | p50 | p99 |
|---|---|---|---|
| Warm (one token reused, verify cache hit) | on | 448 us | 1,404 us |
| Cold (new token every call, signature checked) | on | 772 us | 1,783 us |
| Warm | off | 117 us | 241 us |
| Cold | off | 348 us | 705 us |

Components timed alone (`stages.*.p50_us`): cold verify 193.8 us, of which the Ed25519 signature check 95.1 us; audit append with fsync 225.6 us, without 30.1 us. With the SQLite store instead of memory, warm with fsync, p50 is 1,806 us (`pipeline.sqlite_fsync_on_warm`).

Throughput (`throughput`): in-process, one thread, warm, 1,768.3 calls/s with fsync and 7,148.6 without; cold with fsync 1,221.9. Over HTTP to the FastAPI app on one uvicorn process on localhost, 341.9 calls/s with 1 client (p50 2,835 us) and 619.2 with 16 clients. Through the MCP proxy, the median `tools/call` was 3,990 us slower than the same call made directly to the upstream (`mcp_proxy.added_p50_us`, a difference of medians).

![Latency histograms of warm and cold calls with p50 and p99 marked, and the median of each pipeline component](assets/latency.png)

Caveat: one shared cloud container (Intel Xeon at 2.10 GHz, 4 logical cores, ext4 temp directory), not isolated from other tenants. The numbers are indicative, vary from run to run, and the latency figure changes every time it is regenerated (the only other figures that do are the dashboard screenshots, which show wall-clock times). Nothing here is compared with any other system. fsync cost depends entirely on the disk.

### 4. Delegation, offline tokens, audit and dashboard

![Delegation tree: a user grant, an orchestrator and two sub-agents, each narrower than its parent, and one wider request rejected](assets/delegation_tree.png)

Every arrow is a real `check_attenuation` call: three narrower children are accepted and a request for `read_file(path ~ *)` is rejected (`results/m0_delegation_tree.json`).

![Token chain: an HMAC token gains three caveats offline, each changing the signature, and a token with the last caveat removed fails verification](assets/token_chain.png)

A holder narrows an HMAC chain token offline with no key; removing a caveat fails with "signature mismatch" because HMAC cannot be run backwards (`results/m1b_token_chain.json`).

![Audit chain: an 8-entry log verifies, and a copy with one field of entry 3 changed fails verification at entry 3](assets/audit_tamper.png)

Changing one field of entry 3 in a copy of a real 8-entry log makes `verify` report entry 3 as the first bad entry (`results/m2_audit_tamper.json`).

![Dashboard tamper demo: the real log verifies, a temporary copy with entry 11 changed fails at entry 11](assets/dashboard_tamper.png)

The admin dashboard shows the decision feed, the approval queue and the audit chain; its tamper button edits a temporary copy, never the real log ([full page](assets/dashboard.png)). Screenshots from `scripts/fig_dashboard.py`; times and hashes in them come from the wall clock, so they differ between runs.

## Quick start

Python 3.11 or later.

```bash
pip install -e ".[dev]"
pytest -q                          # TOOLGATE_EXAMPLES=300 for a faster property-test run
ruff check . && ruff format --check .
```

The capability model as a library:

```python
from toolgate import Call, Grant, check_attenuation

parent = Grant.from_dict(
    {
        "expires_at": 1_800_003_600,
        "capabilities": [{"tool": "read_file", "args": {"path": {"glob": "reports/*"}}}],
    }
)
child = Grant.from_dict(
    {
        "expires_at": 1_800_000_600,
        "capabilities": [{"tool": "read_file", "args": {"path": {"glob": "reports/q3/*"}}}],
    }
)

assert check_attenuation(parent, child).ok
assert not check_attenuation(child, parent).ok
assert child.allows(Call("read_file", {"path": "reports/q3/a.txt"}), 1_800_000_000)
assert not child.allows(Call("read_file", {"path": "reports/q1/a.txt"}), 1_800_000_000)
```

Run the gateway. The two secrets come from environment variables, never from files; read [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) before listening on anything but loopback.

```bash
export TOOLGATE_SIGNING_KEY="$(openssl rand -base64 32)"
ADMIN_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
export TOOLGATE_ADMIN_KEY_SHA256="$(printf %s "$ADMIN_KEY" | sha256sum | cut -d' ' -f1)"
python -m toolgate.server --config config/gateway.example.yaml   # 127.0.0.1:8000, audit log in config/

# in a second shell (same ADMIN_KEY): mint a root token, then call the example tool
curl -s -X POST localhost:8000/token -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"sub":"user:alice","actor":"agent:demo","expires_in":600,
       "capabilities":[{"tool":"echo","args":{"text":{"any":true}}}]}'
curl -s -X POST localhost:8000/call -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"tool":"echo","args":{"text":"hi"}}'
curl -s localhost:8000/audit/verify -H "Authorization: Bearer $ADMIN_KEY"
```

`TOKEN` is the `token` field of the first response. The call is denied at stage `policy` ("no rule matched (default deny)"): the grant allows `echo`, but `config/policy.example.yaml` has no rule for it. Both checks must agree.

Demos (each deterministic, each writes its results file):

```bash
python scripts/m1_demo.py          # tokens: exchange, escalation refused, shared budget, revocation
python scripts/demo_gateway.py     # HTTP gateway: allow, deny, approval, revoke, audit verify
python scripts/demo_mcp_proxy.py   # MCP client direct vs through the proxy
python scripts/demo_dashboard.py   # starts the gateway with the dashboard on, prints URL and demo key
```

MCP proxy in front of the example MCP server. The token audience must be the proxy's own URL (RFC 8707), so use a copy of the config with `audience` changed:

```bash
python examples/mcp_upstream_server.py --port 8765 &
sed 's|^audience: "toolgate"|audience: "http://127.0.0.1:8000/mcp"|' \
  config/gateway.example.yaml > config/proxy.local.yaml
python -m toolgate.mcp_proxy --config config/proxy.local.yaml --upstream http://127.0.0.1:8765/mcp
```

The admin API is mounted under `/admin` on the same port. Audit logs can be checked offline with `python -m toolgate.audit verify <path> --head <hash>`.

## Reproducing every number

```bash
bash scripts/reproduce_all.sh      # several minutes; the dashboard step needs Chromium and Playwright
```

| Script | Writes |
|---|---|
| `scripts/m0_invariant.py` | `results/m0_invariant.json` |
| `scripts/fig_delegation_tree.py` | `results/m0_delegation_tree.json`, `assets/delegation_tree.*` |
| `scripts/m0b_prove_rules.py` | `results/m0b_rules.json` |
| `scripts/m0b_completeness.py` (a few minutes) | `results/m0b_completeness.json` |
| `scripts/fig_completeness_gap.py` | `assets/completeness_gap.*` |
| `scripts/m1_demo.py` | `results/m1_demo.json` |
| `scripts/fig_token_chain.py` | `results/m1b_token_chain.json`, `assets/token_chain.*` |
| `scripts/fig_audit_tamper.py` | `results/m2_audit_tamper.json`, `assets/audit_tamper.*` |
| `scripts/demo_gateway.py` | `results/m3_demo.json` |
| `scripts/demo_mcp_proxy.py` | `results/m4_demo.json` |
| `scripts/m5_scripted_eval.py` | `results/m5_scripted.json` |
| `scripts/fig_label_creep.py` | `results/m4b_label_creep.json`, `assets/label_creep.*` |
| `scripts/fig_provenance_graph.py` | `results/m4b_provenance_graph.json`, `assets/provenance_graph.*` |
| `scripts/fig_hero.py` | `results/m6_hero.json`, `assets/hero.svg`, `hero.gif`, `hero_poster.png` |
| `scripts/bench_latency.py` (a few minutes) | `results/m6_latency.json` |
| `scripts/fig_latency.py` | `assets/latency.*` |
| `scripts/fig_dashboard.py` | `assets/dashboard.png`, `assets/dashboard_tamper.png` |

Seeds, clocks and ids are fixed, so every file except `m6_latency.json`, the latency figure and the dashboard screenshots is identical byte for byte on a rerun.

## What this does not do

- **Bearer tokens.** There is no proof of possession (DPoP is not built): a stolen token works until it expires or is revoked.
- **One shared admin key, self-declared approver.** The log records "by admin", and the approver name is any printable name the admin-key holder types. Actor names in `act` are self-declared attribution, never used for a decision.
- **Glob is string matching.** `*` is the only special character and it does not understand paths. Safety depends on canonicalization, which the operator must configure per tool; path canonicalization is lexical and cannot see symbolic links.
- **No implicit flows.** Labels follow data, not control flow: which branch ran, or whether a call happened, is not labeled, and neither is which handle or field the agent selects.
- **Labels per result, not per field, and not persisted with files.** Untrusted text written to a private folder reads back as trusted.
- **Value labels assume a runtime that passes handles.** Ordinary agents do not, unless they run plan-then-execute.
- **Plan-then-execute is scripted here.** The planner and the quarantined extractor are per-task functions, not models; they show the mechanism, not how well a model plans or how often an extractor is fooled.
- **Approvals are only as good as the human.** Compare the careful and rubber-stamp rows; stronger labeling also asks more often.
- **A timed-out tool keeps running.** Python threads cannot be killed; it keeps its in-flight slot and its budget is not refunded.
- **Single node.** The store is in memory or one SQLite file; the approval queue, in-flight counters and unverified-token rate limit are in memory and lost on restart (which fails closed).
- **A reverse proxy is required for anything but loopback.** It must provide TLS, header and body read timeouts, per-address connection and rate limits, and a body size limit; path-based ACLs at the proxy must not be relied on ([docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)).
- **The audit chain is tamper-evident only against a trusted head.** Without a published head or checkpoint, someone who can rewrite the file can truncate it or rebuild every hash. External anchoring is not built, and rotated files are not linked to each other.
- **Budget edge cases.** First-fit derivation can strand budget; a limited capability does not cap an overlapping unlimited one; offline chain tokens carry no budget at all.
- **Expiry is only as good as the clock.** A clock set backwards can revive an expired token.
- **Policy limits.** Conditions see top-level arguments only; `absent` and `any` on a deny or approve rule are presence tests the caller controls; an approve rule opens a path to execution that no allow rule covers.
- **MCP proxy scope.** Only tools are proxied (resources, prompts and sampling are refused); the tool set is fixed at startup; tool descriptions and results pass through as the upstream wrote them; toolgate is not an OAuth authorization server.
- **Incomplete by design.** The attenuation check rejects 208 safe pairs in the measured universe; the proofs cover the rules as modeled, within the stated bounds.

## Relation to prior work

Statements in this section are about other work and are quoted from the named source; none of our numbers is derived from them.

- **MCP authorization**, spec revision 2026-07-28 (modelcontextprotocol.io/specification/2026-07-28/basic/authorization): OAuth 2.1, the MCP server is a resource server, servers publish Protected Resource Metadata (RFC 9728), clients send the `resource` parameter (RFC 8707), and token passthrough is forbidden. toolgate's proxy follows these (it serves the RFC 9728 document, requires the token audience to be its own URL, and never sends the caller's token upstream) and adds what the spec leaves out: per-call argument limits, narrowing down a chain of sub-agents, and human approval.
- **OAuth 2.0 Token Exchange, RFC 8693**, and the IETF WIMSE drafts `draft-sweeney-wimse-credential-delegation-02` and `draft-asor-wimse-agent-delegation-chain-03`: both drafts state monotonic attenuation, monotonic expiry, bounded depth, an unchanged principal and deny on unknown constraint types, and both treat the nested `act` claim as attribution only. toolgate enforces the same invariants and uses `act` the same way; where the Asor draft links hops with a hash of the parent token (`par_hash`), toolgate carries ancestor token ids (`chain`).
- **Macaroons** (Birgisson et al., NDSS 2014) and **Biscuit** (github.com/biscuit-auth/biscuit): tokens whose holder can only add restrictions. toolgate's offline chains are an HMAC construction in the macaroon style and an Ed25519 block chain in the Biscuit style, with a much smaller caveat language and no Datalog.
- **CaMeL**, "Defeating Prompt Injections by Design" (Debenedetti et al., arXiv 2503.18813): a privileged model writes the plan from the user's request, a quarantined model parses untrusted data, and a custom interpreter tracks data and control-flow dependencies and checks policies at tool calls. toolgate borrows the plan-then-execute shape but enforces at the tool boundary, sees only tool calls and the references they carry, and does not claim CaMeL's guarantees.
- **Cedar** (AWS) and **Open Policy Agent** are general policy languages and engines; toolgate's policy is a small YAML rule language with three-valued matching. A Cedar or OPA backend was a stretch goal and is not built.
- **Zanzibar** (Google, 2019) is relationship-based access control at global scale. toolgate has no relationship graph and runs on a single node; the contrast is the point: it authorizes individual tool calls and arguments for one delegation chain.

## Project layout

```
src/toolgate/
  constraints.py   the five argument operators: eq, in, max, glob, any
  capability.py    Call, Capability, Grant and the closed-world allows(call)
  attenuation.py   check_attenuation: sound, deliberately incomplete
  smt.py           Z3 model of the constraint language
  proofs.py        solver lemmas, wrong variants and premise checks
  tokens.py        Ed25519 JWTs: mint, verify, exchange, revoke, authorize
  store.py         revocations and the atomic budget ledger (memory, SQLite)
  chain.py         offline attenuation: HMAC chain and Ed25519 block chain
  policy.py        YAML operator policy, three-valued matching
  audit.py         hash-chained JSON Lines log, verify command
  gateway.py       the decision pipeline (handle_call)
  approvals.py     approval queue bound to the exact request
  server.py        FastAPI front: tokens, calls, approvals, audit
  mcp_proxy.py     MCP proxy: filtered tools/list, every tools/call through the gateway
  canonical.py     per-tool argument canonicalization
  provenance.py    session labels, value labels and handles
  plan.py          plan-then-execute executor
  dashboard.py     admin dashboard (off by default)
  sandbox/         world, 26 tasks, scripted agents, planner, runner
scripts/           every results file and figure, plus reproduce_all.sh
config/            example gateway config and policy, sandbox grants and policies
examples/          a small real MCP server to put behind the proxy
docs/              PLAN.md (design and decision log), DEPLOYMENT.md
results/ assets/   saved outputs and figures
```

## Status

All milestones in [docs/PLAN.md](docs/PLAN.md) are built, and the agent evaluation (M5) was run with scripted agents only. The evaluation with a real language model that M5 originally called for has not been run, so nothing here says how often a real model is hijacked or how a real model performs with the gateway in front of it. The repository is private until the owner decides to publish it.
