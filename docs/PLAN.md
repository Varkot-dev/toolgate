# toolgate: plan

An authorization gateway for LLM agents.

## 1. The problem

An agent that can call tools usually holds one broad, long-lived credential, such as an API key or a user's OAuth token. That creates three risks:

1. **The agent acts on text it should only read.** A document or tool result can contain instructions, and the agent may carry them out with the user's authority. In security terms this is a confused deputy.
2. **Standing access is far wider than the task.** The task needs "read one calendar"; the credential allows everything, indefinitely.
3. **Delegation has no limits.** An orchestrator passes its full credential to every sub-agent.

Afterwards, nobody can reconstruct who authorized what.

The principle behind this project: the model does not decide what it is allowed to do. A separate component outside the model checks every tool call against an explicit grant. This is ordinary least-privilege access control applied to agents.

## 2. What exists today (verify before building)

**MCP authorization.** The Model Context Protocol's authorization spec is based on OAuth 2.1. The current revision in late 2026 is 2026-07-28. An MCP server acts as an OAuth 2.1 resource server: it validates tokens and does not issue them. Servers publish Protected Resource Metadata (RFC 9728), and clients send the `resource` parameter (RFC 8707) so each token is bound to one server. Spec: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization

**OAuth building blocks to know.**
- Token Exchange (RFC 8693), including the nested `act` claim that records who is acting for whom
- DPoP proof of possession (RFC 9449)
- Rich Authorization Requests (RFC 9396)
- JWT access tokens (RFC 9068)

**IETF drafts on agent authorization (2026, all still drafts).**
- Agent Authorization Profile for OAuth 2.0 (draft-aap-oauth-profile)
- OAuth 2.0 Extension: On-Behalf-Of User Authorization for AI Agents
- Credential Delegation Protocol for AI Agents (draft-sweeney-wimse-credential-delegation), which combines RFC 8693, 9449 and 9396
- Verifiable Attenuated Delegation for AI Agent Chains (draft-asor-wimse-agent-delegation-chain)

Read at least the last two. The delegation design here should be explainable in their vocabulary.

**Capability tokens.** Macaroons (Birgisson and coauthors at Google, NDSS 2014) are tokens whose holder can add restrictions that only narrow them. Biscuit is a public-key successor. The attenuation idea in this project comes from that line of work.

**Policy engines.** Cedar (AWS) and Open Policy Agent. Google's Zanzibar paper (2019) describes relationship-based access control at scale and is a useful contrast.

**Information-flow control for agents.** "Defeating Prompt Injections by Design" (Debenedetti and coauthors, Google and Google DeepMind with ETH Zurich, arXiv 2503.18813), known as CaMeL. A privileged model sees only the user's request and writes the plan as code; a separate quarantined model with no tool access parses untrusted content; a custom interpreter attaches metadata ("capabilities") to every value recording where it came from and who may receive it, and security policies are checked when tools are called. Code: github.com/google-research/camel-prompt-injection. Section 3.7 builds a smaller version of this idea into the gateway.

**The gap this project fills.** MCP authorization covers how a client obtains a token for a server. It says little about limits on individual calls and arguments ("may send email, only to this domain, at most 3 per task"), about narrowing authority down a chain of sub-agents, or about human approval. That is what to build.

## 3. Design

```
agent ── tool call + token ──▶ GATEWAY ──▶ real tool or MCP server
                                 │
          ┌──────────────────────┼───────────────────────┐
     verify token          policy decision            audit log
  (signature, expiry,     allow / deny / needs      (hash chained,
   audience, revocation)    human approval           every decision)
```

### 3.1 Capabilities
A capability is a tool name plus constraints on its arguments. The constraint language is deliberately small and closed:

| operator | meaning |
|---|---|
| `eq` | argument equals a value |
| `in` | argument is in an allow-list |
| `max` | numeric argument is at most a ceiling |
| `glob` | string argument matches a pattern |
| `max_calls` | budget on number of calls |

A grant is a set of capabilities, an expiry time and the delegation chain.

**Fail closed:** unknown tool, missing argument or unknown operator means deny.

### 3.2 The core algorithm: attenuation
When an agent requests a weaker token for a sub-agent, the gateway must show that the child grant allows nothing the parent does not. "Child constraint is at least as strict as parent constraint" is defined case by case:

| parent | child is accepted when |
|---|---|
| `eq a` | child is `eq a` |
| `in S` | child is `eq a` with a in S, or `in T` with T a subset of S |
| `max m` | child is `max n` with n <= m, or `eq`/`in` with every value <= m |
| `glob g` | child is `eq`/`in` with every value matching g, or the identical pattern, or a pattern that extends a literal prefix (parent `reports/*`, child `reports/q3/*`) |

Added in M0b after measuring the gap (see the decision log): a child `glob` whose pattern has no `*` accepts exactly one string, so it is checked like `eq` of that string against any parent.

- A child capability is covered if, for every parent constraint, some child constraint on the same argument is at least as strict.
- A child grant is valid if every one of its capabilities is covered by some parent capability and the child's expiry is no later than the parent's.

The check is **sound but not complete**. It never accepts an escalation, but it rejects some safe requests: general pattern containment is hard to decide, and a child covered only by the combination of two parent capabilities is rejected. For a security check that is the right trade, and explaining why is the strongest interview material in this project.

**How to test it.** Property-based testing with Hypothesis: generate random parent grants, random accepted child grants and random calls, then assert that every call the child allows is also allowed by the parent. That single property is the security invariant of the whole system.

### 3.3 Tokens
JWTs signed with Ed25519.
- Claims: `iss`, `aud` (the one gateway or tool server the token is for), `sub` (the user), `act` (actor chain in the RFC 8693 style), `exp` (minutes, not days), `jti`, `caps`, `chain` (ancestor token ids).
- Revocation: revoking any ancestor invalidates every descendant.
- A depth limit on delegation.
- Later milestone: DPoP-style key binding, so a copied token is useless without the holder's private key.

### 3.4 Policy and human approval
Operator policy sits above grants. A grant says what the user delegated; policy says what the organization permits. Rules are YAML with effects `allow`, `deny` and `approve`. Deny beats approve, approve beats allow, and the default is deny. `approve` holds the call in a queue until a person accepts or rejects it, and that decision is logged with who made it.

### 3.5 Audit log
Append-only. Each entry stores a hash of the previous entry, so changing or removing any record breaks the chain, and a `verify` command reports the first bad entry. Each entry holds the time, token id, actor chain, tool, a hash of the arguments, the decision and the rule that fired.

Know the limit: a hash chain shows that records were altered, but someone with full write access could rebuild the entire chain. The remedy is to publish the latest hash somewhere external. Describe this in the README and implement it as a stretch goal.

### 3.6 MCP proxy mode
The gateway runs in front of an MCP server. It reduces `tools/list` to what the token allows, so the agent never sees tools it cannot use, and it enforces on `tools/call`.

### 3.7 Provenance: permissions that depend on where data came from
Sections 3.1 to 3.6 ask "may this agent call this tool with these arguments?" This section adds "where did these arguments come from?"

Build it in two levels.

**Level 1, session labels (coarse).** Every tool is marked as returning trusted or untrusted content (a web fetch or an inbox read is untrusted). Once a session has read untrusted content, the session is labeled, and policy can require approval for sensitive tools in a labeled session. Simple and conservative, but it flags a lot.

**Level 2, value labels (precise).**
- The gateway keeps tool results and gives the agent a handle for each one. Each stored value carries a label: its sources (user, a named tool, untrusted) and its allowed readers.
- A tool argument is either a literal written by the model or a reference to a handle. References have known provenance. Literals written after the session read untrusted content are treated as untrusted.
- Derived values take the union of their inputs' sources. Combining a trusted and an untrusted value gives an untrusted value.
- Two new policy conditions: `source_in` (the argument's sources must all be in a set) and `readers_include` (the destination must be an allowed reader of the data being sent). Example rule: `send_email.to` must come from the user or the contacts tool; the body may only contain data whose readers include the recipient.
- Plan-then-execute mode, following CaMeL: one model call sees only the user's request and produces a short plan in a restricted format; steps that parse untrusted content run in a separate call with no tools; the gateway executes the plan and tracks labels through it.

Things to be able to explain:
- Why this is stronger than argument constraints alone: it blocks misuse that stays inside the allowed arguments.
- Label creep: conservative propagation labels more and more values untrusted until everything needs approval. Measure it and show the usability cost.
- What it cannot see: information that leaks through which branch was taken or whether a call happened at all (implicit flows).
- How it differs from CaMeL: CaMeL enforces this in an interpreter around the model; this project enforces it at the tool boundary. State the trade-offs and do not claim CaMeL's guarantees.

### 3.8 Offline attenuation with chained signatures
In section 3.3 an agent asks the gateway for a weaker token. Here the agent narrows a token by itself, with no network call, and nobody can widen one.

**Construction 1, macaroon style (HMAC).**
- The gateway holds a root key. It issues a token with an identifier and signature **sig0 = HMAC(root_key, identifier)**.
- To add a restriction c1, the holder computes **sig1 = HMAC(sig0, c1)**, appends c1 and replaces sig0 with sig1. Each further restriction chains the same way.
- The gateway verifies by recomputing the chain from its root key and comparing the final signature, then checks that every restriction holds for the call.
- Why a holder cannot remove a restriction: removing c1 requires sig0, and the holder of the narrowed token only has sig1. HMAC cannot be run backwards.

**Construction 2, public-key chain (Biscuit style).** HMAC tokens can only be verified by whoever holds the root key. Replace each step with an Ed25519 signature: each block is signed by the previous block's private key and names a fresh public key for the next block. Anyone with the root public key can verify. Implement Construction 1 first.

**The point to notice.** Restrictions are only ever added and all must hold, so every derived token is weaker by construction. The online exchange in 3.2 needs a subsumption check because the child grant is written fresh; the offline chain needs none. Explaining why the two designs differ here is strong material.

Limits to state: these are bearer tokens, so theft still matters and proof of possession still applies; revocation needs a lookup, which removes part of the offline benefit; long chains grow the token.

### 3.9 Proving the attenuation check with an SMT solver
Property tests in M0 sample the input space. This milestone has a solver search all of it.

- Model each constraint operator as a formula over a symbolic argument value in Z3 (integers and reals for `max`, finite sets for `in`, Z3's string theory for prefix patterns).
- For each row of the table in 3.2, ask: does there exist an argument that the child constraint accepts and the parent rejects, given the row's side condition? An answer of unsatisfiable means that rule can never permit an escalation.
- Then the reverse question for completeness: use the solver to find child constraints that are truly safe but that the checker rejects. Count them to measure how incomplete the checker is, and decide whether any rule is worth extending.
- Differential testing: generate random pairs, compare the Python checker's answer with the solver's. Any case where the checker accepts and the solver finds a counterexample is a security bug.

Be precise about the claim: the solver proves the rules as modeled. The Python implementation is tied to that model by the differential tests, not by proof. General glob patterns stay outside the proven fragment; say so.

## 4. Milestones

| # | Milestone | Done when |
|---|---|---|
| M0 (done 2026-11-17) | Capability model: constraints, capabilities, grants, `allows(call)`, attenuation check | Hypothesis property tests pass on 10,000+ generated cases; every row of the attenuation table has a unit test |
| M0b (done 2026-11-17) | Solver verification of the attenuation rules (section 3.9) with Z3, plus differential tests against the Python checker | Every table row returns unsatisfiable for the escalation query; the completeness gap is measured and reported |
| M1 (done 2026-11-17) | Tokens: mint, verify, exchange, revoke with ancestor chain, depth limit | Tests cover expired, wrong audience, bad signature, revoked ancestor and an attempted escalation |
| M1b (done 2026-11-17) | Offline attenuation (section 3.8): HMAC chain first, then the Ed25519 chain | Tests show a holder can add a restriction offline, cannot remove one, and a modified chain fails verification |
| M2 (done 2026-11-17) | Policy engine and hash-chained audit log with `verify` | Editing any log line is detected at the correct index |
| M3 (done 2026-11-17) | Gateway service (FastAPI): `/token`, `/token/exchange`, `/call`, `/approvals`, `/audit/verify` | An end-to-end test drives a scripted client through allow, deny and approve |
| M4 (done 2026-11-17) | MCP proxy mode in front of a simple real MCP server, following the current spec | An MCP client connected through the gateway sees and can call only permitted tools |
| M4b (done 2026-11-17) | Provenance (section 3.7): session labels, then value labels with handles, then plan-then-execute mode | Tests show labels propagate correctly through derived values; label creep is measured on the sandbox tasks |
| M5 (scripted half done 2026-11-17; one real-model pass per model done 2026-11-18) | Agent demo: a Gemini or local model with email, calendar and file tools in a sandbox, run with and without the gateway | A results table produced by a script comparing four configurations (no gateway, argument constraints only, plus session labels, plus value labels): unintended tool calls, normal tasks still completed, and approvals requested |
| M6 (done 2026-11-17) | Measurement and polish: added latency per call (p50, p99), throughput, README, demo recording | README complete, repo ready to make public |

Order of work: M0, M0b, M1, M1b, M2, M3, M4, M4b, M5, M6. The project is worth showing from M3 onward; each later milestone adds a distinct talking point.

Stretch: DPoP binding; external anchoring of the audit log head; Cedar or OPA as an alternative policy backend; suggesting least-privilege grants from audit logs.

## 5. What the README will report
1. **Security invariant:** number of property-test cases with zero violations, and the solver result for each attenuation rule.
2. **Protection:** unintended tool calls with and without the gateway on the sandbox scenarios.
3. **Usefulness:** normal tasks still completed with the gateway on. A gateway that blocks everything is worthless.
4. **Cost:** latency added per tool call, and how many approvals each configuration asks a person for.

## 6. Visuals
- **Hero:** an animated diagram of one tool call passing through the gateway, being denied, and the audit entry appearing.
- **Delegation tree:** an orchestrator and its sub-agents, each node showing its shrinking set of capabilities.
- **Dashboard:** live decision feed, approval queue, and the audit chain with a "change this entry" button that makes verification fail visibly.
- **Provenance graph:** for one task, every value as a node colored by source, with the blocked call highlighted.
- **Token chain:** a token gaining restrictions step by step, with the signature changing at each step and a failed attempt to drop one.
- **Charts:** protection vs approvals requested across the four configurations; unintended calls with and without the gateway; latency histogram.

## 7. Stack
Python, Z3 (`z3-solver`), FastAPI, PyJWT with `cryptography` (Ed25519), Pydantic, SQLite, PyYAML, Hypothesis, pytest. The official MCP Python SDK for M4. Dashboard as one static page with HTMX, or a small React app.

## 8. Questions you should be able to answer
1. What is a confused deputy, and how does an agent become one?
2. Why may the attenuation check be incomplete but never unsound?
3. Why use short-lived tokens and revocation together?
4. What does the `aud` claim prevent? What does DPoP add?
5. Authentication vs authorization, in this system specifically.
6. Why does a hash chain reveal tampering, and what does it not protect against?
7. Why filter `tools/list` as well as enforcing on `tools/call`?
8. How does this differ from macaroons, from OAuth scopes and from Zanzibar?
9. What can this gateway not prevent? (An allowed tool used badly within its constraints; approval fatigue.)
10. How would you scale it to thousands of calls per second?
11. What does provenance tracking stop that argument constraints cannot?
12. What is label creep, and how did you measure its cost?
13. What is an implicit flow, and why does this design not catch it?
14. How does your design differ from CaMeL, and what guarantee does CaMeL have that yours does not?
15. Walk through the HMAC chain. Why can a holder add a restriction but not remove one?
16. Why does the offline chain need no subsumption check while the online exchange does?
17. Why move from HMAC to a public-key chain?
18. What exactly did the solver prove, and what is still only tested?
19. Soundness vs completeness: which did you prove, which did you measure, and why that way round?

## Decision log

### 2026-11-17, M0

1. **Closed-world arguments, and a fifth operator `any`.** The plan's rule was "missing argument means deny" and said nothing about arguments the capability does not mention. Leaving those unrestricted is a hole: a capability that constrains `send_email.to` would wave through a `bcc` nobody thought about. So a call is allowed only if every argument it carries is named by at least one constraint, and every constraint holds. To let an argument through with any value, the grant must say so explicitly with `any`. Consequence for attenuation: parent and child capability must constrain exactly the same set of argument names.
2. **Glob has one special character.** Only `*` is special; it matches any run of characters including `/` and the empty string. No `?`, no character classes, no escapes. The plan's own example (parent `reports/*` accepts child `reports/q3/*`) is only sound if `*` crosses `/`. Python's `fnmatch` was not used because it brings `?` and `[...]`, which would enlarge what M0b has to model. Limit to state in the README: this is string matching, not path matching, so `reports/../x` matches `reports/*`; tools that take paths must canonicalize before the gateway sees the argument.
3. **Typed equality.** `eq` and `in` do not use Python's `==`, where `True == 1`. A bool only equals a bool, a string only a string, numbers compare by value (3 equals 3.0), and NaN, None, lists and dicts equal nothing.
4. **Finite children are checked by enumeration.** When the child constraint is `eq` or `in` it accepts a finite list of values, so the checker tests each value against the parent's own predicate. This one rule covers the `eq`/`in` cases of every row of the 3.2 table and cannot drift from what `allows` does, because it calls the same code.
5. **The glob prefix rule, stated exactly.** Parent must be `P*` with P containing no `*`; the child is accepted if the text before its first `*` starts with P. Any other pair of distinct patterns is rejected, including safe ones. M0b measures that gap.
6. **`max_calls` is a field of a capability, not an argument constraint, and M0 only compares budgets.** The attenuation check requires child budget <= parent budget and returns a `derivation` (which parent capability covers each child capability). Counting calls is state, and it is only correct if a child's call is also charged to every ancestor along that derivation; otherwise two children each given the parent's full budget could spend it twice. That ledger belongs with tokens in M1. So the M0 invariant is about single calls, and budgets are covered by a separate monotonicity property.
7. **The delegation chain lives in the token (M1), not in `Grant`.** A grant in M0 is capabilities plus expiry.
8. **Core has no dependencies.** Frozen dataclasses, not Pydantic, for the capability model, so the trusted core stays small. Pydantic comes in at the HTTP boundary in M3.

### 2026-11-17, reference check of section 2

Checked against upstream sources. The session's network could not reach modelcontextprotocol.io, datatracker.ietf.org, rfc-editor.org or arxiv.org, so the MCP spec, the two WIMSE drafts, Biscuit and CaMeL were read from their GitHub sources and package versions from PyPI; RFC numbers and drafts (a) and (b) rest on search results only and should be rechecked on the primary pages.

1. **MCP authorization (affects M4).** Latest revision is still 2026-07-28 and the plan's statements hold (OAuth 2.1, server is a resource server, RFC 9728 required, RFC 8707 `resource` required, no token passthrough). Authorization is now a group of four pages, not one. New in 2026-07-28: `iss` validation (RFC 9207), Dynamic Client Registration deprecated in favour of Client ID Metadata Documents. More important for a proxy: the protocol is now stateless, with no `initialize` handshake and no `Mcp-Session-Id`, and `Mcp-Method` and `Mcp-Name` headers are required. M4 must be designed against that, and section 3.7's "session" labels need their own session notion from the gateway (the token id is the natural key), since MCP no longer supplies one.
2. **MCP Python SDK (affects M4).** `mcp` 2.x is a breaking release: `FastMCP` is now `MCPServer`, types moved to `mcp-types`, `streamablehttp_client` was removed, transport parameters moved to `run()`. Follow the migration guide when M4 starts; do not write against v1 examples.
3. **Z3 (affects M0b).** `z3-solver` is on the 5.x line (5.4.1.0). Recheck the string-theory and integer API against current docs before writing M0b.
4. **PyJWT (affects M1).** 2.15.1 supports EdDSA with Ed25519 through the `pyjwt[crypto]` extra.
5. **Drafts.** `draft-sweeney-wimse-credential-delegation` is at -02 (2026-10-30) and `draft-asor-wimse-agent-delegation-chain` at -03 (2026-10-27). `draft-aap-oauth-profile-01` and `draft-oauth-ai-agents-on-behalf-of-user-02` appear to have expired without a newer revision. Vocabulary worth adopting: both WIMSE drafts state the same invariants this project enforces (monotonic attenuation, monotonic expiry, bounded depth, the principal `sub` unchanged at every hop, unknown constraint types deny), and both say the nested `act` claim is attribution history only, never a source of authority. The Asor draft links each hop with a hash of the parent token (`par_hash`), which is worth comparing with the `chain` claim in M1.

### 2026-11-17, M0 review findings and working-rule change

1. **Exact builtin types only.** An independent adversarial review broke the first version of the check with Python subclasses: a `str` subclass whose `__eq__` always returns True, used as a child `eq` value, was accepted and then allowed every value. Same idea for tool names, expiry (`float` subclass) and `max` (`int` subclass). The logic was right; the assumption that the input's own comparison methods could be trusted was wrong. Now every value, name, expiry and budget must be an exact builtin type, checked with `type(v) is ...`, never `isinstance`.
2. **`Call` owns a read-only plain copy of its arguments.** A dict subclass could show the checker one set of keys and the tool another, and the caller could change the dict between the check and the use. `Call` now deep-copies its arguments into builtin types and rejects anything that is not plain JSON data. The gateway (M3) must forward this copy, not the caller's object.
3. **Other fixes from the review.** A 400-digit integer crashed the check (`math.isfinite` overflows on huge ints); expiry and `now` must be finite; `in` accepts lists and tuples only, since set order is not fixed.
4. **Carried forward to M1 from the review.** (a) JSON with duplicate keys silently keeps the last one, so the token parser must reject duplicate keys. (b) Frozen dataclasses can still be mutated with `object.__setattr__`, so a grant is only trusted after being rebuilt from verified signed bytes, never as a live object handed in by a caller. (c) The budget ledger must charge the child capability and then follow the recorded `derivation` up the chain; it must not re-run `parent.decide`, which can pick a different capability than the derivation did.
5. **Review questions moved to the end.** At the owner's request on 2026-11-17, the per-milestone review questions in the owner's study plan (CLAUDE.md, using the list in section 8) are deferred: they are all worked through once, after the final milestone. Teaching at the start of each milestone is unchanged.
6. **The property test was itself tested.** Eleven deliberately broken copies of the check are searched for counterexamples by the same strategies; all eleven are caught. Three survived the first version of the strategies, which is why generated faulty children now carry exactly one fault each.
7. **Milestones built in parallel.** At the owner's request on 2026-11-17, M1, M1b and M2 are built in parallel as separate work streams on disjoint files, because they are independent modules on top of the finished M0 core. Each is still reviewed, tested and merged in plan order, and each still has to meet its own "done when" line. This replaces rule 1 of CLAUDE.md ("one milestone at a time") for milestones with no dependency on each other; M3 onward depends on all three and waits for them.

### 2026-11-17, M0b (solver verification)

1. **What was proven.** 19 lemmas, one or more per rule the checker uses, each asked symbolically (over all parameters, not for examples): "given the rule's side condition, is there a value the child accepts and the parent rejects?" Every answer is unsat. The enumeration rule is proven once for an arbitrary parent predicate (an uninterpreted function), which covers every "child is eq/in" cell of the table together. Bounds, stated honestly: the glob prefix lemma is checked for 0 to 4 child stars plus an unbounded pair of lemmas (a match starts with the head; prefix is transitive); capability composition is for 3 argument names and up to 3 constraints per side; the glob-to-regex link is checked for concrete patterns only.
2. **Proofs with teeth.** 12 deliberately wrong versions of the rules (max flipped, prefix reversed, intersect in place of subset, and so on) are each sat with a recorded counterexample. Each lemma's premises are also checked to be satisfiable on their own, so no unsat comes from a contradictory side condition.
3. **What ties the proof to the code.** The lemmas are about formulas. The Python checker is tied to them by differential tests: `Constraint.holds` against the model on generated values, `glob_match` against the regex, and "checker accepts implies solver finds no escalation" at constraint and grant level. That link is tested, not proven.
4. **Rationals, not floats.** The model's numbers are all rationals, a superset of what Python can pass. So "no escalation" transfers to the code, but the solver can report an escalation at a number between two adjacent floats that no call can carry. Every witness is replayed through the real code; one that does not replay is reported as inconclusive, never as safe or unsafe.
5. **Solver performance lesson.** Asking "in the child's language and not in the parent's" as two separate membership constraints made Z3 time out on small patterns such as parent `*a`, child `b*a`. Asking it as one membership in the intersection of the child's language with the complement of the parent's returns instantly.
6. **The measured gap, and the one rule it justified.** Over all 15,625 ordered pairs of a 125-constraint universe: accepted and unsafe 0; safe and accepted 648; safe but rejected 576, every one with a glob child. 368 of those had a child pattern with no star. Adding "a star-free glob child is checked like eq" (one line, through the existing enumeration path, with its own lemma) moved the gap to 208 and the accepted-and-safe count to 1,016, still with 0 unsafe. Not added: collapsing repeated stars (would close 115 more, but real grants rarely write `**`), a suffix rule (21) and infix containment, each of which needs its own soundness argument for little gain. These rates describe the enumerated universe, not real workloads.

### 2026-11-17, M1, M1b, M2 (tokens, offline chains, policy and audit)

1. **Budgets are charged along the signed derivation path.** Each token carries, per capability, the index of the capability it derives from in every ancestor (`der`). A call charges its own counter and every ancestor's in one atomic store operation, all or nothing, so siblings share their parent's budget. If the first permitting capability is exhausted the next permitting one is tried, so capability order does not change how much a grant allows.
2. **The store is part of the trust base.** A token the store has never registered is rejected, so losing the store cannot silently un-revoke tokens; revocation is re-checked inside the same transaction as the charge.
3. **PyJWT only checks the signature.** Its expiry check uses the system clock and cannot honour an injected one, so every claim is validated in our code against the signed bytes. The header must be exactly `{"alg":"EdDSA","typ":"JWT"}`; duplicate JSON keys and unknown claims are rejected.
4. **`act` is attribution only.** The nested actor chain is self-declared by whoever exchanges a token. It is recorded in the audit log and never used for a decision. Both WIMSE drafts say the same.
5. **Review-driven hardening of tokens.** No forgery, escalation, budget overrun or revocation escape was found by an independent review (including 16 threads and 6 processes on one store). Fixed from it: a failed COMMIT left the SQLite connection stuck in a transaction; one token could mint unlimited children and bloat the store (now a per-parent fan-out limit and expiry-based pruning); expiry is re-checked after a slow charge; store and clock failures are reported as `unavailable`, not `malformed`; actor names the audit log cannot record are refused at mint.
6. **Offline chains: the proof-of-possession and the seal.** Every prefix of a valid Ed25519 block chain is itself validly signed, so a token must also prove knowledge of the last block's private key, either by carrying it (attenuable) or by a seal signature made with it (final). Review finding: OpenSSL accepts small-order Ed25519 public keys, under which a fixed signature verifies for any message, so a block naming such a key would let anyone strip later caveats. Small-order keys are now rejected everywhere a key enters verification.
7. **Policy matching is three-valued.** A condition is true, false or unknown (argument missing or of a type the operator cannot compare). An allow rule needs every condition proven true; a deny or approve rule matches unless a condition is proven false. So a deny rule cannot be dodged by omitting or mistyping an argument, at the cost of over-blocking. An `unless` key was added because, with deny over approve over allow and no negation, "allow internal mail, approve external" cannot be written.
8. **Audit log format.** JSON Lines, one canonical-JSON entry per line, `time` in integer nanoseconds so the chain contains no floats, arguments stored only as a hash. Editing entry i without recomputing hashes is reported at i; editing and recomputing is reported at i+1, and for the last entry or a full rebuild only a trusted copy of the head (or a checkpoint) reveals it.
9. **Review-driven fixes of policy and audit.** A policy file over the size limit with multibyte characters could be read partially and still parse, dropping trailing rules (the size check now runs on bytes before decoding); unquoted number-like scalars must be quoted; a forked process or an interrupt between write and head update could make the writer produce a log its own verifier rejects (both closed).

### 2026-11-17, M3 (gateway service)

1. **One framework-free pipeline.** `Gateway.handle_call` owns the whole decision, in this order: build the canonical `Call`; verify the token and check the grant without charging; policy; charge the budget along the delegation path; write the audit entry; re-verify the token; run the tool on the canonical copy. The HTTP server and the MCP proxy are thin adapters over it, so there is one place where the rules live.
2. **Audit before action, and refunds before action.** If the audit write fails, the tool does not run; an unaudited action is worse than a refused one. A call that is charged but never reaches the tool (audit failure, clock fault, revocation landing during the audit write) is refunded. A call whose tool started is never refunded, because the side effect may already have happened.
3. **Approvals bind to the exact request.** An approval stores the canonical call and a hash of (token id, tool, argument hash). Approving re-runs every check on the stored call with a fresh clock, so a token revoked, expired or out of budget while waiting, or a policy changed to deny, still stops it. There is no way to edit a pending call. This idea was borrowed from an approval-loop pattern in a public Claude Code collection (affaan-m/everything-claude-code, `skills/operator-approval-loop`); nothing from that repository was installed.
4. **Caller text never reaches the log.** Grant denials are logged as fixed codes (`grant: argument_not_permitted`), not as the human reason, which quotes the caller's tool and argument names. Tool names are logged only if they pass a safe-name filter. The agent's own HTTP response keeps the readable reason.
5. **Availability is part of security.** Found by review and fixed: one agent could fill the global approval queue through exchanged children (caps are now per root token and per subject too); 400 slow calls from one token delayed an admin revoke by 29 seconds (admin endpoints now have their own worker pool, and in-flight tools per root token are capped); unauthenticated callers could force 458 fsynced audit entries per second (entries for unverified tokens are now rate-limited, with a summary entry recording how many were suppressed, so nothing is silently lost).
6. **What a reverse proxy must still do** is written down in docs/DEPLOYMENT.md: TLS, slow-client timeouts and connection limits; no path-based ACLs (percent-encoded paths route normally).
7. **Tool error text is hidden from agents** in the deployed configuration, since a real tool's exception message can carry paths or connection strings.
8. **Known limits.** One shared admin key, and the approver's name is self-declared. A tool that times out keeps running in its thread, because Python threads cannot be killed.

### 2026-11-17, process notes

1. **Usage limit mid-run.** Two of the parallel work streams stopped partway when a usage limit was reached. Their work was in the tree; a follow-up pass audited it against the original brief and finished it. No work was redone from scratch.
2. **CI went red twice** when commits from concurrently edited files were pushed in an order where one depended on another not yet pushed. Rule since then: run the full suite before every push and push related commits together.

### 2026-11-17, M4 (MCP proxy)

1. **Built against the current spec and SDK, not the plan's assumptions.** MCP 2026-07-28 is stateless (no `initialize`, no session id) and the Python SDK 2.x renamed and restructured its API (`MCPServer`, low-level `Server(on_list_tools=..., on_call_tool=...)`, types in `mcp-types`, `httpx2`). The proxy is a low-level server whose handlers call `Gateway.handle_call`, so the decision rules live in one place for HTTP and MCP alike.
2. **Visibility rule.** A tool appears in `tools/list` only if the grant names it exactly and policy does not deny every call to it; a tool the grant does not name is never shown. Lists are marked `cacheScope: private`, which the spec permits when a list varies by the authorization presented. A call to a tool the caller cannot see gets the same "Unknown tool" error as a tool that does not exist, so its existence is not revealed.
3. **No token passthrough.** The caller's token is checked by the proxy and never sent upstream, as the spec requires; a test records every upstream header and asserts the token never appears.
4. **Deny by default for everything that is not tools.** Resources, prompts, sampling, subscriptions and the legacy `initialize` handshake are refused, because the gateway has no rules for them yet.
5. **Found while finishing: the SDK client retries on its own.** When the upstream answers "input required" or reports a header mismatch, the SDK client re-sends the call. One allow decision and one budget charge produced 11 upstream calls. The proxy now forwards through the raw session, so one decision is at most one upstream call. Lesson: an authorization layer must control retries below it, or one approval silently becomes many actions.

### 2026-11-17, M5 sandbox (scripted half) and M4b (provenance)

1. **Scripted agents first, on purpose.** The test bed is a model-free sandbox: an in-memory world (inbox, contacts, calendar, files, canned web pages) whose tools record every side effect, 26 hand-written tasks (8 benign, 18 attacks in five classes) with ground-truth checks, and scripted agents: an honest one, a hijacked one that obeys injected instructions and retries twice when denied, and two human approver models, careful (an oracle that approves only the legitimate plan) and rubber-stamp. Results are exactly reproducible. Every result file says "scripted agents, not a language model". Whether to add a real model run depends on the owner providing an API key (done on 2026-11-18; see the entry for that date).
2. **Each attack must work without a defence.** A test asserts every attack succeeds with no gateway, so no number measures an attack that could never have worked.
3. **Canonicalize before deciding.** The sandbox showed `reports/../secrets/api_key.txt` passing a `reports/*` grant, because matching is on the raw string and the file tool resolves `..` afterwards. Arguments are now canonicalized per tool before any decision, and anything ambiguous is refused rather than repaired; the decision and the execution both use the canonical form.
4. **Session labels (level 1).** A session, keyed by token id since MCP no longer has sessions, is marked tainted once any untrusted result has been returned. Policy can require approval for sensitive tools in a tainted session. Simple and strong, and it makes almost every later step need approval: from step 3 on, 100% of values in a session are untrusted.
5. **Value labels (level 2).** Tool results are stored by the gateway and the agent gets handles. A label is a set of sources and a set of allowed readers; deriving a value takes the union of sources and the intersection of readers. A literal written by the agent after the session read untrusted content is untrusted, which is sound against the agent copying data into its own text and is the main cause of label creep. Initial labels come from per-tool declarations (for example a calendar entry is readable by its attendees; a web page is public but untrusted). New policy conditions `source_in` and `readers_include`; a value with no label is UNKNOWN, so it blocks allows and triggers restrictive rules.
6. **Plan-then-execute (scripted).** A planner sees only the user's request and writes the plan; a quarantined extractor with no tools parses untrusted content and can only return a labeled value. An injection can change an extracted value, never which tools run. What remains are data-only attacks: a fooled extractor fills a text slot with the attacker's words.
7. **Results (scripted agents; attacks that succeeded out of those attempted; careful approver).** No gateway 18/18; grant only 10/18; grant plus policy 4/18; plus session labels 0/18; plus value labels 0/17; plan-then-execute 0/18. Benign tasks completed 8/8 in every configuration. With a rubber-stamp approver: 9, 8, 7 and 4 respectively for the last four. Approvals requested by honest runs in total: 8 with policy only, 27 with session labels, 19 with value labels, 15 with plan-then-execute. The defence is only as good as the person approving, and stronger tracking costs more approvals; that trade is the point of the label-creep figure.
8. **What this does not do.** No implicit-flow tracking (information leaking through which branch ran or whether a call happened); labels are per tool result, not per field; writing untrusted text to a file and reading it back can launder its label; value labels assume an agent runtime that passes handles. This enforces at the tool boundary; CaMeL enforces inside an interpreter that also tracks control-flow dependencies, and none of CaMeL's guarantees are claimed here.

### 2026-11-17, dashboard

One admin-only page, off by default. A browser signs in with the admin key once and gets a short-lived HttpOnly, SameSite=Strict session cookie (only its hash is stored); every state change needs a per-session CSRF token; the page sends a Content-Security-Policy with no inline script and vendors nothing from a CDN, because an admin page must not load third-party code. The "change this entry" demo never touches the real log: it edits a temporary copy, runs the real verifier on it, and shows the break next to the untouched log verifying ok.

### 2026-11-17, verify once per call

1. **Measured, then changed.** The first benchmark showed an allowed call verifying the token's Ed25519 signature three times (decision, charge, and the check just before the tool runs), which was most of the CPU cost. The later checks exist so that a revocation or expiry landing mid-call is seen, but only revocation and expiry can change; a token string's signature and claims cannot. The gateway now verifies once and later calls `Authority.recheck`, which reads the clock afresh and checks revocation of the token and every ancestor in one store call.
2. **Why a forged record cannot pass the cheap check.** `recheck`, `authorize` and `refund` accept only the exact record objects that this Authority's `verify` produced (tracked by a weak reference plus a private copy of the verified fields, compared by identity). A hand-built record, a copy, another Authority's record, or a record bent with `object.__setattr__` is refused.
3. **A small cache of signature-checked parses**, keyed by the exact token string. Revocation, registration and expiry are never cached; a revoked token is refused on the very next call.
4. **Tool error text hidden by default.** `Gateway(tool_error_detail=False)` is now the default, matching the deployed server.
5. **Benchmark honesty.** The cache makes repeated calls with one token much cheaper than a first call, so latency is reported separately for a reused token (warm) and a fresh token every call (cold). The first published figure (median 1.19 ms added per call) predates this change.

### 2026-11-17, provenance review follow-up

1. **Structure is data, selection is control flow.** A value the agent assembles from several handles (a list, or a concatenation) now carries the agent's literal label, because the arrangement itself can spell out new data: two clean handles concatenated can spell an attacker's address. Which handle or field the agent picks is deliberately not labeled: that choice is control flow, it can be made just as easily by picking a different handle or by steering a lookup query, and labeling every choice would turn value labels back into session labels. Data protection for a picked field still comes from its readers: it can only go to someone allowed to read it. This is the implicit-flow limit already stated in M4b, made concrete.
2. **Writing a file is sending data.** Data written to a directory is later readable by that directory's readers, so a write that would widen who can read the data now needs approval (a `readers_include` rule on the content, like a recipient check on email). Remaining limit: labels do not travel with files, so untrusted text written to a private folder reads back as trusted.
3. **Canonicalization tightened.** Refused rather than repaired: numeric, hex and short IP hosts, trailing dots, odd ports, escapes that survive one decoding, a trailing slash on paths, and wildcard or source-routing characters in email addresses. Default ports are removed because that is unambiguous.
4. **No results moved.** The sandbox tasks did not exercise these shapes, so the results table is unchanged; two runs remain byte-identical.

### 2026-11-17, M6 (measurement and README)

1. **One script regenerates every number.** `scripts/reproduce_all.sh` runs every results and figure script in order. On the final run every deterministic output was byte-identical to the committed one (only timing fields moved); the latency results and the dashboard screenshots vary by design.
2. **The README cites a file and key for every number**, says "scripted agents" wherever protection numbers appear, reports latency for a reused (warm) and a fresh (cold) token separately, and lists what the system does not do.
3. **Not done: a real-model run of the agent evaluation (M5).** It needs an API key from the owner. Until then the README says plainly that no real model was tested. The repository stays private until the owner publishes it. (Superseded by the 2026-11-18 entry: one real-model pass was run with each of two models.)

### 2026-11-17, real-model evaluation harness

1. **Built, not yet run (run on 2026-11-18, below).** `scripts/m5_real_model_eval.py` lets a real model (default Claude Sonnet 5.5) play the agent in the sandbox for three configurations (no gateway, grant plus policy, plus session labels), one pass over the 26 tasks. It cannot run in the cloud development environment used to build it, which manages its own authentication to the Anthropic API and accepts no user key; the owner runs it with their own key (docs/REAL_MODEL_RUN.md).
2. **An ordinary agent, on purpose.** The system prompt does not mention prompt injection, security or the gateway; denials come back as ordinary tool errors so the model can adapt. A refusal is recorded as an outcome; no fallback model, since switching models mid-run would change what is measured.
3. **Ignored versus stopped.** The new measurement a real model allows: for each attack task, whether the injection was delivered, whether the model ignored it, whether the gateway stopped what it attempted, or whether the attack succeeded. A call counts as attack-driven if it matches an injected step and no legitimate step, carries one of the world's canary strings somewhere the legitimate plan never sends it, or contains attacker-only text. A paraphrased leak without the canary is not detected; that limit is stated.
4. **The careful approver for a real model** approves a parked call only if the legitimate plan has the same tool and the same security-relevant destination (recipient, attendees, canonical path, and the whole URL except the fragment, because data can leave through a query string to an allowed host). It does not read free text, so the right recipient getting the wrong text is not caught; it never looks at the attack check.
5. **Spending is capped in code.** Before each request the worst case (context at the cache-write rate plus the maximum output) is checked against the cap; a run stops cleanly with partial results, and `--resume` continues without paying twice.

### 2026-11-18, real-model runs (M5)

1. **Run locally by the owner, key kept out of files.** The key was stored in the macOS Keychain and passed to the script's environment for one command at a time; it never entered the repository, a `.env` file or the chat. Both results files were checked for the key before committing.
2. **Claude Sonnet 5.5, $0.58: no attack attempted.** It ignored the injection in 17 of 18 attack tasks (one was never delivered), in every configuration. So the run measures only the gateway's cost to a model that is not hijacked, not its protection.
3. **Added Claude Haiku 4.5, and why.** A model that resists every injection cannot show whether the gateway stops one, so the oldest, smallest model on the key was run as well. The current docs say Haiku 4.5 rejects adaptive thinking and the `effort` setting, so `llm_agent.NO_THINKING_MODELS` leaves both out for it (thinking off); its prices ($1 / $5 per million input / output tokens, cache read $0.10, cache write $1.25) were taken from the current pricing table. The results file records thinking as off.
4. **Claude Haiku 4.5, $0.69: two attacks attempted, both stopped with session labels.** `approval-01` (an outsider added to an invite) went through with no gateway and was stopped by the policy's approval rule. `misuse-02` (the Q3 report emailed to an address on the allowed company domain) passed the policy and was stopped only by session labels (`approve-acting-in-tainted-session`). This is the layered design working as intended on one real case, and a count, not a rate.
5. **Open issues found by the runs.** The injection was never delivered in `args-01` and `misuse-03` under Haiku (one task under Sonnet), probably a harness issue. Both models completed 6 of 8 benign tasks with no gateway, so either the utility check is strict or the models leave the plan; not yet investigated. Separately, `test_server_e2e.py::test_missing_wrong_and_tricky_authorization_headers` fails on this machine before and after these changes (an oversized header gets 401, the test expects 400 or 431).
6. **Figure.** `scripts/fig_real_model.py` draws `assets/real_model.png` from the two committed results files only, on the shared chart template, and runs in `reproduce_all.sh` because it calls no model.
