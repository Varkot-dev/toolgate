# Deploying toolgate

This page says what the gateway process enforces by itself, what has to be in
front of it, and the limits that are known and not fixed. It is written for
the HTTP service started with `python -m toolgate.server --config <file>`.

## What the app enforces

- Authentication: admin endpoints compare the SHA-256 of the presented key
  with the configured hash in constant time; agent endpoints verify a signed
  token. The two credentials are never accepted in each other's place.
- Strict requests: one `Authorization` header, JSON bodies only, a hard body
  size limit (`limits.max_body_bytes`), no duplicate keys, no NaN, bounded
  nesting, no unknown fields, no query strings, and no lone surrogates in any
  string (422).
- Per-token limits: budgets, at most `limits.max_in_flight_per_root` tool calls
  running at once under one root token (429 with `Retry-After` past it), a
  tool timeout of `limits.tool_timeout_seconds` (504), and caps on pending
  approvals per token, per root token, per principal and in total.
- uvicorn settings from the config: `server.limit_concurrency` (connections
  and requests in flight; 503 past it) and `server.timeout_keep_alive_seconds`
  (idle keep-alive connections are closed).
- A tool that times out cannot be stopped: a Python thread cannot be killed.
  It may still finish in the background, it keeps its in-flight slot until it
  does, and its budget is not refunded.

## What a reverse proxy must provide

The app does not do these. Put a reverse proxy in front before listening on
anything but loopback.

- TLS. The app speaks plain HTTP. Without TLS every token and the admin key
  cross the network in clear.
- Header and body read timeouts. uvicorn has no request header or body read
  timeout of its own, so a client that sends a request slowly holds a
  connection and counts against `limit_concurrency`. Set both timeouts at the
  proxy, and a total request timeout a little above `tool_timeout_seconds`.
- Connection limits per client address and in total, and a request rate
  limit. The app limits per token, not per address.
- A body size limit no larger than `limits.max_body_bytes`.

Do not rely on path ACLs at the proxy, for example "block /token/revoke from
outside". A percent-encoded path such as `/token/%72evoke` may pass a proxy
rule written for the plain spelling and still be decoded and routed normally
by the app. Admin endpoints are protected by the admin key, not by their
path. If the admin endpoints must not be reachable from a network, run a
second listener on loopback or restrict by source address.

## Binding and files

- `server.host` defaults to `127.0.0.1` (loopback). The server prints a
  warning at startup when it is set to anything else.
- The audit log and the SQLite store file are created with mode 0600. An
  existing store file that group or others can access is refused, as is an
  existing audit log that group or others can write. The audit log path must
  not be a symbolic link; it is not resolved before opening, so the link is
  seen and refused. Run the gateway as its own user and keep its directory
  mode 0700.
- The signing key and the admin key hash come from environment variables,
  never from files in the repo. An all-zero signing key and the hash of an
  empty admin key are refused.
- uvicorn's access log is off by default. When `server.access_log` is true,
  query strings are cut out of each line before it is written.

## Audit log rotation

One process writes one log file, and it holds a lock on it. Each file is its
own hash chain starting at entry 0; nothing links a new file to the old one.

1. Stop the gateway. Do not rotate under a running gateway, and never use
   copy-and-truncate rotation: a truncated log is reported as tampering.
2. Verify the old file and record its last head:
   `python -m toolgate.audit verify <old> --head <hash>`.
3. Move it to the archive, read-only, together with its final head and every
   `--checkpoint SEQ:HASH` value published for it. A checkpoint proves only
   the file it was taken from, so keep each one with its file across
   rotation; losing it loses the proof that the archived prefix was not
   rewritten.
4. Start the gateway on a new, empty path, and publish checkpoints for the
   new file as before.

## Known limits

- There is one admin key, shared by everyone who operates the gateway. The
  log records "by admin", not which person.
- The approver name on `POST /approvals/{id}` is declared by the caller of
  that endpoint. It is checked to be a printable name, not authenticated: any
  holder of the admin key can approve under any name.
- State in the approval queue, the in-flight counters and the unverified-token
  rate limit is in memory and is lost on restart.
