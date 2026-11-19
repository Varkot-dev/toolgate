"""A small, real MCP server to put behind the caveat proxy.

Six tools over an in-memory world (files, an outbox, a calendar), built with
the MCP Python SDK's `MCPServer`. It is canned but stateful: a write shows up
in the next read, a delete removes the file, a sent mail lands in the outbox.
That is what lets the tests assert on the observed absence of a side effect
when a call is refused, not only on the error that came back.

The server also offers one resource and one prompt. The proxy does not
forward those (see caveat.mcp_proxy), and the tests use them to show it.

Expected failures raise `ToolError`, whose message the SDK passes to the
caller as an isError result; any other exception is reported only as
"Error executing tool <name>", with its text kept on the server.

This server has NO authorization of its own. It trusts whoever can reach it,
which is exactly the situation the proxy exists for: run it on a loopback
address or a private network that only the proxy can reach.

Usage:  python examples/mcp_upstream_server.py [--host 127.0.0.1] [--port 8765]
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from starlette.applications import Starlette

SERVER_NAME = "example-upstream"
SERVER_VERSION = "0.1.0"

SEED_FILES: dict[str, str] = {
    "reports/q3.txt": "Q3 revenue was 4.2M, up 8 percent.",
    "reports/q4-draft.txt": "Q4 draft: numbers pending.",
    "notes/todo.txt": "1. ship the proxy\n2. write the README",
    "secrets/payroll.csv": "name,salary\nalice,100\nbob,90",
}
SEED_EVENTS: tuple[dict[str, str], ...] = (
    {"day": "2026-11-18", "title": "Quarterly review"},
    {"day": "2026-11-19", "title": "Dentist"},
    {"day": "2026-11-20", "title": "Review of the audit log design"},
)


@dataclass
class World:
    """Everything the tools can read or change."""

    files: dict[str, str] = field(default_factory=lambda: dict(SEED_FILES))
    outbox: list[dict[str, str]] = field(default_factory=list)
    events: list[dict[str, str]] = field(default_factory=lambda: [dict(e) for e in SEED_EVENTS])
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        """A plain copy of the state, for assertions and demo output."""
        return {
            "files": dict(self.files),
            "outbox": [dict(m) for m in self.outbox],
            "calls": [name for name, _ in self.calls],
        }


def build_server(world: World | None = None) -> tuple[MCPServer, World]:
    """Build the MCP server around `world` (a fresh seeded one by default)."""
    world = world if world is not None else World()
    server = MCPServer(SERVER_NAME, version=SERVER_VERSION, log_level="WARNING")

    @server.tool()
    def read_file(path: str) -> str:
        """Return the contents of one file."""
        world.calls.append(("read_file", {"path": path}))
        if path not in world.files:
            raise ToolError(f"no such file: {path}")
        return world.files[path]

    @server.tool()
    def list_files(path: str = "") -> list[str]:
        """List the files whose path starts with `path`."""
        world.calls.append(("list_files", {"path": path}))
        return sorted(p for p in world.files if p.startswith(path))

    @server.tool()
    def write_file(path: str, content: str) -> str:
        """Create or replace one file."""
        world.calls.append(("write_file", {"path": path, "content": content}))
        world.files[path] = content
        return f"wrote {len(content)} characters to {path}"

    @server.tool()
    def delete_file(path: str) -> str:
        """Delete one file."""
        world.calls.append(("delete_file", {"path": path}))
        if path not in world.files:
            raise ToolError(f"no such file: {path}")
        del world.files[path]
        return f"deleted {path}"

    @server.tool()
    def send_email(to: str, subject: str, body: str) -> str:
        """Send one email to one address."""
        world.calls.append(("send_email", {"to": to, "subject": subject, "body": body}))
        world.outbox.append({"to": to, "subject": subject, "body": body})
        return f"email {len(world.outbox)} sent to {to}"

    @server.tool()
    def search_calendar(query: str) -> list[dict[str, str]]:
        """Find calendar events whose title contains `query` (case-insensitive)."""
        world.calls.append(("search_calendar", {"query": query}))
        return [dict(e) for e in world.events if query.lower() in e["title"].lower()]

    @server.resource("world://outbox-size")
    def outbox_size() -> str:
        """How many emails have been sent."""
        return str(len(world.outbox))

    @server.prompt()
    def summarize_reports() -> str:
        """A canned prompt."""
        return "Summarize every file under reports/."

    return server, world


def build_app(world: World | None = None, *, host: str = "127.0.0.1") -> tuple[Starlette, World]:
    """The server as an ASGI app serving streamable HTTP at /mcp."""
    server, world = build_server(world)
    return server.streamable_http_app(host=host), world


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    options = parser.parse_args(argv)
    import uvicorn

    app, _ = build_app(host=options.host)
    uvicorn.run(app, host=options.host, port=options.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
