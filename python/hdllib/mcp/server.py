"""FastMCP application factory and tool registration."""

from __future__ import annotations

from typing import Any

from . import (
    tools_code,
    tools_memory,
    tools_observe,
    tools_scan,
    tools_session,
    tools_strategies,
)
from .session import get_session


def create_server(**kwargs: Any) -> Any:
    """Create and return a configured FastMCP stdio server."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "The MCP server requires the optional dependency. "
            "Install with: pip install 'hdllib[mcp]'"
        ) from exc

    mcp = FastMCP(
        "hdllib",
        instructions=(
            "hdllib reverse-engineering helper for an injected Windows target. "
            "Call attach (or start hdl-mcp with --preattach) before other tools. "
            "Destructive ops (write/inject/call/patch/hook/watch-install) require "
            "the server to be started with --allow-write. "
            "All tool results are JSON objects with ok=true|false."
        ),
        **kwargs,
    )

    tools_session.register(mcp)
    tools_memory.register(mcp)
    tools_scan.register(mcp)
    tools_code.register(mcp)
    tools_observe.register(mcp)
    tools_strategies.register(mcp)

    # Expose session singleton for tests / advanced hosts.
    mcp._hdllib_session = get_session()  # noqa: SLF001
    return mcp


EXPECTED_TOOL_NAMES = frozenset(
    {
        "attach",
        "detach",
        "session_info",
        "list_modules",
        "module_base",
        "mem_read",
        "mem_write",
        "aob_scan",
        "value_scan_first",
        "value_scan_next",
        "value_scan_hits",
        "resolve_pattern",
        "string_xrefs",
        "ptr_scan",
        "ptr_follow",
        "disasm",
        "probe_struct",
        "health",
        "watch_hw",
        "watch_page",
        "unwatch",
        "watch_hits",
        "hook_trace",
        "hook_hits",
        "unhook",
        "call_export",
        "discover_begin",
        "discover_add",
        "discover_rank",
        "discover_candidates",
        "discover_end",
        "patch_nop",
        "patch_restore",
        "aob_install",
        "access_watch",
    }
)
