"""Smoke: FastMCP app registers the expected tool names."""

from __future__ import annotations

import pytest

mcp = pytest.importorskip("mcp")

from hdllib.mcp.server import EXPECTED_TOOL_NAMES, create_server  # noqa: E402


def _tool_names(server) -> set[str]:
    mgr = getattr(server, "_tool_manager", None)
    if mgr is not None:
        # mcp FastMCP ToolManager
        if hasattr(mgr, "list_tools"):
            tools = mgr.list_tools()
            names = set()
            for t in tools:
                names.add(getattr(t, "name", None) or t)
            if names:
                return {n for n in names if n}
        if hasattr(mgr, "_tools"):
            return set(mgr._tools.keys())
    # Fallback: older FastMCP kept tools on ._tools
    tools = getattr(server, "_tools", None)
    if isinstance(tools, dict):
        return set(tools.keys())
    raise AssertionError("could not enumerate FastMCP tools")


def test_expected_tools_registered():
    server = create_server()
    names = _tool_names(server)
    missing = EXPECTED_TOOL_NAMES - names
    assert not missing, f"missing tools: {sorted(missing)}"
