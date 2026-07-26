"""Disasm / struct probe MCP tools."""

from __future__ import annotations

from typing import Any

from .serialize import ok, parse_addr, to_jsonable
from .session import get_session, tool_result


def register(mcp: Any) -> None:
    @mcp.tool()
    @tool_result
    def disasm(address: int | str, max_insns: int = 16) -> str:
        """Disassemble instructions starting at address."""
        if max_insns <= 0 or max_insns > 256:
            raise ValueError("max_insns must be 1..256")
        insns = get_session().require_attached().code.disasm(
            parse_addr(address), max_insns=max_insns
        )
        return ok({"insns": to_jsonable(insns), "returned": len(insns)})

    @mcp.tool()
    @tool_result
    def probe_struct(
        address: int | str,
        size: int = 64,
        max_fields: int = 64,
    ) -> str:
        """Heuristic field classification over a memory range."""
        fields = get_session().require_attached().structs.probe(
            parse_addr(address), size=size, max_fields=max_fields
        )
        return ok({"fields": to_jsonable(fields), "returned": len(fields)})
