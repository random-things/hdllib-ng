"""Session lifecycle MCP tools."""

from __future__ import annotations

from typing import Any

from .serialize import ok
from .session import get_session, tool_result


def register(mcp: Any) -> None:
    @mcp.tool()
    @tool_result
    def attach(
        pid: int | None = None,
        exe: str | None = None,
        title: str | None = None,
        game: str | None = None,
        inject: bool = False,
        dll: str | None = None,
        method: int | None = None,
        timeout_ms: int | None = None,
    ) -> str:
        """Attach to a target process over the hdllib named pipe.

        Provide pid, exe, title, or game (or rely on HDL_PID / server startup flags).
        Set inject=true only when the server was started with --allow-write.
        """
        info = get_session().attach(
            pid=pid,
            exe=exe,
            title=title,
            game=game,
            inject=inject,
            dll=dll,
            method=method,
            timeout_ms=timeout_ms,
        )
        return ok(info)

    @mcp.tool()
    @tool_result
    def detach() -> str:
        """Detach from the current target and close strategy sessions."""
        get_session().detach()
        return ok({"detached": True})

    @mcp.tool()
    @tool_result
    def session_info() -> str:
        """Return attach state: pid, ping, allow_write, connected."""
        s = get_session()
        if not s.attached:
            return ok(
                {
                    "attached": False,
                    "allow_write": s.allow_write,
                    "pid": None,
                }
            )
        dbg = s.require_attached()
        remote = dbg.hdl.ping()
        return ok(
            {
                "attached": True,
                "allow_write": s.allow_write,
                "pid": dbg.pid,
                "remote_pid": remote,
                "connected": dbg.connected,
            }
        )

    @mcp.tool()
    @tool_result
    def list_modules(max_results: int = 64) -> str:
        """List loaded modules in the target (base, size, path)."""
        mods = get_session().hdl.modules()
        truncated = mods[: max(0, max_results)]
        data = [
            {
                "base": m.base,
                "base_hex": f"0x{m.base:x}",
                "size": m.size,
                "path": m.path,
            }
            for m in truncated
        ]
        return ok({"modules": data, "total": len(mods), "returned": len(data)})

    @mcp.tool()
    @tool_result
    def module_base(name: str | None = None) -> str:
        """Return the base address of a module (default: main executable)."""
        base = get_session().hdl.module_base(name)
        return ok({"base": base, "base_hex": f"0x{base:x}", "module": name})
