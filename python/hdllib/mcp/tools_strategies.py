"""CE strategy MCP tools (patch, AOB inject, access watch)."""

from __future__ import annotations

from typing import Any

from ..protocol import HDL_WATCH_HW_WRITE
from ..strategies import AccessFinder, AobInjector, CodePatcher
from .serialize import ok, parse_addr, to_jsonable
from .session import get_session, tool_result


def register(mcp: Any) -> None:
    @mcp.tool()
    @tool_result
    def patch_nop(address: int | str, name: str | None = None, size: int | None = None) -> str:
        """NOP an instruction (or size bytes) via the patch ledger (requires --allow-write)."""
        s = get_session()
        s.require_write()
        dbg = s.require_attached()
        if s.code_patcher is None:
            s.code_patcher = CodePatcher(dbg)
        addr = parse_addr(address)
        if size is None:
            handle = s.code_patcher.nop_insn(addr, name=name)
        else:
            handle = s.code_patcher.nop(addr, size, name=name)
        key = name or f"nop_{addr:x}"
        return ok({"handle": handle, "name": key, "address": addr, "address_hex": f"0x{addr:x}"})

    @mcp.tool()
    @tool_result
    def patch_restore(name: str) -> str:
        """Disable and remove a named patch (requires --allow-write)."""
        s = get_session()
        s.require_write()
        if s.code_patcher is None:
            raise ValueError("no active CodePatcher; call patch_nop first")
        s.code_patcher.restore(name)
        return ok({"restored": name})

    @mcp.tool()
    @tool_result
    def aob_install(
        pattern: str,
        pattern_offset: int = 0,
        module: str | None = None,
        fill_cave_hex: str | None = None,
    ) -> str:
        """Install an AOB jump injection (requires --allow-write)."""
        s = get_session()
        s.require_write()
        dbg = s.require_attached()
        if s.aob_injector is None:
            s.aob_injector = AobInjector(dbg)
        fill = None
        if fill_cave_hex:
            fill = bytes.fromhex(fill_cave_hex.replace(" ", "").replace("0x", ""))
        inj = s.aob_injector.install(
            pattern,
            pattern_offset=pattern_offset,
            module=module,
            fill_cave=fill,
        )
        return ok(to_jsonable(inj))

    @mcp.tool()
    @tool_result
    def access_watch(
        address: int | str,
        size: int = 4,
        access: int = HDL_WATCH_HW_WRITE,
        timeout_ms: int = 3000,
        max_hits: int = 64,
        arm_only: bool = False,
    ) -> str:
        """Find what accesses/writes an address (requires --allow-write).

        Prefer agent-driven workflow: call with arm_only=true, change the value
        in-game (or via mem_write), then call again with arm_only=false after
        collecting — or omit arm_only to arm, wait timeout_ms, and collect.
        """
        s = get_session()
        s.require_write()
        dbg = s.require_attached()
        if s.access_finder is None:
            s.access_finder = AccessFinder(dbg)
        af = s.access_finder
        addr = parse_addr(address)
        if arm_only:
            handle = af.start(addr, size, access=access)
            return ok({"armed": True, "handle": handle, "address": addr})
        # Arm → wait/poll → stop (no Python callback; agent drives value changes).
        af.start(addr, size, access=access)
        try:
            hits = af.collect(timeout_ms=timeout_ms, max_hits=max_hits)
        finally:
            af.stop()
        return ok({"hits": to_jsonable(hits), "returned": len(hits)})
