"""Hooks, watches, call, health, discover MCP tools."""

from __future__ import annotations

from typing import Any

from ..client import CallArg
from ..protocol import (
    HDL_CAND_ADDRESS,
    HDL_WATCH_HW_WRITE,
    HDL_WATCH_PAGE_GUARD,
)
from .serialize import ok, parse_addr, to_jsonable
from .session import get_session, tool_result


def _parse_call_args(args: list[dict[str, Any]] | None) -> list[CallArg]:
    if not args:
        return []
    out: list[CallArg] = []
    for a in args:
        kind = str(a.get("kind", "u64")).lower()
        if kind == "u64":
            out.append(CallArg.of_u64(int(a["value"], 0) if isinstance(a["value"], str) else int(a["value"])))
        elif kind == "i64":
            out.append(CallArg.of_i64(int(a["value"], 0) if isinstance(a["value"], str) else int(a["value"])))
        elif kind == "ptr":
            out.append(CallArg.of_ptr(parse_addr(a["value"])))
        elif kind == "f32":
            out.append(CallArg.of_f32(float(a["value"])))
        elif kind == "f64":
            out.append(CallArg.of_f64(float(a["value"])))
        elif kind == "cstr":
            out.append(CallArg.of_cstr(str(a["value"])))
        elif kind == "wstr":
            out.append(CallArg.of_wstr(str(a["value"])))
        elif kind == "buf":
            hex_text = str(a["value"]).replace(" ", "").replace("0x", "")
            out.append(CallArg.of_buf(bytes.fromhex(hex_text)))
        else:
            raise ValueError(f"unsupported call arg kind {kind!r}")
    return out


def register(mcp: Any) -> None:
    @mcp.tool()
    @tool_result
    def health() -> str:
        """Process health snapshot (threads, memory, GUI hang, last exception)."""
        snap = get_session().require_attached().health.snapshot()
        return ok(to_jsonable(snap))

    @mcp.tool()
    @tool_result
    def watch_hw(
        address: int | str,
        size: int = 4,
        access: int = HDL_WATCH_HW_WRITE,
        tid: int = 0,
    ) -> str:
        """Install a hardware watchpoint (requires --allow-write)."""
        s = get_session()
        s.require_write()
        handle = s.require_attached().watches.hw(
            parse_addr(address), size, access=access, tid=tid
        )
        return ok({"handle": handle, "handle_hex": f"0x{handle:x}"})

    @mcp.tool()
    @tool_result
    def watch_page(
        address: int | str,
        size: int,
        mode: int = HDL_WATCH_PAGE_GUARD,
    ) -> str:
        """Install a page watch (requires --allow-write)."""
        s = get_session()
        s.require_write()
        handle = s.require_attached().watches.page(
            parse_addr(address), size, mode=mode
        )
        return ok({"handle": handle, "handle_hex": f"0x{handle:x}"})

    @mcp.tool()
    @tool_result
    def unwatch(handle: int | str) -> str:
        """Remove a watch by handle (requires --allow-write)."""
        s = get_session()
        s.require_write()
        s.require_attached().watches.unwatch(parse_addr(handle))
        return ok({"unwatched": True, "handle": parse_addr(handle)})

    @mcp.tool()
    @tool_result
    def watch_hits(max_n: int = 32, timeout_ms: int = 0) -> str:
        """Poll pending hardware/page watch hits."""
        hits = get_session().require_attached().watches.poll(
            max_n=max_n, timeout_ms=timeout_ms
        )
        return ok({"hits": to_jsonable(hits), "returned": len(hits)})

    @mcp.tool()
    @tool_result
    def hook_trace(address: int | str, arg_count: int = 0) -> str:
        """Install a capture-only trace hook (requires --allow-write)."""
        s = get_session()
        s.require_write()
        handle = s.require_attached().hooks.trace(parse_addr(address), arg_count=arg_count)
        return ok({"handle": handle, "handle_hex": f"0x{handle:x}"})

    @mcp.tool()
    @tool_result
    def hook_hits(max_n: int = 16, timeout_ms: int = 0) -> str:
        """Poll pending hook hit records."""
        hits = get_session().require_attached().hooks.poll(
            max_n=max_n, timeout_ms=timeout_ms
        )
        return ok({"hits": to_jsonable(hits), "returned": len(hits)})

    @mcp.tool()
    @tool_result
    def unhook(handle: int | str) -> str:
        """Remove a hook (requires --allow-write)."""
        s = get_session()
        s.require_write()
        s.require_attached().hooks.unhook(parse_addr(handle))
        return ok({"unhooked": True, "handle": parse_addr(handle)})

    @mcp.tool()
    @tool_result
    def call_export(
        name: str,
        module: str | None = None,
        args: list[dict[str, Any]] | None = None,
        timeout_ms: int = 5000,
    ) -> str:
        """Call an exported function in the target (requires --allow-write).

        args: list of {kind, value} where kind is u64|i64|ptr|f32|f64|cstr|wstr|buf.
        """
        s = get_session()
        s.require_write()
        result = s.hdl.call_export(
            name,
            _parse_call_args(args),
            module=module,
            timeout_ms=timeout_ms,
        )
        return ok(to_jsonable(result))

    @mcp.tool()
    @tool_result
    def discover_begin() -> str:
        """Start a discover session (held until discover_end)."""
        disc = get_session().ensure_discover()
        return ok({"session_id": disc.id})

    @mcp.tool()
    @tool_result
    def discover_add(
        address: int | str,
        tag: str | None = None,
        kind: int = HDL_CAND_ADDRESS,
    ) -> str:
        """Add a candidate address to the active discover session."""
        disc = get_session().ensure_discover()
        cand_id = disc.add(parse_addr(address), kind=kind, tag=tag)
        return ok({"cand_id": cand_id, "address": parse_addr(address)})

    @mcp.tool()
    @tool_result
    def discover_rank(action: str = "default", max_results: int = 64) -> str:
        """Rank discover candidates for an action window name."""
        disc = get_session().ensure_discover()
        cands = disc.rank(action)
        capped = cands[: max(0, max_results)]
        return ok(
            {
                "candidates": to_jsonable(capped),
                "total": len(cands),
                "returned": len(capped),
            }
        )

    @mcp.tool()
    @tool_result
    def discover_candidates(max_out: int = 64) -> str:
        """List candidates in the active discover session."""
        disc = get_session().ensure_discover()
        cands = disc.candidates(max_out=max_out)
        return ok({"candidates": to_jsonable(cands), "returned": len(cands)})

    @mcp.tool()
    @tool_result
    def discover_end() -> str:
        """Close the active discover session."""
        s = get_session()
        if s.discover is not None:
            try:
                s.discover.close()
            finally:
                s.discover = None
        return ok({"closed": True})
