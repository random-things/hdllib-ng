"""Scan / locate MCP tools."""

from __future__ import annotations

from typing import Any

from ..protocol import (
    HDL_VALUE_F32,
    HDL_VALUE_F64,
    HDL_VALUE_I32,
    HDL_VALUE_I64,
    HDL_VALUE_U32,
    HDL_VALUE_U64,
)
from ..strategies import ValueScan
from .serialize import ok, parse_addr, to_jsonable
from .session import get_session, tool_result

_VALUE_TYPES = {
    "i32": HDL_VALUE_I32,
    "u32": HDL_VALUE_U32,
    "i64": HDL_VALUE_I64,
    "u64": HDL_VALUE_U64,
    "f32": HDL_VALUE_F32,
    "f64": HDL_VALUE_F64,
}

_NEXT_CMP = {
    "exact": "next_exact",
    "changed": "next_changed",
    "unchanged": "next_unchanged",
    "increased": "next_increased",
    "decreased": "next_decreased",
    "increased_by": "next_increased_by",
    "decreased_by": "next_decreased_by",
}


def _addrs(hits: list[int], max_results: int) -> dict[str, Any]:
    capped = hits[: max(0, max_results)]
    return {
        "hits": [{"addr": a, "hex": f"0x{a:x}"} for a in capped],
        "total": len(hits),
        "returned": len(capped),
    }


def register(mcp: Any) -> None:
    @mcp.tool()
    @tool_result
    def aob_scan(
        pattern: str,
        start: int | str = 0,
        size: int = 0,
        max_hits: int = 64,
    ) -> str:
        """IDA-style array-of-bytes scan (spaces, ?? wildcards)."""
        dbg = get_session().require_attached()
        hits = dbg.scan.aob(
            pattern,
            start=parse_addr(start) if start else 0,
            size=int(size),
            max_hits=max_hits,
        )
        return ok(_addrs(hits, max_hits))

    @mcp.tool()
    @tool_result
    def value_scan_first(
        value_type: str = "i32",
        mode: str = "exact",
        value: int | float | None = None,
        scan_id: str = "default",
        max_results: int = 100000,
        module: str | None = None,
    ) -> str:
        """CE-style first scan. mode: exact | unknown. Keeps scan_id for next/hits."""
        vt = _VALUE_TYPES.get(value_type.lower())
        if vt is None:
            raise ValueError(f"unsupported value_type {value_type!r}")
        s = get_session()
        dbg = s.require_attached()
        if scan_id in s.value_scans:
            try:
                s.value_scans[scan_id].close()
            except Exception:
                pass
            del s.value_scans[scan_id]
        vs = ValueScan(dbg, vt, module=module)
        s.value_scans[scan_id] = vs
        mode_l = mode.lower()
        if mode_l == "unknown":
            count = vs.first_unknown(max_results=max_results)
        elif mode_l == "exact":
            if value is None:
                raise ValueError("exact mode requires value")
            count = vs.first_exact(value, max_results=max_results)
        else:
            raise ValueError("mode must be exact or unknown")
        return ok({"scan_id": scan_id, "count": count, "value_type": value_type})

    @mcp.tool()
    @tool_result
    def value_scan_next(
        cmp: str = "exact",
        value: int | float | None = None,
        scan_id: str = "default",
    ) -> str:
        """CE-style next scan. cmp: exact|changed|unchanged|increased|decreased|*_by."""
        s = get_session()
        vs = s.value_scans.get(scan_id)
        if vs is None:
            raise ValueError(f"unknown scan_id {scan_id!r}; call value_scan_first first")
        key = cmp.lower()
        method = _NEXT_CMP.get(key)
        if method is None:
            raise ValueError(f"unsupported cmp {cmp!r}")
        if key in ("exact", "increased_by", "decreased_by"):
            if value is None:
                raise ValueError(f"{key} requires value")
            count = getattr(vs, method)(value)
        else:
            count = getattr(vs, method)()
        return ok({"scan_id": scan_id, "count": count, "cmp": key})

    @mcp.tool()
    @tool_result
    def value_scan_hits(scan_id: str = "default", max_hits: int = 64) -> str:
        """Return current hits for a ValueScan session."""
        vs = get_session().value_scans.get(scan_id)
        if vs is None:
            raise ValueError(f"unknown scan_id {scan_id!r}")
        hits = vs.hits(max_hits=max(max_hits, 1))
        # hits() already capped; report count from strategy
        payload = _addrs(hits, max_hits)
        payload["scan_id"] = scan_id
        payload["count"] = vs.count
        return ok(payload)

    @mcp.tool()
    @tool_result
    def resolve_pattern(
        pattern: str,
        hit_index: int = 0,
        pattern_offset: int = 0,
        rip_disp_offset: int = 0,
        rip_instr_len: int = 0,
        follow_offsets: list[int] | None = None,
        module: str | None = None,
        max_scan_hits: int = 256,
    ) -> str:
        """AOB + optional RIP/follow offsets → absolute address."""
        result = get_session().require_attached().scan.resolve_pattern(
            pattern,
            hit_index=hit_index,
            pattern_offset=pattern_offset,
            rip_disp_offset=rip_disp_offset,
            rip_instr_len=rip_instr_len,
            follow_offsets=follow_offsets,
            module=module,
            max_scan_hits=max_scan_hits,
        )
        return ok(to_jsonable(result))

    @mcp.tool()
    @tool_result
    def string_xrefs(
        text: str,
        max_results: int = 64,
        wide: bool = False,
        module: str | None = None,
    ) -> str:
        """Find xrefs to a string (ASCII or wide)."""
        hits = get_session().require_attached().scan.string_xrefs(
            text, wide=wide, module=module, max_out=max_results
        )
        return ok(_addrs(list(hits), max_results))

    @mcp.tool()
    @tool_result
    def ptr_scan(
        target: int | str,
        depth: int = 3,
        max_offset: int = 0x1000,
        max_n: int = 64,
        module: str | None = None,
    ) -> str:
        """Pointer scan paths to a target address."""
        s = get_session()
        dbg = s.require_attached()
        helper = s.pointer_helper or __import__(
            "hdllib.strategies", fromlist=["PointerHelper"]
        ).PointerHelper(dbg)
        s.pointer_helper = helper
        paths = helper.scan_paths(
            parse_addr(target),
            depth=depth,
            max_offset=max_offset,
            max_n=max_n,
            module=module,
        )
        return ok({"paths": to_jsonable(paths), "returned": len(paths)})

    @mcp.tool()
    @tool_result
    def ptr_follow(base: int | str, offsets: list[int]) -> str:
        """Follow a pointer chain from base through offsets."""
        addr = get_session().require_attached().scan.follow_pointers(
            parse_addr(base), offsets
        )
        return ok({"addr": addr, "hex": f"0x{addr:x}"})
