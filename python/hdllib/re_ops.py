"""Reverse-engineering Session ops (pointer chains, scans, xrefs, watches, …).

Wire formats match ``docs/capabilities.md`` and ``tools/client/cmds_*.cpp``.
Struct layouts are x64 MSVC packed sizes from ``hdllib.h``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .protocol import (
    HDL_CALL_THREAD_WORKER,
    HDL_SEARCH_IMAGE,
    HDL_WATCH_HW_WRITE,
    HDL_WATCH_PAGE_GUARD,
    HDL_XREF_CALL,
    HDL_XREF_FUNC,
    HDL_XREF_JMP,
    Op,
    Writer,
)

if TYPE_CHECKING:
    from .client import CallArg, CallResult

# Constants re-exported for REPL / toolbox users (values from protocol).
__all__ = [
    "FunctionInfo",
    "HDL_SEARCH_IMAGE",
    "HDL_WATCH_HW_WRITE",
    "HDL_WATCH_PAGE_GUARD",
    "HDL_XREF_CALL",
    "HDL_XREF_FUNC",
    "HDL_XREF_JMP",
    "PatternResult",
    "PointerPath",
    "ReOpsMixin",
    "StructField",
    "WatchHit",
    "XrefEdge",
]

# Packed layouts (x64 MSVC)
_POINTER_PATH_FMT = "<QII" + ("i" * 8)  # 48
_POINTER_PATH_SIZE = struct.calcsize(_POINTER_PATH_FMT)
_STRUCT_FIELD_FMT = "<IIQ"  # 16
_STRUCT_FIELD_SIZE = struct.calcsize(_STRUCT_FIELD_FMT)
_FUNCTION_INFO_FMT = "<QQII"  # 24
_FUNCTION_INFO_SIZE = struct.calcsize(_FUNCTION_INFO_FMT)
_XREF_EDGE_FMT = "<QQII"  # 24
_XREF_EDGE_SIZE = struct.calcsize(_XREF_EDGE_FMT)
_WATCH_HIT_FMT = "<QQIIQQII"  # 48
_WATCH_HIT_SIZE = struct.calcsize(_WATCH_HIT_FMT)
_PATTERN_RESULT_FMT = "<QQQQ"  # 32
_PATTERN_RESULT_SIZE = struct.calcsize(_PATTERN_RESULT_FMT)


@dataclass(frozen=True)
class PointerPath:
    static_base: int
    depth: int
    offsets: tuple[int, ...]


@dataclass(frozen=True)
class StructField:
    offset: int
    kind: int
    value: int


@dataclass(frozen=True)
class FunctionInfo:
    start: int
    end: int
    confidence: int
    flags: int


@dataclass(frozen=True)
class XrefEdge:
    from_addr: int
    to_addr: int
    kind: int


@dataclass(frozen=True)
class WatchHit:
    watch_handle: int
    timestamp_ms: int
    tid: int
    access: int
    rip: int
    accessed: int
    size: int


@dataclass(frozen=True)
class PatternResult:
    match_addr: int
    resolved_addr: int
    module_base: int
    rva: int


def _parse_pointer_path(raw: bytes) -> PointerPath:
    fields = struct.unpack(_POINTER_PATH_FMT, raw)
    static_base, depth, _reserved = fields[0], fields[1], fields[2]
    offs = fields[3:11]
    return PointerPath(
        static_base=static_base,
        depth=depth,
        offsets=tuple(offs[:depth]),
    )


def _parse_struct_field(raw: bytes) -> StructField:
    offset, kind, value = struct.unpack(_STRUCT_FIELD_FMT, raw)
    return StructField(offset=offset, kind=kind, value=value)


def _parse_function_info(raw: bytes) -> FunctionInfo:
    start, end, confidence, flags = struct.unpack(_FUNCTION_INFO_FMT, raw)
    return FunctionInfo(start=start, end=end, confidence=confidence, flags=flags)


def _parse_xref_edge(raw: bytes) -> XrefEdge:
    frm, to, kind, _res = struct.unpack(_XREF_EDGE_FMT, raw)
    return XrefEdge(from_addr=frm, to_addr=to, kind=kind)


def _parse_watch_hit(raw: bytes) -> WatchHit:
    (
        watch_handle,
        timestamp_ms,
        tid,
        access,
        rip,
        accessed,
        size,
        _reserved,
    ) = struct.unpack(_WATCH_HIT_FMT, raw)
    return WatchHit(
        watch_handle=watch_handle,
        timestamp_ms=timestamp_ms,
        tid=tid,
        access=access,
        rip=rip,
        accessed=accessed,
        size=size,
    )


def _parse_pattern_result(raw: bytes) -> PatternResult:
    match_addr, resolved_addr, module_base, rva = struct.unpack(
        _PATTERN_RESULT_FMT, raw
    )
    return PatternResult(
        match_addr=match_addr,
        resolved_addr=resolved_addr,
        module_base=module_base,
        rva=rva,
    )


class ReOpsMixin:
    """Mixin adding locate / graph / watch / vtable ops onto :class:`Session`."""

    # --- pointer / locate --------------------------------------------------

    def follow_pointers(self, base: int, offsets: list[int] | tuple[int, ...]) -> int:
        w = Writer()
        w.append_u32(Op.FOLLOW_POINTERS)
        w.append_u64(base)
        w.append_u32(len(offsets))
        for o in offsets:
            w.append_i64(int(o))
        r = self.request(w.data)
        status = r.take_i32()
        addr = r.take_u64()
        self._check(status, "follow_pointers")
        return addr

    def pointer_scan(
        self,
        target: int,
        *,
        depth: int = 2,
        max_offset: int = 0x1000,
        max_n: int = 32,
        flags: int = HDL_SEARCH_IMAGE,
        module: str | None = None,
    ) -> list[PointerPath]:
        w = Writer()
        w.append_u32(Op.POINTER_SCAN)
        w.append_u64(target)
        w.append_u32(depth)
        w.append_u32(max_offset)
        w.append_u32(max_n)
        w.append_u32(flags)
        w.append_wstring(module)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "pointer_scan")
        return [_parse_pointer_path(r.take(_POINTER_PATH_SIZE)) for _ in range(count)]

    def probe_struct(
        self,
        addr: int,
        size: int = 64,
        *,
        max_fields: int = 64,
    ) -> list[StructField]:
        w = Writer()
        w.append_u32(Op.PROBE_STRUCT)
        w.append_u64(addr)
        w.append_u32(size)
        w.append_u32(max_fields)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "probe_struct")
        return [_parse_struct_field(r.take(_STRUCT_FIELD_SIZE)) for _ in range(count)]

    def resolve_pattern(
        self,
        pattern: str,
        *,
        hit_index: int = 0,
        pattern_offset: int = 0,
        rip_disp_offset: int = 0,
        rip_instr_len: int = 0,
        follow_offsets: list[int] | tuple[int, ...] | None = None,
        flags: int = 0,
        module: str | None = None,
        max_scan_hits: int = 256,
    ) -> PatternResult:
        follows = list(follow_offsets or ())
        w = Writer()
        w.append_u32(Op.RESOLVE_PATTERN)
        w.append_string(pattern)
        w.append_u32(hit_index)
        w.append_i32(pattern_offset)
        w.append_u32(rip_disp_offset)
        w.append_u32(rip_instr_len)
        w.append_u32(len(follows))
        w.append_u32(flags)
        w.append_u32(max_scan_hits)
        w.append_wstring(module)
        for o in follows:
            w.append_i64(int(o))
        r = self.request(w.data)
        status = r.take_i32()
        raw = r.take(_PATTERN_RESULT_SIZE)
        self._check(status, "resolve_pattern")
        return _parse_pattern_result(raw)

    # --- vtable / RTTI / call ----------------------------------------------

    def call_vtable(
        self,
        obj: int,
        index: int,
        args: list[CallArg] | None = None,
        *,
        prepend_this: bool = True,
        thread_mode: int = HDL_CALL_THREAD_WORKER,
        timeout_ms: int = 0,
        job_id: int = 0,
    ) -> CallResult:
        from .client import _append_call_arg, _parse_call_result

        args = args or []
        w = Writer()
        w.append_u32(Op.CALL_VTABLE)
        w.append_u64(obj)
        w.append_u32(index)
        w.append_u32(len(args))
        w.append_i32(1 if prepend_this else 0)
        w.append_u32(thread_mode)
        w.append_u32(timeout_ms)
        w.append_u64(job_id)
        for a in args:
            _append_call_arg(w, a)
        return _parse_call_result(self.request(w.data), "call_vtable")

    def walk_vtable(self, addr: int, *, is_object: bool = True) -> list[int]:
        w = Writer()
        w.append_u32(Op.WALK_VTABLE)
        w.append_u64(addr)
        w.append_i32(1 if is_object else 0)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "walk_vtable")
        return [r.take_u64() for _ in range(count)]

    def query_rtti(self, addr: int, *, is_object: bool = True) -> str:
        w = Writer()
        w.append_u32(Op.QUERY_RTTI_NAME)
        w.append_u64(addr)
        w.append_i32(1 if is_object else 0)
        r = self.request(w.data)
        status = r.take_i32()
        name = r.take_string()
        self._check(status, "query_rtti")
        return name

    # --- graph / xrefs -----------------------------------------------------

    def enum_functions(
        self,
        *,
        start: int = 0,
        size: int = 0,
        flags: int = 0,
        max_results: int = 64,
        module: str | None = None,
    ) -> list[FunctionInfo]:
        w = Writer()
        w.append_u32(Op.ENUM_FUNCTIONS)
        w.append_u64(start)
        w.append_u64(size)
        w.append_u32(flags)
        w.append_u32(max_results)
        w.append_wstring(module)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "enum_functions")
        return [
            _parse_function_info(r.take(_FUNCTION_INFO_SIZE)) for _ in range(count)
        ]

    def xrefs_from(
        self,
        seed: int,
        *,
        depth: int = 2,
        max_nodes: int = 64,
        kinds: int = 0,
    ) -> list[XrefEdge]:
        w = Writer()
        w.append_u32(Op.XREFS_FROM)
        w.append_u64(seed)
        w.append_u32(depth)
        w.append_u32(max_nodes)
        w.append_u32(kinds)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "xrefs_from")
        return [_parse_xref_edge(r.take(_XREF_EDGE_SIZE)) for _ in range(count)]

    def xrefs_to(
        self,
        target: int,
        *,
        max_nodes: int = 64,
        kinds: int = HDL_XREF_CALL | HDL_XREF_JMP | HDL_XREF_FUNC,
        flags: int = 0,
        module: str | None = None,
    ) -> list[XrefEdge]:
        w = Writer()
        w.append_u32(Op.XREFS_TO)
        w.append_u64(target)
        w.append_u32(max_nodes)
        w.append_u32(kinds)
        w.append_u32(flags)
        w.append_wstring(module)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "xrefs_to")
        return [_parse_xref_edge(r.take(_XREF_EDGE_SIZE)) for _ in range(count)]

    # --- hooks / watches ---------------------------------------------------

    def hook_import(
        self,
        dll: str,
        import_name: str,
        *,
        module: str | None = None,
        arg_count: int = 0,
    ) -> int:
        w = Writer()
        w.append_u32(Op.HOOK_IMPORT)
        w.append_wstring(module)
        w.append_string(dll)
        w.append_string(import_name)
        w.append_u32(arg_count)
        r = self.request(w.data)
        status = r.take_i32()
        handle = r.take_u64()
        self._check(status, "hook_import")
        return handle

    def watch_hw(
        self,
        addr: int,
        size: int = 1,
        *,
        access: int = HDL_WATCH_HW_WRITE,
        tid: int = 0,
    ) -> int:
        w = Writer()
        w.append_u32(Op.WATCH_HW)
        w.append_u64(addr)
        w.append_u32(size)
        w.append_u32(access)
        w.append_u32(tid)
        r = self.request(w.data)
        status = r.take_i32()
        handle = r.take_u64()
        self._check(status, "watch_hw")
        return handle

    def watch_page(
        self,
        addr: int,
        size: int,
        *,
        mode: int = HDL_WATCH_PAGE_GUARD,
    ) -> int:
        w = Writer()
        w.append_u32(Op.WATCH_PAGE)
        w.append_u64(addr)
        w.append_u64(size)
        w.append_u32(mode)
        r = self.request(w.data)
        status = r.take_i32()
        handle = r.take_u64()
        self._check(status, "watch_page")
        return handle

    def unwatch(self, handle: int) -> None:
        w = Writer()
        w.append_u32(Op.UNWATCH)
        w.append_u64(handle)
        r = self.request(w.data)
        self._check(r.take_i32(), "unwatch")

    def poll_watch_hits(
        self, max_n: int = 32, timeout_ms: int = 0
    ) -> list[WatchHit]:
        w = Writer()
        w.append_u32(Op.POLL_WATCH_HITS)
        w.append_u32(max_n)
        w.append_u32(timeout_ms)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "poll_watch_hits")
        return [_parse_watch_hit(r.take(_WATCH_HIT_SIZE)) for _ in range(count)]
