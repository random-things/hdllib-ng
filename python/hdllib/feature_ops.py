"""Session mixins for jobs, health, place, code, PE, and discover.

Wire formats match ``docs/capabilities.md`` and ``src/ipc/handlers_*.cpp``.
Struct layouts are x64 MSVC sizes from ``hdllib.h`` (verified with sizeof).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, ByteString

from .protocol import (
    HDL_CAND_ADDRESS,
    HDL_STUB_ABS_JMP,
    HDL_STR_XREF_ABSOLUTE,
    HDL_STR_XREF_RIP_REL,
    Op,
    PAGE_EXECUTE_READWRITE,
    Writer,
)
from .re_ops import PointerPath, _parse_pointer_path, _POINTER_PATH_SIZE

if TYPE_CHECKING:
    pass

__all__ = [
    "BackendInfo",
    "Candidate",
    "CaveInfo",
    "Event",
    "ExportInfo",
    "FeatureOpsMixin",
    "FieldPred",
    "HealthInfo",
    "HeatField",
    "ImportInfo",
    "Insn",
    "PatchInfo",
    "SectionInfo",
    "StubResult",
    "SynthesizedPattern",
    "ThreadInfo",
    "WatchInfo",
]

# Packed layouts (x64 MSVC) — include trailing padding where sizeof requires it
_HEALTH_FMT = "<IIIIQQQQIIIIQQ"  # 80
_HEALTH_SIZE = struct.calcsize(_HEALTH_FMT)
_THREAD_FMT = "<IIQQQ"  # 32
_THREAD_SIZE = struct.calcsize(_THREAD_FMT)
_EVENT_FMT = "<IIQQQ"  # 32
_EVENT_SIZE = struct.calcsize(_EVENT_FMT)
_CAVE_FMT = "<QQQI4x"  # 32
_CAVE_SIZE = struct.calcsize(_CAVE_FMT)
_BACKEND_FMT = "<i32s"  # 36
_BACKEND_SIZE = struct.calcsize(_BACKEND_FMT)
_INSN_FMT = "<QIIQiI32s96s"  # 160
_INSN_SIZE = struct.calcsize(_INSN_FMT)
_STUB_RESULT_FMT = "<QII256s"  # 272
_STUB_RESULT_SIZE = struct.calcsize(_STUB_RESULT_FMT)
_PATCH_FMT = "<QQII48s"  # 72
_PATCH_SIZE = struct.calcsize(_PATCH_FMT)
_SECTION_FMT = "<16sQQII"  # 40
_SECTION_SIZE = struct.calcsize(_SECTION_FMT)
_EXPORT_FMT = "<128sIII4xQQ"  # 160
_EXPORT_SIZE = struct.calcsize(_EXPORT_FMT)
_IMPORT_FMT = "<64s128sIIQQ"  # 216
_IMPORT_SIZE = struct.calcsize(_IMPORT_FMT)
_WATCH_INFO_FMT = "<QQIIII"  # 32
_WATCH_INFO_SIZE = struct.calcsize(_WATCH_INFO_FMT)
_CANDIDATE_FMT = "<QIIQQQII48s"  # 96
_CANDIDATE_SIZE = struct.calcsize(_CANDIDATE_FMT)
_SYNTH_FMT = "<192siII4xQQII"  # 232
_SYNTH_SIZE = struct.calcsize(_SYNTH_FMT)
_HEAT_FMT = "<IIIIQ"  # 24
_HEAT_SIZE = struct.calcsize(_HEAT_FMT)
_FIELD_PRED_FMT = "<iiqq"  # 24
_FIELD_PRED_SIZE = struct.calcsize(_FIELD_PRED_FMT)
_FUNCTION_INFO_SIZE = 24  # Q Q I I


def _c_str(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


@dataclass(frozen=True)
class HealthInfo:
    pid: int
    thread_count: int
    handle_count: int
    flags: int
    working_set: int
    private_bytes: int
    user_time_100ns: int
    kernel_time_100ns: int
    cpu_percent: int
    gui_hung: int
    last_exception_code: int
    last_exception_addr: int
    last_exception_tick_ms: int


@dataclass(frozen=True)
class ThreadInfo:
    tid: int
    suspend_count: int
    user_time_100ns: int
    kernel_time_100ns: int
    start_address: int


@dataclass(frozen=True)
class Event:
    type: int
    code: int
    timestamp_ms: int
    address: int
    detail: int


@dataclass(frozen=True)
class CaveInfo:
    addr: int
    size: int
    region_base: int


@dataclass(frozen=True)
class BackendInfo:
    id: int
    name: str


@dataclass(frozen=True)
class Insn:
    addr: int
    length: int
    flags: int
    branch_target: int
    rip_disp_offset: int
    rip_disp_size: int
    mnemonic: str
    op_str: str


@dataclass(frozen=True)
class StubResult:
    stub_va: int
    stolen_bytes: int
    code_size: int
    code: bytes


@dataclass(frozen=True)
class PatchInfo:
    handle: int
    addr: int
    size: int
    enabled: int
    name: str


@dataclass(frozen=True)
class SectionInfo:
    name: str
    va: int
    vsize: int
    raw_size: int
    characteristics: int


@dataclass(frozen=True)
class ExportInfo:
    name: str
    ordinal: int
    forwarder: int
    rva: int
    va: int


@dataclass(frozen=True)
class ImportInfo:
    module: str
    name: str
    ordinal: int
    iat_va: int
    bound_va: int


@dataclass(frozen=True)
class WatchInfo:
    handle: int
    addr: int
    size: int
    kind: int
    type: int
    tid: int


@dataclass(frozen=True)
class Candidate:
    id: int
    kind: int
    confidence: int
    address: int
    module_base: int
    rva: int
    field_offset: int
    flags: int
    tag: str


@dataclass(frozen=True)
class SynthesizedPattern:
    pattern: str
    pattern_offset: int
    rip_disp_offset: int
    rip_instr_len: int
    match_addr: int
    resolved_addr: int
    unique_hits: int


@dataclass(frozen=True)
class HeatField:
    offset: int
    changes: int
    kind: int
    size: int
    last_value: int


@dataclass(frozen=True)
class FieldPred:
    offset: int
    kind: int
    a: int = 0
    b: int = 0

    def pack(self) -> bytes:
        return struct.pack(_FIELD_PRED_FMT, self.offset, self.kind, self.a, self.b)


def _parse_health(raw: bytes) -> HealthInfo:
    (
        pid,
        thread_count,
        handle_count,
        flags,
        working_set,
        private_bytes,
        user_time,
        kernel_time,
        cpu_percent,
        gui_hung,
        last_exc_code,
        _res,
        last_exc_addr,
        last_exc_tick,
    ) = struct.unpack(_HEALTH_FMT, raw)
    return HealthInfo(
        pid=pid,
        thread_count=thread_count,
        handle_count=handle_count,
        flags=flags,
        working_set=working_set,
        private_bytes=private_bytes,
        user_time_100ns=user_time,
        kernel_time_100ns=kernel_time,
        cpu_percent=cpu_percent,
        gui_hung=gui_hung,
        last_exception_code=last_exc_code,
        last_exception_addr=last_exc_addr,
        last_exception_tick_ms=last_exc_tick,
    )


def _parse_thread(raw: bytes) -> ThreadInfo:
    tid, suspend, user, kernel, start = struct.unpack(_THREAD_FMT, raw)
    return ThreadInfo(
        tid=tid,
        suspend_count=suspend,
        user_time_100ns=user,
        kernel_time_100ns=kernel,
        start_address=start,
    )


def _parse_event(raw: bytes) -> Event:
    typ, code, ts, addr, detail = struct.unpack(_EVENT_FMT, raw)
    return Event(type=typ, code=code, timestamp_ms=ts, address=addr, detail=detail)


def _parse_cave(raw: bytes) -> CaveInfo:
    addr, size, region_base, _res = struct.unpack(_CAVE_FMT, raw)
    return CaveInfo(addr=addr, size=size, region_base=region_base)


def _parse_backend(raw: bytes) -> BackendInfo:
    bid, name = struct.unpack(_BACKEND_FMT, raw)
    return BackendInfo(id=bid, name=_c_str(name))


def _parse_insn(raw: bytes) -> Insn:
    (
        addr,
        length,
        flags,
        branch,
        rip_off,
        rip_sz,
        mnemonic,
        op_str,
    ) = struct.unpack(_INSN_FMT, raw)
    return Insn(
        addr=addr,
        length=length,
        flags=flags,
        branch_target=branch,
        rip_disp_offset=rip_off,
        rip_disp_size=rip_sz,
        mnemonic=_c_str(mnemonic),
        op_str=_c_str(op_str),
    )


def _parse_stub_result(raw: bytes) -> StubResult:
    stub_va, stolen, code_size, code = struct.unpack(_STUB_RESULT_FMT, raw)
    return StubResult(
        stub_va=stub_va,
        stolen_bytes=stolen,
        code_size=code_size,
        code=code[:code_size],
    )


def _parse_patch(raw: bytes) -> PatchInfo:
    handle, addr, size, enabled, name = struct.unpack(_PATCH_FMT, raw)
    return PatchInfo(
        handle=handle,
        addr=addr,
        size=size,
        enabled=enabled,
        name=_c_str(name),
    )


def _parse_section(raw: bytes) -> SectionInfo:
    name, va, vsize, raw_size, chars = struct.unpack(_SECTION_FMT, raw)
    return SectionInfo(
        name=_c_str(name),
        va=va,
        vsize=vsize,
        raw_size=raw_size,
        characteristics=chars,
    )


def _parse_export(raw: bytes) -> ExportInfo:
    name, ordinal, forwarder, _res, rva, va = struct.unpack(_EXPORT_FMT, raw)
    return ExportInfo(
        name=_c_str(name),
        ordinal=ordinal,
        forwarder=forwarder,
        rva=rva,
        va=va,
    )


def _parse_import(raw: bytes) -> ImportInfo:
    module, name, ordinal, _res, iat_va, bound_va = struct.unpack(_IMPORT_FMT, raw)
    return ImportInfo(
        module=_c_str(module),
        name=_c_str(name),
        ordinal=ordinal,
        iat_va=iat_va,
        bound_va=bound_va,
    )


def _parse_watch_info(raw: bytes) -> WatchInfo:
    handle, addr, size, kind, typ, tid = struct.unpack(_WATCH_INFO_FMT, raw)
    return WatchInfo(
        handle=handle, addr=addr, size=size, kind=kind, type=typ, tid=tid
    )


def _parse_candidate(raw: bytes) -> Candidate:
    (
        cid,
        kind,
        confidence,
        address,
        module_base,
        rva,
        field_offset,
        flags,
        tag,
    ) = struct.unpack(_CANDIDATE_FMT, raw)
    return Candidate(
        id=cid,
        kind=kind,
        confidence=confidence,
        address=address,
        module_base=module_base,
        rva=rva,
        field_offset=field_offset,
        flags=flags,
        tag=_c_str(tag),
    )


def _parse_synth(raw: bytes) -> SynthesizedPattern:
    (
        pattern,
        pattern_offset,
        rip_disp,
        rip_len,
        match_addr,
        resolved_addr,
        unique_hits,
        _res,
    ) = struct.unpack(_SYNTH_FMT, raw)
    return SynthesizedPattern(
        pattern=_c_str(pattern),
        pattern_offset=pattern_offset,
        rip_disp_offset=rip_disp,
        rip_instr_len=rip_len,
        match_addr=match_addr,
        resolved_addr=resolved_addr,
        unique_hits=unique_hits,
    )


def _parse_heat(raw: bytes) -> HeatField:
    offset, changes, kind, size, last = struct.unpack(_HEAT_FMT, raw)
    return HeatField(
        offset=offset, changes=changes, kind=kind, size=size, last_value=last
    )


def _pack_pointer_path(path: PointerPath) -> bytes:
    offs = list(path.offsets) + [0] * (8 - len(path.offsets))
    return struct.pack(
        "<QII" + ("i" * 8),
        path.static_base,
        path.depth,
        0,
        *offs[:8],
    )


class FeatureOpsMixin:
    """Jobs, health, place, code, PE, and discover ops for :class:`Session`."""

    # --- jobs / health / events --------------------------------------------

    def job_create(self, timeout_ms: int = 0) -> int:
        w = Writer()
        w.append_u32(Op.JOB_CREATE)
        w.append_u32(timeout_ms)
        r = self.request(w.data)
        status = r.take_i32()
        job_id = r.take_u64()
        self._check(status, "job_create")
        return job_id

    def job_cancel(self, job_id: int) -> None:
        w = Writer()
        w.append_u32(Op.JOB_CANCEL)
        w.append_u64(job_id)
        r = self.request(w.data)
        self._check(r.take_i32(), "job_cancel")

    def job_close(self, job_id: int) -> None:
        w = Writer()
        w.append_u32(Op.JOB_CLOSE)
        w.append_u64(job_id)
        r = self.request(w.data)
        self._check(r.take_i32(), "job_close")

    def get_health(self) -> HealthInfo:
        w = Writer()
        w.append_u32(Op.GET_HEALTH)
        r = self.request(w.data)
        status = r.take_i32()
        raw = r.take(_HEALTH_SIZE)
        self._check(status, "get_health")
        return _parse_health(raw)

    def threads(self) -> list[ThreadInfo]:
        w = Writer()
        w.append_u32(Op.ENUM_THREADS)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "threads")
        return [_parse_thread(r.take(_THREAD_SIZE)) for _ in range(count)]

    def poll_events(
        self, max_events: int = 16, timeout_ms: int = 0
    ) -> list[Event]:
        w = Writer()
        w.append_u32(Op.POLL_EVENTS)
        w.append_u32(max_events)
        w.append_u32(timeout_ms)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "poll_events")
        return [_parse_event(r.take(_EVENT_SIZE)) for _ in range(count)]

    # --- alloc / place -----------------------------------------------------

    def alloc(
        self, size: int, protect: int = PAGE_EXECUTE_READWRITE
    ) -> int:
        w = Writer()
        w.append_u32(Op.ALLOC)
        w.append_u64(size)
        w.append_u32(protect)
        r = self.request(w.data)
        status = r.take_i32()
        addr = r.take_u64()
        self._check(status, "alloc")
        return addr

    def free(self, addr: int) -> None:
        w = Writer()
        w.append_u32(Op.FREE)
        w.append_u64(addr)
        r = self.request(w.data)
        self._check(r.take_i32(), "free")

    def alloc_near(
        self,
        near_addr: int,
        size: int,
        *,
        max_distance: int = 0x7FFFFFFF,
        protect: int = PAGE_EXECUTE_READWRITE,
    ) -> int:
        w = Writer()
        w.append_u32(Op.ALLOC_NEAR)
        w.append_u64(near_addr)
        w.append_u64(max_distance)
        w.append_u64(size)
        w.append_u32(protect)
        r = self.request(w.data)
        status = r.take_i32()
        addr = r.take_u64()
        self._check(status, "alloc_near")
        return addr

    def find_caves(
        self,
        *,
        min_size: int = 16,
        fill_byte: int = 0xCC,
        near_addr: int = 0,
        max_distance: int = 0,
        flags: int = 0,
        max_results: int = 64,
        module: str | None = None,
    ) -> list[CaveInfo]:
        w = Writer()
        w.append_u32(Op.FIND_CAVES)
        w.append_u32(min_size)
        w.append_u32(fill_byte & 0xFF)
        w.append_u32(flags)
        w.append_u32(max_results)
        w.append_u64(near_addr)
        w.append_u64(max_distance)
        w.append_wstring(module)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "find_caves")
        return [_parse_cave(r.take(_CAVE_SIZE)) for _ in range(count)]

    def protect_memory(self, addr: int, size: int, protect: int) -> int:
        """Change protection; returns previous PAGE_* flags."""
        w = Writer()
        w.append_u32(Op.PROTECT_MEMORY)
        w.append_u64(addr)
        w.append_u64(size)
        w.append_u32(protect)
        r = self.request(w.data)
        status = r.take_i32()
        old = r.take_u32()
        self._check(status, "protect_memory")
        return old

    def flush_icache(self, addr: int, size: int) -> None:
        w = Writer()
        w.append_u32(Op.FLUSH_ICACHE)
        w.append_u64(addr)
        w.append_u64(size)
        r = self.request(w.data)
        self._check(r.take_i32(), "flush_icache")

    # --- resolve / locate extras -------------------------------------------

    def resolve_rip(
        self, addr: int, disp_offset: int = 3, instr_len: int = 7
    ) -> int:
        w = Writer()
        w.append_u32(Op.RESOLVE_RIP)
        w.append_u64(addr)
        w.append_u32(disp_offset)
        w.append_u32(instr_len)
        r = self.request(w.data)
        status = r.take_i32()
        out = r.take_u64()
        self._check(status, "resolve_rip")
        return out

    def find_string_xrefs(
        self,
        text: str | bytes,
        *,
        wide: bool = False,
        xref_flags: int = HDL_STR_XREF_ABSOLUTE | HDL_STR_XREF_RIP_REL,
        search_flags: int = 0,
        max_out: int = 256,
        module: str | None = None,
    ) -> list[int]:
        if isinstance(text, str):
            raw = (
                (text + "\x00").encode("utf-16-le")
                if wide
                else text.encode("utf-8") + b"\x00"
            )
        else:
            raw = bytes(text)
        w = Writer()
        w.append_u32(Op.FIND_STRING_XREFS)
        w.append_u32(len(raw))
        w.append_i32(1 if wide else 0)
        w.append_u32(xref_flags)
        w.append_u32(search_flags)
        w.append_u32(max_out)
        w.append_wstring(module)
        w.append_bytes(raw)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "find_string_xrefs")
        return [r.take_u64() for _ in range(count)]

    # --- disasm / stubs / patches ------------------------------------------

    def disasm_backends(self) -> list[BackendInfo]:
        w = Writer()
        w.append_u32(Op.DISASM_ENUM_BACKENDS)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "disasm_backends")
        return [_parse_backend(r.take(_BACKEND_SIZE)) for _ in range(count)]

    def disasm_get_backend(self) -> int:
        w = Writer()
        w.append_u32(Op.DISASM_GET_BACKEND)
        r = self.request(w.data)
        status = r.take_i32()
        bid = r.take_i32()
        self._check(status, "disasm_get_backend")
        return bid

    def disasm_set_backend(self, backend_id: int) -> None:
        w = Writer()
        w.append_u32(Op.DISASM_SET_BACKEND)
        w.append_i32(backend_id)
        r = self.request(w.data)
        self._check(r.take_i32(), "disasm_set_backend")

    def instr_len(self, addr: int) -> int:
        w = Writer()
        w.append_u32(Op.INSTR_LEN)
        w.append_u64(addr)
        r = self.request(w.data)
        status = r.take_i32()
        length = r.take_u32()
        self._check(status, "instr_len")
        return length

    def disasm(self, addr: int, max_insns: int = 16) -> list[Insn]:
        w = Writer()
        w.append_u32(Op.DISASM)
        w.append_u64(addr)
        w.append_u32(max_insns)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "disasm")
        return [_parse_insn(r.take(_INSN_SIZE)) for _ in range(count)]

    def build_stub(
        self,
        target: int,
        *,
        kind: int = HDL_STUB_ABS_JMP,
        steal_from: int = 0,
        steal_min_bytes: int = 0,
        alloc_rx: bool = True,
        raw: ByteString | None = None,
        flags: int = 0,
    ) -> StubResult:
        raw_bytes = bytes(raw or b"")
        w = Writer()
        w.append_u32(Op.BUILD_STUB)
        w.append_i32(kind)
        w.append_u32(flags)
        w.append_u64(target)
        w.append_u64(steal_from)
        w.append_u32(steal_min_bytes)
        w.append_u32(0)  # reserved
        w.append_u32(1 if alloc_rx else 0)
        w.append_u32(len(raw_bytes))
        if raw_bytes:
            w.append_bytes(raw_bytes)
        r = self.request(w.data)
        status = r.take_i32()
        result = r.take(_STUB_RESULT_SIZE)
        self._check(status, "build_stub")
        return _parse_stub_result(result)

    def patch_create(
        self, addr: int, bytes_: ByteString, name: str | None = None
    ) -> int:
        raw = bytes(bytes_)
        w = Writer()
        w.append_u32(Op.PATCH_CREATE)
        w.append_u64(addr)
        w.append_u32(len(raw))
        w.append_string(name)
        if raw:
            w.append_bytes(raw)
        r = self.request(w.data)
        status = r.take_i32()
        handle = r.take_u64()
        self._check(status, "patch_create")
        return handle

    def patch_enable(self, handle: int, enable: bool = True) -> None:
        w = Writer()
        w.append_u32(Op.PATCH_ENABLE)
        w.append_u64(handle)
        w.append_i32(1 if enable else 0)
        r = self.request(w.data)
        self._check(r.take_i32(), "patch_enable")

    def patch_remove(self, handle: int) -> None:
        w = Writer()
        w.append_u32(Op.PATCH_REMOVE)
        w.append_u64(handle)
        r = self.request(w.data)
        self._check(r.take_i32(), "patch_remove")

    def patch_enum(self) -> list[PatchInfo]:
        w = Writer()
        w.append_u32(Op.PATCH_ENUM)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "patch_enum")
        return [_parse_patch(r.take(_PATCH_SIZE)) for _ in range(count)]

    # --- PE ----------------------------------------------------------------

    def enum_sections(self, module_base: int = 0) -> list[SectionInfo]:
        w = Writer()
        w.append_u32(Op.ENUM_SECTIONS)
        w.append_u64(module_base)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "enum_sections")
        return [_parse_section(r.take(_SECTION_SIZE)) for _ in range(count)]

    def enum_exports(self, module_base: int = 0) -> list[ExportInfo]:
        w = Writer()
        w.append_u32(Op.ENUM_EXPORTS)
        w.append_u64(module_base)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "enum_exports")
        return [_parse_export(r.take(_EXPORT_SIZE)) for _ in range(count)]

    def enum_imports(self, module_base: int = 0) -> list[ImportInfo]:
        w = Writer()
        w.append_u32(Op.ENUM_IMPORTS)
        w.append_u64(module_base)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "enum_imports")
        return [_parse_import(r.take(_IMPORT_SIZE)) for _ in range(count)]

    # --- graph / watch extras ----------------------------------------------

    def resolve_function(
        self,
        addr: int,
        *,
        flags: int = 0,
        module: str | None = None,
    ):
        from .re_ops import _parse_function_info

        w = Writer()
        w.append_u32(Op.RESOLVE_FUNCTION)
        w.append_u64(addr)
        w.append_u32(flags)
        w.append_wstring(module)
        r = self.request(w.data)
        status = r.take_i32()
        self._check(status, "resolve_function")
        return _parse_function_info(r.take(_FUNCTION_INFO_SIZE))

    def invalidate_fn_index(self, module: str | None = None) -> None:
        w = Writer()
        w.append_u32(Op.INVALIDATE_FN_INDEX)
        w.append_wstring(module)
        r = self.request(w.data)
        self._check(r.take_i32(), "invalidate_fn_index")

    def enum_watches(self) -> list[WatchInfo]:
        w = Writer()
        w.append_u32(Op.ENUM_WATCHES)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "enum_watches")
        return [_parse_watch_info(r.take(_WATCH_INFO_SIZE)) for _ in range(count)]

    def watch_refresh(self) -> None:
        w = Writer()
        w.append_u32(Op.WATCH_REFRESH)
        r = self.request(w.data)
        self._check(r.take_i32(), "watch_refresh")

    # --- discover ----------------------------------------------------------

    def discover_create(self) -> int:
        w = Writer()
        w.append_u32(Op.DISCOVER_CREATE)
        r = self.request(w.data)
        status = r.take_i32()
        sid = r.take_u64()
        self._check(status, "discover_create")
        return sid

    def discover_close(self, session: int) -> None:
        w = Writer()
        w.append_u32(Op.DISCOVER_CLOSE)
        w.append_u64(session)
        r = self.request(w.data)
        self._check(r.take_i32(), "discover_close")

    def discover_add_candidate(
        self,
        session: int,
        address: int,
        *,
        kind: int = HDL_CAND_ADDRESS,
        tag: str | None = None,
    ) -> int:
        w = Writer()
        w.append_u32(Op.DISCOVER_ADD_CANDIDATE)
        w.append_u64(session)
        w.append_u32(kind)
        w.append_u64(address)
        w.append_string(tag)
        r = self.request(w.data)
        status = r.take_i32()
        cand_id = r.take_u64()
        self._check(status, "discover_add_candidate")
        return cand_id

    def discover_constraint_scan(
        self,
        session: int,
        object_size: int,
        preds: list[FieldPred],
        *,
        flags: int = 0,
        max_results: int = 64,
        module: str | None = None,
        tag: str | None = None,
    ) -> None:
        w = Writer()
        w.append_u32(Op.DISCOVER_CONSTRAINT_SCAN)
        w.append_u64(session)
        w.append_u32(object_size)
        w.append_u32(len(preds))
        w.append_u32(flags)
        w.append_u32(max_results)
        w.append_wstring(module)
        w.append_string(tag)
        for p in preds:
            w.append_bytes(p.pack())
        r = self.request(w.data)
        self._check(r.take_i32(), "discover_constraint_scan")

    def discover_synthesize_pattern(
        self,
        session: int,
        cand_id: int,
        *,
        before: int = 16,
        after: int = 16,
        flags: int = 0,
        module: str | None = None,
    ) -> SynthesizedPattern:
        w = Writer()
        w.append_u32(Op.DISCOVER_SYNTHESIZE_PATTERN)
        w.append_u64(session)
        w.append_u64(cand_id)
        w.append_u32(before)
        w.append_u32(after)
        w.append_u32(flags)
        w.append_wstring(module)
        r = self.request(w.data)
        status = r.take_i32()
        raw = r.take(_SYNTH_SIZE)
        self._check(status, "discover_synthesize_pattern")
        return _parse_synth(raw)

    def discover_path_consensus(
        self,
        target: int,
        *,
        depth: int = 2,
        max_offset: int = 0x1000,
        max_n: int = 32,
        flags: int = 0,
        module: str | None = None,
    ) -> list[PointerPath]:
        w = Writer()
        w.append_u32(Op.DISCOVER_PATH_CONSENSUS)
        w.append_u64(target)
        w.append_u32(depth)
        w.append_u32(max_offset)
        w.append_u32(max_n)
        w.append_u32(flags)
        w.append_wstring(module)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "discover_path_consensus")
        return [_parse_pointer_path(r.take(_POINTER_PATH_SIZE)) for _ in range(count)]

    def discover_path_validate(
        self, expected: int, paths: list[PointerPath]
    ) -> list[PointerPath]:
        w = Writer()
        w.append_u32(Op.DISCOVER_PATH_VALIDATE)
        w.append_u64(expected)
        w.append_u32(len(paths))
        for p in paths:
            w.append_bytes(_pack_pointer_path(p))
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "discover_path_validate")
        return [_parse_pointer_path(r.take(_POINTER_PATH_SIZE)) for _ in range(count)]

    def discover_watch(
        self, session: int, fn: int, arg_count: int = 0
    ) -> None:
        w = Writer()
        w.append_u32(Op.DISCOVER_WATCH)
        w.append_u64(session)
        w.append_u64(fn)
        w.append_u32(arg_count)
        r = self.request(w.data)
        self._check(r.take_i32(), "discover_watch")

    def discover_unwatch_all(self, session: int) -> None:
        w = Writer()
        w.append_u32(Op.DISCOVER_UNWATCH_ALL)
        w.append_u64(session)
        r = self.request(w.data)
        self._check(r.take_i32(), "discover_unwatch_all")

    def discover_action_begin(self, session: int, name: str) -> None:
        w = Writer()
        w.append_u32(Op.DISCOVER_ACTION_BEGIN)
        w.append_u64(session)
        w.append_string(name)
        r = self.request(w.data)
        self._check(r.take_i32(), "discover_action_begin")

    def discover_action_end(self, session: int) -> None:
        w = Writer()
        w.append_u32(Op.DISCOVER_ACTION_END)
        w.append_u64(session)
        r = self.request(w.data)
        self._check(r.take_i32(), "discover_action_end")

    def discover_watch_region(
        self, session: int, base: int, size: int
    ) -> None:
        w = Writer()
        w.append_u32(Op.DISCOVER_WATCH_REGION)
        w.append_u64(session)
        w.append_u64(base)
        w.append_u32(size)
        r = self.request(w.data)
        self._check(r.take_i32(), "discover_watch_region")

    def discover_get_heat(
        self, session: int, base: int, max_fields: int = 64
    ) -> list[HeatField]:
        w = Writer()
        w.append_u32(Op.DISCOVER_GET_HEAT)
        w.append_u64(session)
        w.append_u64(base)
        w.append_u32(max_fields)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "discover_get_heat")
        return [_parse_heat(r.take(_HEAT_SIZE)) for _ in range(count)]

    def discover_rank_functions(
        self,
        session: int,
        action: str,
        *,
        flags: int = 0,
        max_out: int = 64,
    ) -> list[Candidate]:
        w = Writer()
        w.append_u32(Op.DISCOVER_RANK_FUNCTIONS)
        w.append_u64(session)
        w.append_string(action)
        w.append_u32(flags)
        w.append_u32(max_out)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "discover_rank_functions")
        return [_parse_candidate(r.take(_CANDIDATE_SIZE)) for _ in range(count)]

    def discover_cluster_type(
        self,
        session: int,
        seed: int,
        object_size: int,
        *,
        flags: int = 0,
        max_results: int = 64,
        module: str | None = None,
    ) -> None:
        w = Writer()
        w.append_u32(Op.DISCOVER_CLUSTER_TYPE)
        w.append_u64(session)
        w.append_u64(seed)
        w.append_u32(object_size)
        w.append_u32(flags)
        w.append_u32(max_results)
        w.append_wstring(module)
        r = self.request(w.data)
        self._check(r.take_i32(), "discover_cluster_type")

    def discover_get_candidates(
        self, session: int, max_out: int = 256
    ) -> list[Candidate]:
        w = Writer()
        w.append_u32(Op.DISCOVER_GET_CANDIDATES)
        w.append_u64(session)
        w.append_u32(max_out)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "discover_get_candidates")
        return [_parse_candidate(r.take(_CANDIDATE_SIZE)) for _ in range(count)]

    def discover_watch_import(
        self,
        session: int,
        dll: str,
        import_name: str,
        *,
        module: str | None = None,
        arg_count: int = 0,
    ) -> None:
        w = Writer()
        w.append_u32(Op.DISCOVER_WATCH_IMPORT)
        w.append_u64(session)
        w.append_wstring(module)
        w.append_string(dll)
        w.append_string(import_name)
        w.append_u32(arg_count)
        r = self.request(w.data)
        self._check(r.take_i32(), "discover_watch_import")

    def discover_reset_heat(self, session: int, base: int) -> None:
        w = Writer()
        w.append_u32(Op.DISCOVER_RESET_HEAT)
        w.append_u64(session)
        w.append_u64(base)
        r = self.request(w.data)
        self._check(r.take_i32(), "discover_reset_heat")

    def discover_export(self, session: int, cap: int = 65536) -> str:
        w = Writer()
        w.append_u32(Op.DISCOVER_EXPORT)
        w.append_u64(session)
        w.append_u32(cap)
        r = self.request(w.data)
        status = r.take_i32()
        size = r.take_u32()
        self._check(status, "discover_export")
        raw = r.take(size) if size else b""
        if raw.endswith(b"\x00"):
            raw = raw[:-1]
        return raw.decode("utf-8", errors="replace")

    def discover_import(self, session: int, json_text: str) -> None:
        w = Writer()
        w.append_u32(Op.DISCOVER_IMPORT)
        w.append_u64(session)
        w.append_string(json_text)
        r = self.request(w.data)
        self._check(r.take_i32(), "discover_import")

    def discover_diff_objects(
        self,
        session: int,
        addrs: list[int],
        *,
        max_size: int = 256,
        max_fields: int = 64,
    ) -> list[HeatField]:
        w = Writer()
        w.append_u32(Op.DISCOVER_DIFF_OBJECTS)
        w.append_u64(session)
        w.append_u32(len(addrs))
        w.append_u32(max_size)
        w.append_u32(max_fields)
        for a in addrs:
            w.append_u64(a)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "discover_diff_objects")
        return [_parse_heat(r.take(_HEAT_SIZE)) for _ in range(count)]

    def discover_apply_watch_hits(
        self, session: int, object_base: int, size: int
    ) -> None:
        w = Writer()
        w.append_u32(Op.DISCOVER_APPLY_WATCH_HITS)
        w.append_u64(session)
        w.append_u64(object_base)
        w.append_u32(size)
        r = self.request(w.data)
        self._check(r.take_i32(), "discover_apply_watch_hits")

    def discover_get_evidence(
        self, session: int, cand_id: int, cap: int = 160
    ) -> str:
        w = Writer()
        w.append_u32(Op.DISCOVER_GET_EVIDENCE)
        w.append_u64(session)
        w.append_u64(cand_id)
        w.append_u32(cap)
        r = self.request(w.data)
        status = r.take_i32()
        text = r.take_string()
        self._check(status, "discover_get_evidence")
        return text
