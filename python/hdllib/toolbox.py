"""Cheat Engine / ReClass-style facades over :class:`HdlClient`.

Short names for the Python REPL: ``mem``, ``scan``, ``hooks``, ``watches``,
``structs``, ``graph``, ``place``, ``code``, ``pe``, ``health``, ``discover``
— plus ``dbg`` (:class:`DebugSession`) and ``hdl``.
"""

from __future__ import annotations

import struct
from typing import ByteString

from .client import CallArg, HdlClient, attach
from .feature_ops import (
    BackendInfo,
    Candidate,
    CaveInfo,
    Event,
    ExportInfo,
    FieldPred,
    HealthInfo,
    HeatField,
    ImportInfo,
    Insn,
    PatchInfo,
    SectionInfo,
    StubResult,
    SynthesizedPattern,
    ThreadInfo,
    WatchInfo,
)
from .inject import INJECT_CREATE_REMOTE_THREAD
from .protocol import (
    HDL_CAND_ADDRESS,
    HDL_CMP_CHANGED,
    HDL_CMP_EXACT,
    HDL_CMP_UNKNOWN,
    HDL_SEARCH_IMAGE,
    HDL_VALUE_F32,
    HDL_VALUE_F64,
    HDL_VALUE_I64,
    HDL_VALUE_U64,
    HDL_WATCH_HW_WRITE,
    HDL_WATCH_PAGE_GUARD,
    HDL_XREF_CALL,
    HDL_XREF_FUNC,
    HDL_XREF_JMP,
    PAGE_EXECUTE_READWRITE,
)
from .re_ops import (
    FunctionInfo,
    PatternResult,
    PointerPath,
    StructField,
    WatchHit,
    XrefEdge,
)


class Memory:
    """Typed memory read/write helpers."""

    __slots__ = ("_hdl",)

    def __init__(self, hdl: HdlClient) -> None:
        self._hdl = hdl

    def read(self, address: int, size: int) -> bytes:
        return self._hdl.read(address, size)

    def write(self, address: int, data: ByteString) -> int:
        return self._hdl.write(address, data)

    def u8(self, address: int) -> int:
        return struct.unpack_from("<B", self.read(address, 1))[0]

    def i8(self, address: int) -> int:
        return struct.unpack_from("<b", self.read(address, 1))[0]

    def u16(self, address: int) -> int:
        return struct.unpack_from("<H", self.read(address, 2))[0]

    def i16(self, address: int) -> int:
        return struct.unpack_from("<h", self.read(address, 2))[0]

    def u32(self, address: int) -> int:
        return struct.unpack_from("<I", self.read(address, 4))[0]

    def i32(self, address: int) -> int:
        return struct.unpack_from("<i", self.read(address, 4))[0]

    def u64(self, address: int) -> int:
        return struct.unpack_from("<Q", self.read(address, 8))[0]

    def i64(self, address: int) -> int:
        return struct.unpack_from("<q", self.read(address, 8))[0]

    def ptr(self, address: int) -> int:
        return self.u64(address)

    def f32(self, address: int) -> float:
        return struct.unpack_from("<f", self.read(address, 4))[0]

    def f64(self, address: int) -> float:
        return struct.unpack_from("<d", self.read(address, 8))[0]

    def write_u8(self, address: int, value: int) -> int:
        return self.write(address, struct.pack("<B", value & 0xFF))

    def write_i8(self, address: int, value: int) -> int:
        return self.write(address, struct.pack("<b", int(value)))

    def write_u16(self, address: int, value: int) -> int:
        return self.write(address, struct.pack("<H", value & 0xFFFF))

    def write_i16(self, address: int, value: int) -> int:
        return self.write(address, struct.pack("<h", int(value)))

    def write_u32(self, address: int, value: int) -> int:
        return self.write(address, struct.pack("<I", value & 0xFFFFFFFF))

    def write_i32(self, address: int, value: int) -> int:
        return self.write(address, struct.pack("<i", int(value)))

    def write_u64(self, address: int, value: int) -> int:
        return self.write(address, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))

    def write_i64(self, address: int, value: int) -> int:
        return self.write(address, struct.pack("<q", int(value)))

    def write_ptr(self, address: int, value: int) -> int:
        return self.write_u64(address, value)

    def write_f32(self, address: int, value: float) -> int:
        return self.write(address, struct.pack("<f", float(value)))

    def write_f64(self, address: int, value: float) -> int:
        return self.write(address, struct.pack("<d", float(value)))


class SearchSession:
    """Context-managed incremental CE-style value scan."""

    __slots__ = ("_hdl", "_id", "_closed")

    def __init__(self, hdl: HdlClient) -> None:
        self._hdl = hdl
        self._id = hdl.search_create()
        self._closed = False

    @property
    def id(self) -> int:
        return self._id

    def __enter__(self) -> SearchSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._hdl.search_close(self._id)
            self._closed = True

    def reset(self) -> None:
        self._hdl.search_reset(self._id)

    def first(
        self,
        value: bytes,
        *,
        value_type: int,
        cmp: int = HDL_CMP_EXACT,
        start: int = 0,
        size: int = 0,
        alignment: int = 0,
        max_results: int = 64,
        flags: int = 0,
        module: str | None = None,
    ) -> int:
        return self._hdl.search_first(
            self._id,
            value=value,
            value_type=value_type,
            cmp=cmp,
            start=start,
            size=size,
            alignment=alignment,
            max_results=max_results,
            flags=flags,
            module=module,
        )

    def next(self, cmp: int, value: bytes = b"") -> int:
        return self._hdl.search_next(self._id, cmp=cmp, value=value)

    def hits(self, max_hits: int = 64) -> list[int]:
        return self._hdl.search_get_hits(self._id, max_hits=max_hits)

    def unknown(
        self,
        value_type: int,
        *,
        max_results: int = 64,
        flags: int = 0,
        module: str | None = None,
    ) -> int:
        return self.first(
            b"",
            value_type=value_type,
            cmp=HDL_CMP_UNKNOWN,
            max_results=max_results,
            flags=flags,
            module=module,
        )

    def changed(self) -> int:
        return self.next(HDL_CMP_CHANGED)


class Scanner:
    """AOB / value search, pattern resolve, pointer scan/follow."""

    __slots__ = ("_hdl",)

    def __init__(self, hdl: HdlClient) -> None:
        self._hdl = hdl

    def session(self) -> SearchSession:
        return SearchSession(self._hdl)

    def aob(
        self,
        pattern: str,
        *,
        start: int = 0,
        size: int = 0,
        max_hits: int = 64,
    ) -> list[int]:
        return self._hdl.search(pattern, start=start, size=size, max_hits=max_hits)

    def u32(
        self,
        value: int,
        *,
        max_results: int = 64,
        flags: int = 0,
        module: str | None = None,
    ) -> tuple[int, list[int]]:
        return self._hdl.scan_u32(
            value, max_results=max_results, flags=flags, module=module
        )

    def i32(
        self,
        value: int,
        *,
        max_results: int = 64,
        flags: int = 0,
        module: str | None = None,
    ) -> tuple[int, list[int]]:
        return self._hdl.scan_i32(
            value, max_results=max_results, flags=flags, module=module
        )

    def u64(
        self,
        value: int,
        *,
        max_results: int = 64,
        flags: int = 0,
        module: str | None = None,
    ) -> list[int]:
        with self.session() as s:
            s.first(
                struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF),
                value_type=HDL_VALUE_U64,
                max_results=max_results,
                flags=flags,
                module=module,
            )
            return s.hits(max_hits=max_results)

    def i64(
        self,
        value: int,
        *,
        max_results: int = 64,
        flags: int = 0,
        module: str | None = None,
    ) -> list[int]:
        with self.session() as s:
            s.first(
                struct.pack("<q", int(value)),
                value_type=HDL_VALUE_I64,
                max_results=max_results,
                flags=flags,
                module=module,
            )
            return s.hits(max_hits=max_results)

    def f32(
        self,
        value: float,
        *,
        max_results: int = 64,
        flags: int = 0,
        module: str | None = None,
    ) -> list[int]:
        with self.session() as s:
            s.first(
                struct.pack("<f", float(value)),
                value_type=HDL_VALUE_F32,
                max_results=max_results,
                flags=flags,
                module=module,
            )
            return s.hits(max_hits=max_results)

    def f64(
        self,
        value: float,
        *,
        max_results: int = 64,
        flags: int = 0,
        module: str | None = None,
    ) -> list[int]:
        with self.session() as s:
            s.first(
                struct.pack("<d", float(value)),
                value_type=HDL_VALUE_F64,
                max_results=max_results,
                flags=flags,
                module=module,
            )
            return s.hits(max_hits=max_results)

    def follow_pointers(
        self, base: int, offsets: list[int] | tuple[int, ...]
    ) -> int:
        return self._hdl.follow_pointers(base, offsets)

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
        return self._hdl.pointer_scan(
            target,
            depth=depth,
            max_offset=max_offset,
            max_n=max_n,
            flags=flags,
            module=module,
        )

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
        return self._hdl.resolve_pattern(
            pattern,
            hit_index=hit_index,
            pattern_offset=pattern_offset,
            rip_disp_offset=rip_disp_offset,
            rip_instr_len=rip_instr_len,
            follow_offsets=follow_offsets,
            flags=flags,
            module=module,
            max_scan_hits=max_scan_hits,
        )

    def resolve_rip(
        self, addr: int, disp_offset: int = 3, instr_len: int = 7
    ) -> int:
        return self._hdl.resolve_rip(addr, disp_offset, instr_len)

    def string_xrefs(self, text: str, **kwargs) -> list[int]:
        return self._hdl.find_string_xrefs(text, **kwargs)


class Hooks:
    """Trace hooks and import hooks."""

    __slots__ = ("_hdl",)

    def __init__(self, hdl: HdlClient) -> None:
        self._hdl = hdl

    def trace(self, target: int, arg_count: int = 0) -> int:
        return self._hdl.hook_trace(target, arg_count=arg_count)

    def import_(
        self,
        dll: str,
        import_name: str,
        *,
        module: str | None = None,
        arg_count: int = 0,
    ) -> int:
        return self._hdl.hook_import(
            dll, import_name, module=module, arg_count=arg_count
        )

    def enable(self, handle: int, enable: bool = True) -> None:
        self._hdl.enable_hook(handle, enable)

    def unhook(self, handle: int) -> None:
        self._hdl.unhook(handle)

    def poll(self, max_n: int = 16, timeout_ms: int = 0):
        return self._hdl.poll_hook_hits(max_n=max_n, timeout_ms=timeout_ms)


class Watches:
    """Hardware and page watchpoints."""

    __slots__ = ("_hdl",)

    def __init__(self, hdl: HdlClient) -> None:
        self._hdl = hdl

    def hw(
        self,
        addr: int,
        size: int = 1,
        *,
        access: int = HDL_WATCH_HW_WRITE,
        tid: int = 0,
    ) -> int:
        return self._hdl.watch_hw(addr, size, access=access, tid=tid)

    def page(
        self,
        addr: int,
        size: int,
        *,
        mode: int = HDL_WATCH_PAGE_GUARD,
    ) -> int:
        return self._hdl.watch_page(addr, size, mode=mode)

    def unwatch(self, handle: int) -> None:
        self._hdl.unwatch(handle)

    def list(self) -> list[WatchInfo]:
        return self._hdl.enum_watches()

    def refresh(self) -> None:
        self._hdl.watch_refresh()

    def poll(self, max_n: int = 32, timeout_ms: int = 0) -> list[WatchHit]:
        return self._hdl.poll_watch_hits(max_n=max_n, timeout_ms=timeout_ms)


class Structs:
    """Structure probe, vtable walk, RTTI, vtable call."""

    __slots__ = ("_hdl",)

    def __init__(self, hdl: HdlClient) -> None:
        self._hdl = hdl

    def probe(
        self, addr: int, size: int = 64, *, max_fields: int = 64
    ) -> list[StructField]:
        return self._hdl.probe_struct(addr, size, max_fields=max_fields)

    def walk_vtable(self, addr: int, *, is_object: bool = True) -> list[int]:
        return self._hdl.walk_vtable(addr, is_object=is_object)

    def rtti(self, addr: int, *, is_object: bool = True) -> str:
        return self._hdl.query_rtti(addr, is_object=is_object)

    def call_vtable(
        self,
        obj: int,
        index: int,
        args: list[CallArg] | None = None,
        **kwargs,
    ):
        return self._hdl.call_vtable(obj, index, args, **kwargs)


class Graph:
    """Function enum and xref graph."""

    __slots__ = ("_hdl",)

    def __init__(self, hdl: HdlClient) -> None:
        self._hdl = hdl

    def functions(
        self,
        *,
        start: int = 0,
        size: int = 0,
        flags: int = 0,
        max_results: int = 64,
        module: str | None = None,
    ) -> list[FunctionInfo]:
        return self._hdl.enum_functions(
            start=start,
            size=size,
            flags=flags,
            max_results=max_results,
            module=module,
        )

    def resolve(
        self, addr: int, *, flags: int = 0, module: str | None = None
    ) -> FunctionInfo:
        return self._hdl.resolve_function(addr, flags=flags, module=module)

    def invalidate(self, module: str | None = None) -> None:
        self._hdl.invalidate_fn_index(module)

    def xrefs_from(
        self,
        seed: int,
        *,
        depth: int = 2,
        max_nodes: int = 64,
        kinds: int = 0,
    ) -> list[XrefEdge]:
        return self._hdl.xrefs_from(
            seed, depth=depth, max_nodes=max_nodes, kinds=kinds
        )

    def xrefs_to(
        self,
        target: int,
        *,
        max_nodes: int = 64,
        kinds: int = HDL_XREF_CALL | HDL_XREF_JMP | HDL_XREF_FUNC,
        flags: int = 0,
        module: str | None = None,
    ) -> list[XrefEdge]:
        return self._hdl.xrefs_to(
            target,
            max_nodes=max_nodes,
            kinds=kinds,
            flags=flags,
            module=module,
        )


class Place:
    """Caves, nearby alloc, protect, and I-cache flush."""

    __slots__ = ("_hdl",)

    def __init__(self, hdl: HdlClient) -> None:
        self._hdl = hdl

    def alloc(
        self, size: int, protect: int = PAGE_EXECUTE_READWRITE
    ) -> int:
        return self._hdl.alloc(size, protect)

    def free(self, addr: int) -> None:
        self._hdl.free(addr)

    def alloc_near(
        self,
        near_addr: int,
        size: int,
        *,
        max_distance: int = 0x7FFFFFFF,
        protect: int = PAGE_EXECUTE_READWRITE,
    ) -> int:
        return self._hdl.alloc_near(
            near_addr, size, max_distance=max_distance, protect=protect
        )

    def caves(self, **kwargs) -> list[CaveInfo]:
        return self._hdl.find_caves(**kwargs)

    def protect(self, addr: int, size: int, protect: int) -> int:
        return self._hdl.protect_memory(addr, size, protect)

    def flush(self, addr: int, size: int) -> None:
        self._hdl.flush_icache(addr, size)


class Code:
    """Disassembly backends, stubs, and the reversible patch ledger."""

    __slots__ = ("_hdl",)

    def __init__(self, hdl: HdlClient) -> None:
        self._hdl = hdl

    def backends(self) -> list[BackendInfo]:
        return self._hdl.disasm_backends()

    def backend(self) -> int:
        return self._hdl.disasm_get_backend()

    def set_backend(self, backend_id: int) -> None:
        self._hdl.disasm_set_backend(backend_id)

    def instr_len(self, addr: int) -> int:
        return self._hdl.instr_len(addr)

    def disasm(self, addr: int, max_insns: int = 16) -> list[Insn]:
        return self._hdl.disasm(addr, max_insns=max_insns)

    def stub(self, target: int, **kwargs) -> StubResult:
        return self._hdl.build_stub(target, **kwargs)

    def patch(
        self, addr: int, bytes_: ByteString, name: str | None = None
    ) -> int:
        """Create and enable a patch; returns handle."""
        handle = self._hdl.patch_create(addr, bytes_, name=name)
        self._hdl.patch_enable(handle, True)
        return handle

    def patch_create(
        self, addr: int, bytes_: ByteString, name: str | None = None
    ) -> int:
        return self._hdl.patch_create(addr, bytes_, name=name)

    def enable(self, handle: int, enable: bool = True) -> None:
        self._hdl.patch_enable(handle, enable)

    def remove(self, handle: int) -> None:
        self._hdl.patch_remove(handle)

    def patches(self) -> list[PatchInfo]:
        return self._hdl.patch_enum()


class Pe:
    """PE section / export / import metadata for a module."""

    __slots__ = ("_hdl",)

    def __init__(self, hdl: HdlClient) -> None:
        self._hdl = hdl

    def sections(self, module_base: int = 0) -> list[SectionInfo]:
        return self._hdl.enum_sections(module_base)

    def exports(self, module_base: int = 0) -> list[ExportInfo]:
        return self._hdl.enum_exports(module_base)

    def imports(self, module_base: int = 0) -> list[ImportInfo]:
        return self._hdl.enum_imports(module_base)

    def find_export(
        self, name: str, module_base: int = 0
    ) -> ExportInfo | None:
        key = name.lower()
        for e in self.exports(module_base):
            if e.name.lower() == key:
                return e
        return None

    def find_import(
        self, dll: str, name: str, module_base: int = 0
    ) -> ImportInfo | None:
        dll_key = dll.lower()
        name_key = name.lower()
        for i in self.imports(module_base):
            if i.module.lower() == dll_key and i.name.lower() == name_key:
                return i
        return None


class Health:
    """Process health, threads, events, and cooperative jobs."""

    __slots__ = ("_hdl",)

    def __init__(self, hdl: HdlClient) -> None:
        self._hdl = hdl

    def snapshot(self) -> HealthInfo:
        return self._hdl.get_health()

    def threads(self) -> list[ThreadInfo]:
        return self._hdl.threads()

    def events(
        self, max_events: int = 16, timeout_ms: int = 0
    ) -> list[Event]:
        return self._hdl.poll_events(max_events=max_events, timeout_ms=timeout_ms)

    def job(self, timeout_ms: int = 0) -> Job:
        return Job(self._hdl, timeout_ms=timeout_ms)


class Job:
    """Context-managed cooperative cancel/timeout token."""

    __slots__ = ("_hdl", "_id", "_closed")

    def __init__(self, hdl: HdlClient, timeout_ms: int = 0) -> None:
        self._hdl = hdl
        self._id = hdl.job_create(timeout_ms)
        self._closed = False

    @property
    def id(self) -> int:
        return self._id

    def __enter__(self) -> Job:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def cancel(self) -> None:
        self._hdl.job_cancel(self._id)

    def close(self) -> None:
        if not self._closed:
            self._hdl.job_close(self._id)
            self._closed = True


class DiscoverSession:
    """Context-managed discover pipeline (seed → evidence → stabilize)."""

    __slots__ = ("_hdl", "_id", "_closed")

    def __init__(self, hdl: HdlClient) -> None:
        self._hdl = hdl
        self._id = hdl.discover_create()
        self._closed = False

    @property
    def id(self) -> int:
        return self._id

    def __enter__(self) -> DiscoverSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._hdl.discover_close(self._id)
            self._closed = True

    def add(
        self,
        address: int,
        *,
        kind: int = HDL_CAND_ADDRESS,
        tag: str | None = None,
    ) -> int:
        return self._hdl.discover_add_candidate(
            self._id, address, kind=kind, tag=tag
        )

    def constraint(
        self,
        object_size: int,
        preds: list[FieldPred],
        **kwargs,
    ) -> None:
        self._hdl.discover_constraint_scan(
            self._id, object_size, preds, **kwargs
        )

    def synthesize(
        self, cand_id: int, **kwargs
    ) -> SynthesizedPattern:
        return self._hdl.discover_synthesize_pattern(
            self._id, cand_id, **kwargs
        )

    def path_consensus(self, target: int, **kwargs) -> list[PointerPath]:
        return self._hdl.discover_path_consensus(target, **kwargs)

    def path_validate(
        self, expected: int, paths: list[PointerPath]
    ) -> list[PointerPath]:
        return self._hdl.discover_path_validate(expected, paths)

    def watch(self, fn: int, arg_count: int = 0) -> None:
        self._hdl.discover_watch(self._id, fn, arg_count=arg_count)

    def watch_import(self, dll: str, import_name: str, **kwargs) -> None:
        self._hdl.discover_watch_import(
            self._id, dll, import_name, **kwargs
        )

    def unwatch_all(self) -> None:
        self._hdl.discover_unwatch_all(self._id)

    def action_begin(self, name: str) -> None:
        self._hdl.discover_action_begin(self._id, name)

    def action_end(self) -> None:
        self._hdl.discover_action_end(self._id)

    def watch_region(self, base: int, size: int) -> None:
        self._hdl.discover_watch_region(self._id, base, size)

    def heat(self, base: int, max_fields: int = 64) -> list[HeatField]:
        return self._hdl.discover_get_heat(
            self._id, base, max_fields=max_fields
        )

    def reset_heat(self, base: int) -> None:
        self._hdl.discover_reset_heat(self._id, base)

    def rank(self, action: str, **kwargs) -> list[Candidate]:
        return self._hdl.discover_rank_functions(
            self._id, action, **kwargs
        )

    def cluster(self, seed: int, object_size: int, **kwargs) -> None:
        self._hdl.discover_cluster_type(
            self._id, seed, object_size, **kwargs
        )

    def candidates(self, max_out: int = 256) -> list[Candidate]:
        return self._hdl.discover_get_candidates(self._id, max_out=max_out)

    def export_json(self, cap: int = 65536) -> str:
        return self._hdl.discover_export(self._id, cap=cap)

    def import_json(self, json_text: str) -> None:
        self._hdl.discover_import(self._id, json_text)

    def diff_objects(self, addrs: list[int], **kwargs) -> list[HeatField]:
        return self._hdl.discover_diff_objects(self._id, addrs, **kwargs)

    def apply_watch_hits(self, object_base: int, size: int) -> None:
        self._hdl.discover_apply_watch_hits(self._id, object_base, size)

    def evidence(self, cand_id: int) -> str:
        return self._hdl.discover_get_evidence(self._id, cand_id)


class DebugSession:
    """Bundled RE toolbox around a connected :class:`HdlClient`."""

    def __init__(self, hdl: HdlClient) -> None:
        self.hdl = hdl
        self.mem = Memory(hdl)
        self.scan = Scanner(hdl)
        self.hooks = Hooks(hdl)
        self.watches = Watches(hdl)
        self.structs = Structs(hdl)
        self.graph = Graph(hdl)
        self.place = Place(hdl)
        self.code = Code(hdl)
        self.pe = Pe(hdl)
        self.health = Health(hdl)

    @property
    def pid(self) -> int:
        return self.hdl.pid

    @property
    def connected(self) -> bool:
        return self.hdl.connected

    def __enter__(self) -> DebugSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.hdl.close()

    def discover(self) -> DiscoverSession:
        return DiscoverSession(self.hdl)

    def search(self) -> SearchSession:
        return SearchSession(self.hdl)

    def locals_dict(self) -> dict[str, object]:
        """Names bound into the interactive Python REPL."""
        from .strategies import strategies_locals

        ns: dict[str, object] = {
            "dbg": self,
            "hdl": self.hdl,
            "mem": self.mem,
            "scan": self.scan,
            "hooks": self.hooks,
            "watches": self.watches,
            "structs": self.structs,
            "graph": self.graph,
            "place": self.place,
            "code": self.code,
            "pe": self.pe,
            "health": self.health,
            "CallArg": CallArg,
            "DiscoverSession": DiscoverSession,
            "FieldPred": FieldPred,
            "HdlClient": HdlClient,
            "SearchSession": SearchSession,
        }
        ns.update(strategies_locals(self))
        return ns


def open_debug_session(
    pid: int,
    *,
    inject: bool = True,
    method: int = INJECT_CREATE_REMOTE_THREAD,
    dll: str | None = None,
    timeout_ms: int = 10000,
) -> DebugSession:
    """Attach (optionally inject) and wrap an :class:`HdlClient` in a toolbox."""
    hdl = attach(
        pid, inject=inject, method=method, dll=dll, timeout_ms=timeout_ms
    )
    return DebugSession(hdl)
