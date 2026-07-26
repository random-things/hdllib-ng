"""Cheat-Engine-style strategies built on the toolbox facades.

Maps common CE tutorial workflows
(https://wiki.cheatengine.org/index.php?title=Tutorials:Cheat_Engine_Tutorial_Guide_x64)
onto hdllib ops:

| CE tutorial idea              | Helper here              | Underlying classes      |
|-------------------------------|--------------------------|-------------------------|
| Exact / unknown / float scan  | :class:`ValueScan`       | ``SearchSession``       |
| Address list + freeze         | :class:`CheatTable`      | ``Memory``              |
| Find what accesses            | :class:`AccessFinder`    | ``Watches`` + ``Code``  |
| Replace with NOP / restore    | :class:`CodePatcher`     | ``Code``                |
| Pointers / multilevel         | :class:`PointerHelper`   | ``Scanner`` / discover  |
| Code / AOB injection          | :class:`AobInjector`     | ``Place`` + ``Code``    |
| Structure / shared-code filter| :class:`StructHelper`    | ``Structs`` / discover  |
"""

from __future__ import annotations

import struct
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, ByteString, Callable

from .protocol import (
    HDL_CMP_CHANGED,
    HDL_CMP_DECREASED,
    HDL_CMP_DECREASED_BY,
    HDL_CMP_EXACT,
    HDL_CMP_INCREASED,
    HDL_CMP_INCREASED_BY,
    HDL_CMP_UNCHANGED,
    HDL_CMP_UNKNOWN,
    HDL_SEARCH_IMAGE,
    HDL_SEARCH_MODULE,
    HDL_STUB_ABS_JMP,
    HDL_VALUE_F32,
    HDL_VALUE_F64,
    HDL_VALUE_I32,
    HDL_VALUE_U32,
    HDL_VALUE_U64,
    HDL_WATCH_HW_WRITE,
    PAGE_EXECUTE_READWRITE,
)
from .re_ops import FunctionInfo, PointerPath, StructField
from .toolbox import (
    Code,
    DiscoverSession,
    Graph,
    Memory,
    Place,
    Scanner,
    SearchSession,
    Structs,
    Watches,
)

if TYPE_CHECKING:
    from .client import HdlClient
    from .feature_ops import Insn
    from .toolbox import DebugSession

__all__ = [
    "AccessFinder",
    "AccessHit",
    "AobInjector",
    "CheatEntry",
    "CheatTable",
    "CodePatcher",
    "PointerHelper",
    "StructHelper",
    "ValueScan",
    "strategies_locals",
]


# ---------------------------------------------------------------------------
# Value scanning (CE steps 2–4)
# ---------------------------------------------------------------------------


def _pack_value(value: int | float, value_type: int) -> bytes:
    if value_type == HDL_VALUE_I32:
        return struct.pack("<i", int(value))
    if value_type == HDL_VALUE_U32:
        return struct.pack("<I", int(value) & 0xFFFFFFFF)
    if value_type == HDL_VALUE_U64:
        return struct.pack("<Q", int(value) & 0xFFFFFFFFFFFFFFFF)
    if value_type == HDL_VALUE_F32:
        return struct.pack("<f", float(value))
    if value_type == HDL_VALUE_F64:
        return struct.pack("<d", float(value))
    raise ValueError(f"unsupported value_type for pack: {value_type}")


class ValueScan:
    """Interactive CE-style first/next scan (exact, unknown, float, …).

    Typical CE step 2::

        vs = ValueScan(dbg, HDL_VALUE_I32)
        vs.first_exact(100)          # First Scan
        # … take damage in game …
        vs.next_exact(95)            # Next Scan
        print(vs.hits())
    """

    __slots__ = ("_hdl", "_type", "_flags", "_module", "_session", "_count")

    def __init__(
        self,
        dbg: DebugSession | HdlClient,
        value_type: int = HDL_VALUE_I32,
        *,
        flags: int = 0,
        module: str | None = None,
    ) -> None:
        self._hdl = getattr(dbg, "hdl", dbg)
        self._type = value_type
        self._flags = flags
        self._module = module
        self._session: SearchSession | None = None
        self._count = 0

    def __enter__(self) -> ValueScan:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._session is not None:
            self._session.close()
            self._session = None

    def new_scan(self) -> None:
        """CE 'New Scan' — drop the previous session."""
        self.close()
        self._count = 0

    @property
    def count(self) -> int:
        return self._count

    def hits(self, max_hits: int = 256) -> list[int]:
        if self._session is None:
            return []
        return self._session.hits(max_hits=max_hits)

    def _ensure(self) -> SearchSession:
        if self._session is None:
            self._session = SearchSession(self._hdl)
        return self._session

    def first_exact(
        self,
        value: int | float,
        *,
        max_results: int = 100000,
        start: int = 0,
        size: int = 0,
    ) -> int:
        """CE Exact Value first scan."""
        self.new_scan()
        s = self._ensure()
        self._count = s.first(
            _pack_value(value, self._type),
            value_type=self._type,
            cmp=HDL_CMP_EXACT,
            start=start,
            size=size,
            max_results=max_results,
            flags=self._flags,
            module=self._module,
        )
        return self._count

    def first_unknown(self, *, max_results: int = 100000) -> int:
        """CE Unknown initial value first scan."""
        self.new_scan()
        s = self._ensure()
        self._count = s.unknown(
            self._type,
            max_results=max_results,
            flags=self._flags,
            module=self._module,
        )
        return self._count

    def next_exact(self, value: int | float) -> int:
        self._count = self._ensure().next(
            HDL_CMP_EXACT, _pack_value(value, self._type)
        )
        return self._count

    def next_changed(self) -> int:
        self._count = self._ensure().next(HDL_CMP_CHANGED)
        return self._count

    def next_unchanged(self) -> int:
        self._count = self._ensure().next(HDL_CMP_UNCHANGED)
        return self._count

    def next_increased(self) -> int:
        self._count = self._ensure().next(HDL_CMP_INCREASED)
        return self._count

    def next_decreased(self) -> int:
        self._count = self._ensure().next(HDL_CMP_DECREASED)
        return self._count

    def next_increased_by(self, delta: int | float) -> int:
        self._count = self._ensure().next(
            HDL_CMP_INCREASED_BY, _pack_value(delta, self._type)
        )
        return self._count

    def next_decreased_by(self, delta: int | float) -> int:
        self._count = self._ensure().next(
            HDL_CMP_DECREASED_BY, _pack_value(delta, self._type)
        )
        return self._count

    def refine_until(
        self,
        action: Callable[[], None],
        refine: Callable[[], int],
        *,
        max_hits: int = 32,
        rounds: int = 32,
    ) -> list[int]:
        """Run ``action`` then ``refine`` until few hits remain.

        CE loop: change value in-game → Next Scan → repeat.
        """
        for _ in range(rounds):
            if 0 < self._count <= max_hits:
                return self.hits(max_hits=max_hits)
            action()
            refine()
        return self.hits(max_hits=max_hits)


# ---------------------------------------------------------------------------
# Cheat table / freeze (CE address list)
# ---------------------------------------------------------------------------


@dataclass
class CheatEntry:
    """One CE-style address-list row."""

    address: int
    value_type: int = HDL_VALUE_I32
    description: str = ""
    offsets: tuple[int, ...] = ()
    base: int | None = None  # static/module base when using pointer chain
    frozen: bool = False
    freeze_value: int | float | None = None


class CheatTable:
    """Minimal CE address list: resolve pointers, set/freeze values."""

    def __init__(self, dbg: DebugSession | HdlClient) -> None:
        hdl = getattr(dbg, "hdl", dbg)
        self._hdl = hdl
        self.mem = getattr(dbg, "mem", None) or Memory(hdl)
        self.entries: list[CheatEntry] = []
        self._freeze_stop = threading.Event()
        self._freeze_thread: threading.Thread | None = None
        self._freeze_interval = 0.05

    def add(
        self,
        address: int,
        *,
        value_type: int = HDL_VALUE_I32,
        description: str = "",
        offsets: list[int] | tuple[int, ...] = (),
        base: int | None = None,
    ) -> CheatEntry:
        e = CheatEntry(
            address=address,
            value_type=value_type,
            description=description,
            offsets=tuple(offsets),
            base=base,
        )
        self.entries.append(e)
        return e

    def resolve(self, entry: CheatEntry) -> int:
        """Follow pointer chain if ``base``/``offsets`` set; else absolute."""
        if entry.base is None and not entry.offsets:
            return entry.address
        base = entry.base if entry.base is not None else entry.address
        if not entry.offsets:
            return base
        return self._hdl.follow_pointers(base, entry.offsets)

    def read(self, entry: CheatEntry) -> int | float:
        addr = self.resolve(entry)
        if entry.value_type == HDL_VALUE_I32:
            return self.mem.i32(addr)
        if entry.value_type == HDL_VALUE_U32:
            return self.mem.u32(addr)
        if entry.value_type == HDL_VALUE_U64:
            return self.mem.u64(addr)
        if entry.value_type == HDL_VALUE_F32:
            return self.mem.f32(addr)
        if entry.value_type == HDL_VALUE_F64:
            return self.mem.f64(addr)
        raise ValueError(f"unsupported type {entry.value_type}")

    def write(self, entry: CheatEntry, value: int | float) -> None:
        addr = self.resolve(entry)
        if entry.value_type == HDL_VALUE_I32:
            self.mem.write_i32(addr, int(value))
        elif entry.value_type == HDL_VALUE_U32:
            self.mem.write_u32(addr, int(value))
        elif entry.value_type == HDL_VALUE_U64:
            self.mem.write_u64(addr, int(value))
        elif entry.value_type == HDL_VALUE_F32:
            self.mem.write_f32(addr, float(value))
        elif entry.value_type == HDL_VALUE_F64:
            self.mem.write_f64(addr, float(value))
        else:
            raise ValueError(f"unsupported type {entry.value_type}")

    def freeze(self, entry: CheatEntry, value: int | float | None = None) -> None:
        entry.frozen = True
        entry.freeze_value = value if value is not None else self.read(entry)
        self._ensure_freezer()

    def unfreeze(self, entry: CheatEntry) -> None:
        entry.frozen = False
        entry.freeze_value = None

    def stop_freezer(self) -> None:
        self._freeze_stop.set()
        t = self._freeze_thread
        if t is not None:
            t.join(timeout=1.0)
        self._freeze_thread = None
        self._freeze_stop.clear()

    def _ensure_freezer(self) -> None:
        if self._freeze_thread is not None and self._freeze_thread.is_alive():
            return
        self._freeze_stop.clear()

        def loop() -> None:
            while not self._freeze_stop.is_set():
                for e in list(self.entries):
                    if e.frozen and e.freeze_value is not None:
                        try:
                            self.write(e, e.freeze_value)
                        except Exception:
                            pass
                time.sleep(self._freeze_interval)

        self._freeze_thread = threading.Thread(
            target=loop, name="hdllib-freeze", daemon=True
        )
        self._freeze_thread.start()


# ---------------------------------------------------------------------------
# Find what accesses (CE step 5)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AccessHit:
    rip: int
    accessed: int
    size: int
    tid: int
    insn: Insn | None = None
    function: FunctionInfo | None = None


class AccessFinder:
    """CE 'Find out what accesses/writes this address' via HW watchpoints.

    Collects hit RIPs, optionally disassembles and resolves containing
    functions — the usual path into code-finder / NOP / injection.
    """

    def __init__(self, dbg: DebugSession | HdlClient) -> None:
        hdl = getattr(dbg, "hdl", dbg)
        self._hdl = hdl
        self.watches = getattr(dbg, "watches", None) or Watches(hdl)
        self.code = getattr(dbg, "code", None) or Code(hdl)
        self.graph = getattr(dbg, "graph", None) or Graph(hdl)
        self._handle: int | None = None

    def __enter__(self) -> AccessFinder:
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def start(
        self,
        addr: int,
        size: int = 4,
        *,
        access: int = HDL_WATCH_HW_WRITE,
    ) -> int:
        self.stop()
        self._handle = self.watches.hw(addr, size, access=access)
        return self._handle

    def stop(self) -> None:
        if self._handle is not None:
            try:
                self.watches.unwatch(self._handle)
            except Exception:
                pass
            self._handle = None

    def collect(
        self,
        *,
        timeout_ms: int = 2000,
        max_hits: int = 64,
        disasm: bool = True,
        resolve_fn: bool = True,
    ) -> list[AccessHit]:
        raw = self.watches.poll(max_n=max_hits, timeout_ms=timeout_ms)
        out: list[AccessHit] = []
        seen: set[int] = set()
        for h in raw:
            if h.rip in seen:
                continue
            seen.add(h.rip)
            insn = None
            fn = None
            if disasm:
                try:
                    insns = self.code.disasm(h.rip, max_insns=1)
                    insn = insns[0] if insns else None
                except Exception:
                    pass
            if resolve_fn:
                try:
                    fn = self.graph.resolve(h.rip)
                except Exception:
                    pass
            out.append(
                AccessHit(
                    rip=h.rip,
                    accessed=h.accessed,
                    size=h.size,
                    tid=h.tid,
                    insn=insn,
                    function=fn,
                )
            )
        return out

    def watch_until(
        self,
        addr: int,
        action: Callable[[], None],
        *,
        size: int = 4,
        access: int = HDL_WATCH_HW_WRITE,
        timeout_ms: int = 3000,
    ) -> list[AccessHit]:
        """Arm watch → run ``action`` (e.g. take damage) → collect writers."""
        self.start(addr, size, access=access)
        try:
            action()
            return self.collect(timeout_ms=timeout_ms)
        finally:
            self.stop()


# ---------------------------------------------------------------------------
# Code patcher / NOP (CE step 5 replace)
# ---------------------------------------------------------------------------


class CodePatcher:
    """Reversible NOP / byte patches (CE Advanced Options replace/restore)."""

    def __init__(self, dbg: DebugSession | HdlClient) -> None:
        hdl = getattr(dbg, "hdl", dbg)
        self.code = getattr(dbg, "code", None) or Code(hdl)
        self._handles: dict[str, int] = {}

    def nop(self, addr: int, size: int, name: str | None = None) -> int:
        key = name or f"nop_{addr:x}"
        handle = self.code.patch(addr, b"\x90" * size, name=key)
        self._handles[key] = handle
        return handle

    def nop_insn(self, addr: int, name: str | None = None) -> int:
        length = self.code.instr_len(addr)
        return self.nop(addr, length, name=name)

    def write_bytes(
        self, addr: int, data: ByteString, name: str | None = None
    ) -> int:
        key = name or f"patch_{addr:x}"
        handle = self.code.patch(addr, data, name=key)
        self._handles[key] = handle
        return handle

    def disable(self, name: str) -> None:
        handle = self._handles[name]
        self.code.enable(handle, False)

    def enable(self, name: str) -> None:
        handle = self._handles[name]
        self.code.enable(handle, True)

    def restore(self, name: str) -> None:
        """Disable and remove ledger entry (restores original bytes)."""
        handle = self._handles.pop(name)
        self.code.enable(handle, False)
        self.code.remove(handle)


# ---------------------------------------------------------------------------
# Pointers (CE steps 6 / 8)
# ---------------------------------------------------------------------------


class PointerHelper:
    """Pointer scan, chain resolve, and path validation."""

    def __init__(self, dbg: DebugSession | HdlClient) -> None:
        hdl = getattr(dbg, "hdl", dbg)
        self._hdl = hdl
        self.scan = getattr(dbg, "scan", None) or Scanner(hdl)

    def resolve(self, base: int, offsets: list[int] | tuple[int, ...]) -> int:
        return self.scan.follow_pointers(base, offsets)

    def scan_paths(
        self,
        target: int,
        *,
        depth: int = 3,
        max_offset: int = 0x1000,
        max_n: int = 64,
        flags: int = HDL_SEARCH_IMAGE,
        module: str | None = None,
    ) -> list[PointerPath]:
        """CE Pointer Scan (single snapshot)."""
        return self.scan.pointer_scan(
            target,
            depth=depth,
            max_offset=max_offset,
            max_n=max_n,
            flags=flags,
            module=module,
        )

    def consensus(
        self,
        target: int,
        *,
        depth: int = 3,
        max_offset: int = 0x1000,
        max_n: int = 64,
        flags: int = HDL_SEARCH_IMAGE,
        module: str | None = None,
    ) -> list[PointerPath]:
        """Pointer scan kept only if paths still resolve (discover consensus)."""
        return self._hdl.discover_path_consensus(
            target,
            depth=depth,
            max_offset=max_offset,
            max_n=max_n,
            flags=flags,
            module=module,
        )

    def validate(
        self, expected: int, paths: list[PointerPath]
    ) -> list[PointerPath]:
        """CE-style compare: keep paths that still point at ``expected``."""
        return self._hdl.discover_path_validate(expected, paths)

    def find_static_bases(
        self,
        target: int,
        *,
        module: str | None = None,
        max_n: int = 64,
    ) -> list[int]:
        """Scan for exact pointer value of ``target`` in image (CE green addrs)."""
        flags = HDL_SEARCH_MODULE if module else HDL_SEARCH_IMAGE
        return self.scan.u64(
            target,
            max_results=max_n,
            flags=flags,
            module=module,
        )

    def to_entry(
        self,
        path: PointerPath,
        *,
        value_type: int = HDL_VALUE_I32,
        description: str = "",
        final_offset: int = 0,
    ) -> CheatEntry:
        offs = list(path.offsets)
        if final_offset:
            offs.append(final_offset)
        return CheatEntry(
            address=path.static_base,
            value_type=value_type,
            description=description,
            offsets=tuple(offs),
            base=path.static_base,
        )


# ---------------------------------------------------------------------------
# AOB / code injection (CE step 7 + AOB tutorials)
# ---------------------------------------------------------------------------


@dataclass
class Injection:
    """Installed AOB jump injection (enable/disable via patch ledger)."""

    pattern: str
    match_addr: int
    inject_addr: int
    stolen: int
    stub_va: int
    patch_handle: int
    original: bytes


class AobInjector:
    """CE AOB Injection: unique signature → cave/alloc → jmp stub → patch.

    Does not assemble arbitrary AA scripts; it places an absolute jmp to a
    caller-supplied stub (or an empty RX cave for you to fill).
    """

    def __init__(self, dbg: DebugSession | HdlClient) -> None:
        hdl = getattr(dbg, "hdl", dbg)
        self._hdl = hdl
        self.scan = getattr(dbg, "scan", None) or Scanner(hdl)
        self.place = getattr(dbg, "place", None) or Place(hdl)
        self.code = getattr(dbg, "code", None) or Code(hdl)
        self._active: list[Injection] = []

    def find_unique(
        self,
        pattern: str,
        *,
        module: str | None = None,
        max_hits: int = 8,
    ) -> int:
        hits = self.scan.aob(pattern, max_hits=max_hits)
        if module:
            # Prefer hits inside named module when caller scopes scan via resolve_pattern
            pass
        if len(hits) != 1:
            raise ValueError(
                f"AOB not unique: {len(hits)} hits for {pattern!r} "
                "(widen wildcards or add more bytes)"
            )
        return hits[0]

    def install(
        self,
        pattern: str,
        *,
        pattern_offset: int = 0,
        stub_size: int = 0x1000,
        module: str | None = None,
        fill_cave: ByteString | None = None,
    ) -> Injection:
        """Find unique AOB, alloc near, build abs-jmp stub, patch site."""
        if module:
            result = self.scan.resolve_pattern(
                pattern,
                pattern_offset=pattern_offset,
                flags=HDL_SEARCH_MODULE,
                module=module,
                max_scan_hits=8,
            )
            inject_addr = result.resolved_addr
            match_addr = result.match_addr
        else:
            match_addr = self.find_unique(pattern)
            inject_addr = match_addr + pattern_offset

        stolen = 0
        # Steal enough bytes for a 14-byte abs jmp (FF 25 …) or stub helper
        need = 14
        cur = inject_addr
        while stolen < need:
            stolen += self.code.instr_len(cur)
            cur = inject_addr + stolen

        original = self._hdl.read(inject_addr, stolen)
        stub = self.code.stub(
            inject_addr + stolen,
            kind=HDL_STUB_ABS_JMP,
            steal_from=inject_addr,
            steal_min_bytes=stolen,
            alloc_rx=True,
        )
        stub_va = stub.stub_va
        if fill_cave is not None and stub_va:
            self.place.protect(stub_va, stub_size, PAGE_EXECUTE_READWRITE)
            # Prefer writing custom cave before the generated trampoline return
            self._hdl.write(stub_va, fill_cave)

        # Patch injection site: jmp to stub
        jmp = self.code.stub(
            stub_va,
            kind=HDL_STUB_ABS_JMP,
            alloc_rx=False,
        )
        patch_bytes = jmp.code[: jmp.code_size]
        if len(patch_bytes) < stolen:
            patch_bytes = patch_bytes + b"\x90" * (stolen - len(patch_bytes))
        handle = self.code.patch(
            inject_addr, patch_bytes[:stolen], name=f"aob_{inject_addr:x}"
        )
        inj = Injection(
            pattern=pattern,
            match_addr=match_addr,
            inject_addr=inject_addr,
            stolen=stolen,
            stub_va=stub_va,
            patch_handle=handle,
            original=original,
        )
        self._active.append(inj)
        return inj

    def disable(self, inj: Injection) -> None:
        self.code.enable(inj.patch_handle, False)

    def enable(self, inj: Injection) -> None:
        self.code.enable(inj.patch_handle, True)

    def remove(self, inj: Injection) -> None:
        self.disable(inj)
        self.code.remove(inj.patch_handle)
        if inj in self._active:
            self._active.remove(inj)
        if inj.stub_va:
            try:
                self.place.free(inj.stub_va)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Structure helpers (CE step 9 / dissect)
# ---------------------------------------------------------------------------


class StructHelper:
    """Probe layouts and diff instances (shared-code / team-id workflows)."""

    def __init__(self, dbg: DebugSession | HdlClient) -> None:
        hdl = getattr(dbg, "hdl", dbg)
        self._hdl = hdl
        self.structs = getattr(dbg, "structs", None) or Structs(hdl)

    def probe(
        self, addr: int, size: int = 64, *, max_fields: int = 64
    ) -> list[StructField]:
        return self.structs.probe(addr, size, max_fields=max_fields)

    def diff(
        self, addrs: list[int], *, max_size: int = 256, max_fields: int = 64
    ):
        """Bytewise multi-instance diffs → candidate field offsets."""
        with DiscoverSession(self._hdl) as disc:
            return disc.diff_objects(
                addrs, max_size=max_size, max_fields=max_fields
            )

    def cluster_same_vtable(
        self, seed: int, object_size: int = 256, **kwargs
    ) -> list:
        """Find other objects with same vtable@0 (CE actor-list expansion)."""
        with DiscoverSession(self._hdl) as disc:
            disc.add(seed, tag="seed")
            disc.cluster(seed, object_size, **kwargs)
            return disc.candidates()


# ---------------------------------------------------------------------------
# REPL bindings
# ---------------------------------------------------------------------------


def strategies_locals(dbg: DebugSession) -> dict[str, object]:
    """Extra names for the Python REPL (`ce`, scanners, helpers)."""
    table = CheatTable(dbg)
    return {
        "ce": table,
        "ValueScan": ValueScan,
        "CheatTable": CheatTable,
        "AccessFinder": AccessFinder,
        "CodePatcher": CodePatcher,
        "PointerHelper": PointerHelper,
        "AobInjector": AobInjector,
        "StructHelper": StructHelper,
        "vs": ValueScan(dbg),
        "access": AccessFinder(dbg),
        "patcher": CodePatcher(dbg),
        "ptrs": PointerHelper(dbg),
        "aob": AobInjector(dbg),
        "structs_helper": StructHelper(dbg),
    }
