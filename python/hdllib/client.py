"""High-level Session API over the hdllib named-pipe protocol."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ByteString

from .exceptions import HdlStatusError
from .feature_ops import FeatureOpsMixin
from .inject import INJECT_CREATE_REMOTE_THREAD, inject_dll
from .pipe import PipeClient
from .re_ops import ReOpsMixin
from .protocol import (
    HDL_CALL_ARG_BUF,
    HDL_CALL_ARG_CSTR,
    HDL_CALL_ARG_F32,
    HDL_CALL_ARG_F64,
    HDL_CALL_ARG_I64,
    HDL_CALL_ARG_PTR,
    HDL_CALL_ARG_U64,
    HDL_CALL_ARG_WSTR,
    HDL_CALL_THREAD_WORKER,
    HDL_CMP_EXACT,
    HDL_IPC_REQ_STREAM,
    HDL_OK,
    HDL_VALUE_BYTES,
    HDL_VALUE_I32,
    HDL_VALUE_U32,
    Op,
    Reader,
    Writer,
    status_name,
)


@dataclass(frozen=True)
class ModuleInfo:
    base: int
    size: int
    path: str


@dataclass(frozen=True)
class RegionInfo:
    base: int
    size: int
    protect: int
    state: int
    type: int


@dataclass(frozen=True)
class CallArg:
    kind: int
    size: int = 0
    u64: int = 0
    blob: bytes = b""

    @classmethod
    def of_u64(cls, v: int) -> CallArg:
        return cls(HDL_CALL_ARG_U64, 0, v & 0xFFFFFFFFFFFFFFFF)

    @classmethod
    def of_i64(cls, v: int) -> CallArg:
        return cls(HDL_CALL_ARG_I64, 0, v & 0xFFFFFFFFFFFFFFFF)

    @classmethod
    def of_ptr(cls, v: int) -> CallArg:
        return cls(HDL_CALL_ARG_PTR, 0, v & 0xFFFFFFFFFFFFFFFF)

    @classmethod
    def of_cstr(cls, s: str) -> CallArg:
        raw = s.encode("utf-8") + b"\x00"
        return cls(HDL_CALL_ARG_CSTR, len(raw), 0, raw)

    @classmethod
    def of_wstr(cls, s: str) -> CallArg:
        raw = (s + "\x00").encode("utf-16-le")
        return cls(HDL_CALL_ARG_WSTR, len(raw), 0, raw)

    @classmethod
    def of_buf(cls, data: ByteString) -> CallArg:
        raw = bytes(data)
        return cls(HDL_CALL_ARG_BUF, len(raw), 0, raw)

    @classmethod
    def of_f32(cls, v: float) -> CallArg:
        bits = struct.unpack("<I", struct.pack("<f", v))[0]
        return cls(HDL_CALL_ARG_F32, 0, bits)

    @classmethod
    def of_f64(cls, v: float) -> CallArg:
        bits = struct.unpack("<Q", struct.pack("<d", v))[0]
        return cls(HDL_CALL_ARG_F64, 0, bits)


@dataclass(frozen=True)
class CallResult:
    return_value: int
    last_error: int
    buffers: dict[int, bytes]


@dataclass(frozen=True)
class HookHit:
    hook_id: int
    timestamp_ms: int
    return_value: int
    arg_count: int
    frame_count: int
    args: tuple[int, ...]
    caller: int
    frames: tuple[int, ...]


# Packed layouts matching hdllib.h (x64 MSVC)
_MODULE_INFO_FMT = "<QQ" + "520s"  # base, size, wchar path[260]
_MODULE_INFO_SIZE = struct.calcsize(_MODULE_INFO_FMT)
_REGION_INFO_FMT = "<QQIIII"
_REGION_INFO_SIZE = struct.calcsize(_REGION_INFO_FMT)
_CALL_RESULT_FMT = "<QII"
_CALL_RESULT_SIZE = struct.calcsize(_CALL_RESULT_FMT)
# HdlHookHit: 3*u64 + 2*u32 + 8*u64 + u64 + 8*u64
_HOOK_HIT_FMT = "<QQQII" + ("Q" * 8) + "Q" + ("Q" * 8)
_HOOK_HIT_SIZE = struct.calcsize(_HOOK_HIT_FMT)


def _decode_wstring_fixed(raw: bytes) -> str:
    text = raw.decode("utf-16-le", errors="replace")
    return text.split("\x00", 1)[0]


class Session(ReOpsMixin, FeatureOpsMixin):
    """Attach to an injected target: inject (optional) → connect → ops."""

    def __init__(self, pid: int) -> None:
        self.pid = int(pid)
        self._pipe = PipeClient(self.pid)

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def connected(self) -> bool:
        return self._pipe.connected

    def close(self) -> None:
        self._pipe.close()

    def inject(
        self,
        dll: str | None = None,
        method: int = INJECT_CREATE_REMOTE_THREAD,
        *,
        connect: bool = True,
        timeout_ms: int = 10000,
    ) -> int:
        """Inject hdllib into this session's pid. Returns module base."""
        result = inject_dll(self.pid, dll=dll, method=method)
        if result.pid and result.pid != self.pid:
            self.pid = result.pid
            self._pipe = PipeClient(self.pid)
        if connect:
            self.connect(timeout_ms=timeout_ms)
        return result.base

    def connect(self, timeout_ms: int = 5000) -> None:
        self._pipe.connect(timeout_ms=timeout_ms)

    def request(self, req: ByteString) -> Reader:
        resp = self._pipe.request(req)
        return Reader(resp)

    def _check(self, status: int, what: str) -> None:
        if status != HDL_OK:
            raise HdlStatusError(status, f"{what}: {status_name(status)}")

    # --- lifecycle ---------------------------------------------------------

    def ping(self) -> int:
        w = Writer()
        w.append_u32(Op.PING)
        r = self.request(w.data)
        status = r.take_i32()
        remote_pid = r.take_u32()
        self._check(status, "ping")
        return remote_pid

    def set_log_level(self, level: int) -> None:
        w = Writer()
        w.append_u32(Op.SET_LOG_LEVEL)
        w.append_i32(level)
        r = self.request(w.data)
        self._check(r.take_i32(), "set_log_level")

    # --- memory ------------------------------------------------------------

    def read(self, address: int, size: int) -> bytes:
        w = Writer()
        w.append_u32(Op.READ_MEMORY)
        w.append_u64(address)
        w.append_u32(size)
        r = self.request(w.data)
        status = r.take_i32()
        got = r.take_u32()
        self._check(status, "read")
        return r.take(got)

    def write(self, address: int, data: ByteString) -> int:
        raw = bytes(data)
        w = Writer()
        w.append_u32(Op.WRITE_MEMORY)
        w.append_u64(address)
        w.append_u32(len(raw))
        w.append_bytes(raw)
        r = self.request(w.data)
        status = r.take_i32()
        wrote = r.take_u32()
        self._check(status, "write")
        return wrote

    def modules(self, *, stream: bool = False) -> list[ModuleInfo]:
        w = Writer()
        w.append_u32(Op.ENUM_MODULES)
        if stream:
            w.append_job_trailer(flags=HDL_IPC_REQ_STREAM)
            out: list[ModuleInfo] = []

            def on_frame(status: int, _flags: int, payload: bytes) -> bool:
                self._check(status, "modules")
                r = Reader(payload)
                _total = r.take_u32()
                _off = r.take_u32()
                count = r.take_u32()
                for _ in range(count):
                    out.append(_parse_module(r.take(_MODULE_INFO_SIZE)))
                return True

            self._pipe.request_stream(w.data, on_frame)
            return out

        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "modules")
        return [_parse_module(r.take(_MODULE_INFO_SIZE)) for _ in range(count)]

    def regions(self, *, stream: bool = False) -> list[RegionInfo]:
        w = Writer()
        w.append_u32(Op.ENUM_REGIONS)
        if stream:
            w.append_job_trailer(flags=HDL_IPC_REQ_STREAM)
            out: list[RegionInfo] = []

            def on_frame(status: int, _flags: int, payload: bytes) -> bool:
                self._check(status, "regions")
                r = Reader(payload)
                _total = r.take_u32()
                _off = r.take_u32()
                count = r.take_u32()
                for _ in range(count):
                    out.append(_parse_region(r.take(_REGION_INFO_SIZE)))
                return True

            self._pipe.request_stream(w.data, on_frame)
            return out

        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "regions")
        return [_parse_region(r.take(_REGION_INFO_SIZE)) for _ in range(count)]

    def module_base(self, module: str | None = None) -> int:
        w = Writer()
        w.append_u32(Op.MODULE_BASE)
        w.append_wstring(module)
        r = self.request(w.data)
        status = r.take_i32()
        base = r.take_u64()
        self._check(status, "module_base")
        return base

    # --- search ------------------------------------------------------------

    def search(
        self,
        pattern: str,
        *,
        start: int = 0,
        size: int = 0,
        max_hits: int = 64,
    ) -> list[int]:
        """One-shot AOB search (``OpSearchMemory``)."""
        w = Writer()
        w.append_u32(Op.SEARCH_MEMORY)
        w.append_u64(start)
        w.append_u64(size)
        w.append_u32(max_hits)
        w.append_string(pattern)
        w.append_job_trailer()
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "search")
        return [r.take_u64() for _ in range(count)]

    def search_create(self) -> int:
        w = Writer()
        w.append_u32(Op.SEARCH_CREATE)
        r = self.request(w.data)
        status = r.take_i32()
        session = r.take_u64()
        self._check(status, "search_create")
        return session

    def search_close(self, session: int) -> None:
        w = Writer()
        w.append_u32(Op.SEARCH_CLOSE)
        w.append_u64(session)
        r = self.request(w.data)
        self._check(r.take_i32(), "search_close")

    def search_reset(self, session: int) -> None:
        w = Writer()
        w.append_u32(Op.SEARCH_RESET)
        w.append_u64(session)
        r = self.request(w.data)
        self._check(r.take_i32(), "search_reset")

    def search_first(
        self,
        session: int,
        *,
        value: bytes,
        value_type: int = HDL_VALUE_BYTES,
        cmp: int = HDL_CMP_EXACT,
        start: int = 0,
        size: int = 0,
        alignment: int = 0,
        max_results: int = 64,
        flags: int = 0,
        module: str | None = None,
    ) -> int:
        w = Writer()
        w.append_u32(Op.SEARCH_FIRST)
        w.append_u64(session)
        w.append_u64(start)
        w.append_u64(size)
        w.append_i32(value_type)
        w.append_i32(cmp)
        w.append_u32(alignment)
        w.append_u32(max_results)
        w.append_u32(len(value))
        if value:
            w.append_bytes(value)
        w.append_u32(flags)
        w.append_wstring(module)
        w.append_job_trailer()
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "search_first")
        return count

    def search_next(
        self,
        session: int,
        *,
        cmp: int,
        value: bytes = b"",
    ) -> int:
        w = Writer()
        w.append_u32(Op.SEARCH_NEXT)
        w.append_u64(session)
        w.append_i32(cmp)
        w.append_u32(len(value))
        if value:
            w.append_bytes(value)
        w.append_job_trailer()
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "search_next")
        return count

    def search_get_hits(self, session: int, max_hits: int = 64) -> list[int]:
        w = Writer()
        w.append_u32(Op.SEARCH_GET_HITS)
        w.append_u64(session)
        w.append_u32(max_hits)
        w.append_job_trailer()
        r = self.request(w.data)
        status = r.take_i32()
        _total = r.take_u32()
        got = r.take_u32()
        self._check(status, "search_get_hits")
        return [r.take_u64() for _ in range(got)]

    def scan_u32(
        self,
        value: int,
        *,
        max_results: int = 64,
        flags: int = 0,
        module: str | None = None,
    ) -> tuple[int, list[int]]:
        """Convenience: create session, first-scan u32, return (session, hits)."""
        session = self.search_create()
        raw = struct.pack("<I", value & 0xFFFFFFFF)
        self.search_first(
            session,
            value=raw,
            value_type=HDL_VALUE_U32,
            cmp=HDL_CMP_EXACT,
            max_results=max_results,
            flags=flags,
            module=module,
        )
        hits = self.search_get_hits(session, max_hits=max_results)
        return session, hits

    def scan_i32(
        self,
        value: int,
        *,
        max_results: int = 64,
        flags: int = 0,
        module: str | None = None,
    ) -> tuple[int, list[int]]:
        session = self.search_create()
        raw = struct.pack("<i", int(value))
        self.search_first(
            session,
            value=raw,
            value_type=HDL_VALUE_I32,
            cmp=HDL_CMP_EXACT,
            max_results=max_results,
            flags=flags,
            module=module,
        )
        hits = self.search_get_hits(session, max_hits=max_results)
        return session, hits

    # --- call / resolve ----------------------------------------------------

    def resolve_export(self, export_name: str, module: str | None = None) -> int:
        w = Writer()
        w.append_u32(Op.RESOLVE_EXPORT)
        w.append_wstring(module)
        w.append_string(export_name)
        r = self.request(w.data)
        status = r.take_i32()
        addr = r.take_u64()
        self._check(status, "resolve_export")
        return addr

    def call_export(
        self,
        export_name: str,
        args: list[CallArg] | None = None,
        *,
        module: str | None = None,
        timeout_ms: int = 0,
        job_id: int = 0,
    ) -> CallResult:
        args = args or []
        w = Writer()
        w.append_u32(Op.CALL_EXPORT)
        w.append_wstring(module)
        w.append_string(export_name)
        w.append_u32(len(args))
        w.append_u32(timeout_ms)
        w.append_u64(job_id)
        for a in args:
            _append_call_arg(w, a)
        return _parse_call_result(self.request(w.data), "call_export")

    def call(
        self,
        address: int,
        args: list[CallArg] | None = None,
        *,
        thread_mode: int = HDL_CALL_THREAD_WORKER,
        timeout_ms: int = 0,
        job_id: int = 0,
    ) -> CallResult:
        args = args or []
        w = Writer()
        w.append_u32(Op.CALL)
        w.append_u64(address)
        w.append_u32(len(args))
        w.append_u32(thread_mode)
        w.append_u32(timeout_ms)
        w.append_u64(job_id)
        for a in args:
            _append_call_arg(w, a)
        return _parse_call_result(self.request(w.data), "call")

    # --- hooks -------------------------------------------------------------

    def hook_trace(self, target: int, arg_count: int = 0) -> int:
        w = Writer()
        w.append_u32(Op.HOOK_TRACE)
        w.append_u64(target)
        w.append_u32(arg_count)
        r = self.request(w.data)
        status = r.take_i32()
        handle = r.take_u64()
        self._check(status, "hook_trace")
        return handle

    def enable_hook(self, handle: int, enable: bool = True) -> None:
        w = Writer()
        w.append_u32(Op.ENABLE_HOOK)
        w.append_u64(handle)
        w.append_i32(1 if enable else 0)
        r = self.request(w.data)
        self._check(r.take_i32(), "enable_hook")

    def unhook(self, handle: int) -> None:
        w = Writer()
        w.append_u32(Op.UNHOOK)
        w.append_u64(handle)
        r = self.request(w.data)
        self._check(r.take_i32(), "unhook")

    def poll_hook_hits(self, max_n: int = 16, timeout_ms: int = 0) -> list[HookHit]:
        w = Writer()
        w.append_u32(Op.POLL_HOOK_HITS)
        w.append_u32(max_n)
        w.append_u32(timeout_ms)
        r = self.request(w.data)
        status = r.take_i32()
        count = r.take_u32()
        self._check(status, "poll_hook_hits")
        hits: list[HookHit] = []
        for _ in range(count):
            hits.append(_parse_hook_hit(r.take(_HOOK_HIT_SIZE)))
        return hits


def _parse_module(raw: bytes) -> ModuleInfo:
    base, size, path_raw = struct.unpack(_MODULE_INFO_FMT, raw)
    return ModuleInfo(base=base, size=size, path=_decode_wstring_fixed(path_raw))


def _parse_region(raw: bytes) -> RegionInfo:
    base, size, protect, state, typ, _res = struct.unpack(_REGION_INFO_FMT, raw)
    return RegionInfo(base=base, size=size, protect=protect, state=state, type=typ)


def _append_call_arg(w: Writer, a: CallArg) -> None:
    w.append_i32(a.kind)
    w.append_u32(a.size)
    w.append_u64(a.u64)
    if a.kind in (HDL_CALL_ARG_CSTR, HDL_CALL_ARG_WSTR, HDL_CALL_ARG_BUF):
        w.append_u32(len(a.blob))
        if a.blob:
            w.append_bytes(a.blob)


def _parse_call_result(r: Reader, what: str) -> CallResult:
    status = r.take_i32()
    raw = r.take(_CALL_RESULT_SIZE)
    ret, last_error, _res = struct.unpack(_CALL_RESULT_FMT, raw)
    if status != HDL_OK:
        raise HdlStatusError(status, f"{what}: {status_name(status)}")
    buffers: dict[int, bytes] = {}
    if r.left >= 4:
        buf_n = r.take_u32()
        for _ in range(buf_n):
            idx = r.take_u32()
            sz = r.take_u32()
            buffers[idx] = r.take(sz)
    return CallResult(return_value=ret, last_error=last_error, buffers=buffers)


def _parse_hook_hit(raw: bytes) -> HookHit:
    fields = struct.unpack(_HOOK_HIT_FMT, raw)
    hook_id, timestamp_ms, return_value, arg_count, frame_count = fields[:5]
    args = fields[5:13]
    caller = fields[13]
    frames = fields[14:22]
    return HookHit(
        hook_id=hook_id,
        timestamp_ms=timestamp_ms,
        return_value=return_value,
        arg_count=arg_count,
        frame_count=frame_count,
        args=tuple(args[:arg_count]),
        caller=caller,
        frames=tuple(frames[:frame_count]),
    )


class HdlClient(Session):
    """Pipe client for scripting and the interactive shell/REPL.

    Same surface as :class:`Session`; preferred name when binding ``hdl`` in a
    programmatic Python REPL.
    """

    def __repr__(self) -> str:
        state = "connected" if self.connected else "disconnected"
        return f"HdlClient(pid={self.pid}, {state})"


def attach(
    pid: int,
    *,
    inject: bool = True,
    method: int = INJECT_CREATE_REMOTE_THREAD,
    dll: str | None = None,
    timeout_ms: int = 10000,
) -> HdlClient:
    """Create an :class:`HdlClient`, optionally inject, and connect the pipe."""
    client = HdlClient(pid)
    if inject:
        client.inject(dll=dll, method=method, connect=True, timeout_ms=timeout_ms)
    else:
        client.connect(timeout_ms=timeout_ms)
    return client
