"""Wire protocol: opcodes, status codes, and encode/decode helpers.

Mirrors ``src/protocol.hpp`` and the framing rules in ``docs/capabilities.md``.
"""

from __future__ import annotations

import struct
from enum import IntEnum
from typing import ByteString


class Op(IntEnum):
    PING = 1
    INJECT_DLL = 2
    READ_MEMORY = 3
    WRITE_MEMORY = 4
    ENUM_REGIONS = 5
    ENUM_MODULES = 6
    SEARCH_MEMORY = 7
    SET_LOG_LEVEL = 8
    SEARCH_CREATE = 9
    SEARCH_CLOSE = 10
    SEARCH_FIRST = 11
    SEARCH_NEXT = 12
    SEARCH_GET_HITS = 13
    SEARCH_RESET = 14
    JOB_CREATE = 15
    JOB_CANCEL = 16
    JOB_CLOSE = 17
    GET_HEALTH = 18
    ENUM_THREADS = 19
    POLL_EVENTS = 20
    RESOLVE_EXPORT = 21
    CALL_EXPORT = 22
    CALL = 23
    ALLOC = 24
    FREE = 25
    RESOLVE_RIP = 26
    FOLLOW_POINTERS = 27
    MODULE_BASE = 28
    CALL_VTABLE = 29
    HOOK_TRACE = 30
    ENABLE_HOOK = 31
    UNHOOK = 32
    POLL_HOOK_HITS = 33
    RESOLVE_PATTERN = 34
    FIND_STRING_XREFS = 35
    POINTER_SCAN = 36
    PROBE_STRUCT = 37
    DISCOVER_CREATE = 38
    DISCOVER_CLOSE = 39
    DISCOVER_ADD_CANDIDATE = 40
    DISCOVER_CONSTRAINT_SCAN = 41
    DISCOVER_SYNTHESIZE_PATTERN = 42
    DISCOVER_PATH_CONSENSUS = 43
    DISCOVER_PATH_VALIDATE = 44
    DISCOVER_WATCH = 45
    DISCOVER_UNWATCH_ALL = 46
    DISCOVER_ACTION_BEGIN = 47
    DISCOVER_ACTION_END = 48
    DISCOVER_WATCH_REGION = 49
    DISCOVER_GET_HEAT = 50
    DISCOVER_RANK_FUNCTIONS = 51
    DISCOVER_CLUSTER_TYPE = 52
    DISCOVER_GET_CANDIDATES = 53
    FIND_CAVES = 54
    ALLOC_NEAR = 55
    PROTECT_MEMORY = 56
    FLUSH_ICACHE = 57
    DISASM_ENUM_BACKENDS = 58
    DISASM_GET_BACKEND = 59
    DISASM_SET_BACKEND = 60
    INSTR_LEN = 61
    DISASM = 62
    BUILD_STUB = 63
    PATCH_CREATE = 64
    PATCH_ENABLE = 65
    PATCH_REMOVE = 66
    PATCH_ENUM = 67
    ENUM_SECTIONS = 68
    ENUM_EXPORTS = 69
    ENUM_IMPORTS = 70
    ENUM_FUNCTIONS = 71
    XREFS_FROM = 72
    WALK_VTABLE = 73
    QUERY_RTTI_NAME = 74
    WATCH_HW = 75
    WATCH_PAGE = 76
    UNWATCH = 77
    ENUM_WATCHES = 78
    RESOLVE_FUNCTION = 79
    XREFS_TO = 80
    WATCH_REFRESH = 81
    POLL_WATCH_HITS = 82
    HOOK_IMPORT = 83
    DISCOVER_WATCH_IMPORT = 84
    INVALIDATE_FN_INDEX = 85
    DISCOVER_RESET_HEAT = 86
    DISCOVER_EXPORT = 87
    DISCOVER_IMPORT = 88
    DISCOVER_DIFF_OBJECTS = 89
    DISCOVER_APPLY_WATCH_HITS = 90
    DISCOVER_GET_EVIDENCE = 91


class Status(IntEnum):
    OK = 0
    E_INVALID_ARG = 1
    E_ACCESS = 2
    E_NOT_FOUND = 3
    E_NO_MEM = 4
    E_BUSY = 5
    E_FAILED = 6
    E_BUFFER_SMALL = 7
    E_CANCELLED = 8
    E_NOT_INIT = 9
    E_TIMEOUT = 10


HDL_OK = Status.OK

HDL_IPC_REQ_STREAM = 1
HDL_IPC_MORE = 1

HDL_VALUE_BYTES = 0
HDL_VALUE_I8 = 1
HDL_VALUE_U8 = 2
HDL_VALUE_I16 = 3
HDL_VALUE_U16 = 4
HDL_VALUE_I32 = 5
HDL_VALUE_U32 = 6
HDL_VALUE_I64 = 7
HDL_VALUE_U64 = 8
HDL_VALUE_F32 = 9
HDL_VALUE_F64 = 10
HDL_VALUE_STRING = 11
HDL_VALUE_WSTRING = 12

HDL_CMP_EXACT = 0
HDL_CMP_UNKNOWN = 1
HDL_CMP_CHANGED = 2
HDL_CMP_UNCHANGED = 3
HDL_CMP_INCREASED = 4
HDL_CMP_DECREASED = 5
HDL_CMP_INCREASED_BY = 6
HDL_CMP_DECREASED_BY = 7
HDL_CMP_GREATER = 8
HDL_CMP_LESS = 9

HDL_SEARCH_IMAGE = 1
HDL_SEARCH_EXECUTABLE = 2
HDL_SEARCH_MODULE = 4

HDL_XREF_CALL = 1
HDL_XREF_JMP = 2
HDL_XREF_DATA = 4
HDL_XREF_FUNC = 8

HDL_WATCH_HW_EXEC = 1
HDL_WATCH_HW_WRITE = 2
HDL_WATCH_HW_RW = 3
HDL_WATCH_PAGE_GUARD = 1
HDL_WATCH_PAGE_NOACCESS = 2

HDL_CALL_ARG_U64 = 0
HDL_CALL_ARG_I64 = 1
HDL_CALL_ARG_PTR = 2
HDL_CALL_ARG_BUF = 3
HDL_CALL_ARG_CSTR = 4
HDL_CALL_ARG_WSTR = 5
HDL_CALL_ARG_F32 = 6
HDL_CALL_ARG_F64 = 7

HDL_CALL_THREAD_WORKER = 0
HDL_CALL_THREAD_MAIN = 1

# String-xref flags (OpFindStringXrefs) — distinct from graph HDL_XREF_*
HDL_STR_XREF_ABSOLUTE = 1
HDL_STR_XREF_RIP_REL = 2

HDL_CAND_ADDRESS = 1
HDL_CAND_FUNCTION = 2
HDL_CAND_OBJECT = 3
HDL_CAND_FIELD = 4

HDL_PRED_EQ_I32 = 1
HDL_PRED_EQ_F32 = 2
HDL_PRED_RANGE_I32 = 3
HDL_PRED_LE_I32 = 4
HDL_PRED_PTR = 5
HDL_PRED_VTABLE = 6
HDL_PRED_EQ_U64 = 7

HDL_RANK_CALLER_ONLY = 1

HDL_STUB_ABS_JMP = 1
HDL_STUB_REL_JMP32 = 2
HDL_STUB_MOV_RAX_JMP = 3
HDL_STUB_RAW = 4

HDL_EVENT_EXCEPTION = 1
HDL_EVENT_HEALTH = 2
HDL_EVENT_JOB_DONE = 3
HDL_EVENT_HOOK = 4
HDL_EVENT_WATCH = 5

HDL_HEALTH_OK = 0
HDL_HEALTH_GUI_HUNG = 1
HDL_HEALTH_HIGH_CPU = 2
HDL_HEALTH_RECENT_EXCEPTION = 4

HDL_FN_EXPORT = 1
HDL_FN_CALLED = 2
HDL_FN_PROLOGUE = 4

# Win32 PAGE_* protect constants commonly used with alloc / protect
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

_STATUS_NAMES = {
    Status.OK: "HDL_OK",
    Status.E_INVALID_ARG: "HDL_E_INVALID_ARG",
    Status.E_ACCESS: "HDL_E_ACCESS",
    Status.E_NOT_FOUND: "HDL_E_NOT_FOUND",
    Status.E_NO_MEM: "HDL_E_NO_MEM",
    Status.E_BUSY: "HDL_E_BUSY",
    Status.E_FAILED: "HDL_E_FAILED",
    Status.E_BUFFER_SMALL: "HDL_E_BUFFER_SMALL",
    Status.E_CANCELLED: "HDL_E_CANCELLED",
    Status.E_NOT_INIT: "HDL_E_NOT_INIT",
    Status.E_TIMEOUT: "HDL_E_TIMEOUT",
}


def status_name(status: int) -> str:
    try:
        return _STATUS_NAMES[Status(status)]
    except (ValueError, KeyError):
        return f"HDL_STATUS_{status}"


class Writer:
    """Append POD / length-prefixed strings matching ``hdl::proto``."""

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf = bytearray()

    @property
    def data(self) -> bytes:
        return bytes(self._buf)

    def bytes(self) -> bytes:
        return self.data

    def append_bytes(self, data: ByteString) -> None:
        self._buf.extend(data)

    def append_pod(self, fmt: str, *values: object) -> None:
        self._buf.extend(struct.pack("<" + fmt, *values))

    def append_u32(self, v: int) -> None:
        self.append_pod("I", v & 0xFFFFFFFF)

    def append_i32(self, v: int) -> None:
        self.append_pod("i", int(v))

    def append_u64(self, v: int) -> None:
        self.append_pod("Q", v & 0xFFFFFFFFFFFFFFFF)

    def append_i64(self, v: int) -> None:
        self.append_pod("q", int(v))

    def append_string(self, s: str | None) -> None:
        """Narrow string: uint32 byte_len + NUL-terminated bytes (len includes NUL)."""
        if not s:
            self.append_u32(0)
            return
        raw = s.encode("utf-8") + b"\x00"
        self.append_u32(len(raw))
        self.append_bytes(raw)

    def append_wstring(self, s: str | None) -> None:
        """Wide string: uint32 byte_len + UTF-16LE including trailing NUL."""
        if not s:
            self.append_u32(0)
            return
        raw = (s + "\x00").encode("utf-16-le")
        self.append_u32(len(raw))
        self.append_bytes(raw)

    def append_job_trailer(
        self,
        job_id: int = 0,
        timeout_ms: int = 0,
        flags: int = 0,
    ) -> None:
        self.append_u64(job_id)
        self.append_u32(timeout_ms)
        self.append_u32(flags)


class Reader:
    """Consume POD / length-prefixed strings from a reply payload."""

    __slots__ = ("_data", "_pos")

    def __init__(self, data: ByteString) -> None:
        self._data = memoryview(bytes(data))
        self._pos = 0

    @property
    def left(self) -> int:
        return len(self._data) - self._pos

    @property
    def remaining(self) -> bytes:
        return bytes(self._data[self._pos :])

    def take(self, n: int) -> bytes:
        if self.left < n:
            raise ValueError(f"need {n} bytes, have {self.left}")
        out = bytes(self._data[self._pos : self._pos + n])
        self._pos += n
        return out

    def take_pod(self, fmt: str) -> tuple:
        size = struct.calcsize("<" + fmt)
        return struct.unpack("<" + fmt, self.take(size))

    def take_u32(self) -> int:
        return self.take_pod("I")[0]

    def take_i32(self) -> int:
        return self.take_pod("i")[0]

    def take_u64(self) -> int:
        return self.take_pod("Q")[0]

    def take_i64(self) -> int:
        return self.take_pod("q")[0]

    def take_string(self) -> str:
        n = self.take_u32()
        if n == 0:
            return ""
        raw = self.take(n)
        if raw.endswith(b"\x00"):
            raw = raw[:-1]
        return raw.decode("utf-8", errors="replace")

    def take_wstring(self) -> str:
        n = self.take_u32()
        if n == 0:
            return ""
        if n % 2 != 0:
            raise ValueError("wstring byte length must be even")
        raw = self.take(n)
        text = raw.decode("utf-16-le")
        if text.endswith("\x00"):
            text = text[:-1]
        return text


def pipe_name_hash(pid: int) -> int:
    """Port of ``HdlPipeNameHash`` from ``include/hdllib/pipe_name.h``."""
    pid = pid & 0xFFFFFFFF
    h = (0x811C9DC5 ^ pid) & 0xFFFFFFFF
    h = (h * 0x01000193) & 0xFFFFFFFF
    h = (h ^ (((pid << 13) | (pid >> 19)) & 0xFFFFFFFF)) & 0xFFFFFFFF
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h = (h ^ (h >> 16)) & 0xFFFFFFFF
    return h


def format_pipe_name(pid: int, env_value: str | None = None) -> str:
    """Port of ``HdlFormatPipeName`` (optional ``HDL_PIPE`` override)."""
    if env_value is None:
        import os

        env_value = os.environ.get("HDL_PIPE")
    if env_value:
        if "%" in env_value:
            # C swprintf with %lu — accept common Python %-formats too
            try:
                return env_value % (pid & 0xFFFFFFFF)
            except TypeError:
                return env_value.replace("%lu", str(pid & 0xFFFFFFFF)).replace(
                    "%u", str(pid & 0xFFFFFFFF)
                )
        return env_value
    tag = pipe_name_hash(pid)
    return f"\\\\.\\pipe\\RPCControl_{tag:08X}"
