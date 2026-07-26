"""ctypes wrappers for out-of-process inject / resolve / recommend."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass

from ._dll import dll_path, load_hdllib
from .exceptions import HdlStatusError
from .protocol import Status

# Matches HDL_INJECT_* in hdllib.h
INJECT_CREATE_REMOTE_THREAD = 0
INJECT_NT_CREATE_THREAD_EX = 1
INJECT_RTL_CREATE_USER_THREAD = 2
INJECT_QUEUE_USER_APC = 3
INJECT_SET_WINDOWS_HOOK_EX = 4
INJECT_THREAD_HIJACK = 5
INJECT_MANUAL_MAP = 6
INJECT_EARLY_BIRD_APC = 7
INJECT_ATOM_BOMBING = 8
INJECT_MODULE_STOMP = 9
INJECT_SECTION_MAP = 10
INJECT_WINDOW_SUBCLASS = 11
INJECT_INSTRUMENTATION_CALLBACK = 12
INJECT_KERNEL_CALLBACK_TABLE = 13
INJECT_VEH = 14
INJECT_SET_WIN_EVENT_HOOK = 15
INJECT_RTL_REMOTE_CALL = 16
INJECT_SPECIAL_USER_APC = 17
INJECT_THREAD_POOL = 18
INJECT_ETW_CALLBACK = 19
INJECT_AUTO = -1

INJECT_CAND_ELIGIBLE = 1
INJECT_CAND_NEEDS_ELEVATION = 2

METHOD_NAMES = {
    INJECT_CREATE_REMOTE_THREAD: "create_remote_thread",
    INJECT_NT_CREATE_THREAD_EX: "nt_create_thread_ex",
    INJECT_RTL_CREATE_USER_THREAD: "rtl_create_user_thread",
    INJECT_QUEUE_USER_APC: "queue_user_apc",
    INJECT_SET_WINDOWS_HOOK_EX: "set_windows_hook_ex",
    INJECT_THREAD_HIJACK: "thread_hijack",
    INJECT_MANUAL_MAP: "manual_map",
    INJECT_EARLY_BIRD_APC: "early_bird_apc",
    INJECT_ATOM_BOMBING: "atom_bombing",
    INJECT_MODULE_STOMP: "module_stomp",
    INJECT_SECTION_MAP: "section_map",
    INJECT_WINDOW_SUBCLASS: "window_subclass",
    INJECT_INSTRUMENTATION_CALLBACK: "instrumentation_callback",
    INJECT_KERNEL_CALLBACK_TABLE: "kernel_callback_table",
    INJECT_VEH: "veh",
    INJECT_SET_WIN_EVENT_HOOK: "set_win_event_hook",
    INJECT_RTL_REMOTE_CALL: "rtl_remote_call",
    INJECT_SPECIAL_USER_APC: "special_user_apc",
    INJECT_THREAD_POOL: "thread_pool",
    INJECT_ETW_CALLBACK: "etw_callback",
    INJECT_AUTO: "auto",
}


class HdlTargetSpec(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("window_title_or_null", wintypes.LPCWSTR),
        ("window_class_or_null", wintypes.LPCWSTR),
    ]


class HdlInjectCandidate(ctypes.Structure):
    _fields_ = [
        ("method", ctypes.c_int),
        ("confidence", ctypes.c_int),
        ("flags", ctypes.c_uint32),
        ("reasons", ctypes.c_char * 256),
    ]


@dataclass(frozen=True)
class InjectResult:
    status: int
    pid: int
    base: int
    dll: str


@dataclass(frozen=True)
class InjectCandidate:
    method: int
    confidence: int
    flags: int
    reasons: str

    @property
    def name(self) -> str:
        return METHOD_NAMES.get(self.method, str(self.method))

    @property
    def eligible(self) -> bool:
        return bool(self.flags & INJECT_CAND_ELIGIBLE)


def _bind() -> ctypes.CDLL:
    dll = load_hdllib()
    if getattr(dll, "_hdl_inject_bound", False):
        return dll

    dll.HdlInjectDllEx.argtypes = [
        ctypes.c_uint32,
        wintypes.LPCWSTR,
        ctypes.c_int,
        wintypes.LPCWSTR,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint64),
    ]
    dll.HdlInjectDllEx.restype = ctypes.c_int32

    dll.HdlResolveTarget.argtypes = [
        ctypes.POINTER(HdlTargetSpec),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(wintypes.HWND),
    ]
    dll.HdlResolveTarget.restype = ctypes.c_int32

    dll.HdlRecommendInject.argtypes = [
        ctypes.POINTER(HdlTargetSpec),
        wintypes.LPCWSTR,
        ctypes.c_char_p,
        ctypes.POINTER(HdlInjectCandidate),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    dll.HdlRecommendInject.restype = ctypes.c_int32

    dll.HdlInit.argtypes = []
    dll.HdlInit.restype = ctypes.c_int32

    dll._hdl_inject_bound = True  # type: ignore[attr-defined]
    return dll


def inject_dll(
    pid: int,
    dll: str | None = None,
    method: int = INJECT_CREATE_REMOTE_THREAD,
    exe_path: str | None = None,
    hook_export: str | None = None,
    *,
    raise_on_error: bool = True,
) -> InjectResult:
    """Inject ``hdllib.dll`` (or another DLL) into ``pid`` via ``HdlInjectDllEx``.

    Default method is CreateRemoteThread. Use ``INJECT_AUTO`` (-1) for
    ranked auto-select.
    """
    lib = _bind()
    lib.HdlInit()
    path = dll or dll_path()
    out_pid = ctypes.c_uint32(0)
    out_base = ctypes.c_uint64(0)
    hook = hook_export.encode("ascii") if hook_export else None
    status = int(
        lib.HdlInjectDllEx(
            ctypes.c_uint32(pid),
            path,
            int(method),
            exe_path,
            hook,
            ctypes.byref(out_pid),
            ctypes.byref(out_base),
        )
    )
    result = InjectResult(
        status=status,
        pid=int(out_pid.value) or int(pid),
        base=int(out_base.value),
        dll=path,
    )
    if raise_on_error and status != Status.OK:
        raise HdlStatusError(status, f"HdlInjectDllEx failed for pid={pid}")
    return result


def resolve_target(
    pid: int = 0,
    window_title: str | None = None,
    window_class: str | None = None,
) -> tuple[int, int]:
    """Resolve ``(pid, hwnd)`` from pid and/or window title/class substring."""
    lib = _bind()
    lib.HdlInit()
    spec = HdlTargetSpec(
        pid=pid,
        window_title_or_null=window_title,
        window_class_or_null=window_class,
    )
    out_pid = ctypes.c_uint32(0)
    out_hwnd = wintypes.HWND()
    status = int(
        lib.HdlResolveTarget(ctypes.byref(spec), ctypes.byref(out_pid), ctypes.byref(out_hwnd))
    )
    if status != Status.OK:
        raise HdlStatusError(status, "HdlResolveTarget failed")
    return int(out_pid.value), int(ctypes.cast(out_hwnd, ctypes.c_void_p).value or 0)


def recommend_inject(
    pid: int = 0,
    window_title: str | None = None,
    window_class: str | None = None,
    dll: str | None = None,
    hook_export: str | None = None,
) -> list[InjectCandidate]:
    """Rank inject methods without injecting."""
    lib = _bind()
    lib.HdlInit()
    spec = HdlTargetSpec(
        pid=pid,
        window_title_or_null=window_title,
        window_class_or_null=window_class,
    )
    count = ctypes.c_uint32(20)
    arr = (HdlInjectCandidate * 20)()
    path = dll or dll_path()
    hook = hook_export.encode("ascii") if hook_export else None
    status = int(
        lib.HdlRecommendInject(
            ctypes.byref(spec),
            path,
            hook,
            arr,
            ctypes.byref(count),
        )
    )
    if status == Status.E_BUFFER_SMALL:
        n = int(count.value)
        arr = (HdlInjectCandidate * n)()
        count = ctypes.c_uint32(n)
        status = int(
            lib.HdlRecommendInject(
                ctypes.byref(spec),
                path,
                hook,
                arr,
                ctypes.byref(count),
            )
        )
    if status != Status.OK:
        raise HdlStatusError(status, "HdlRecommendInject failed")
    out: list[InjectCandidate] = []
    for i in range(int(count.value)):
        c = arr[i]
        out.append(
            InjectCandidate(
                method=int(c.method),
                confidence=int(c.confidence),
                flags=int(c.flags),
                reasons=bytes(c.reasons).split(b"\x00", 1)[0].decode("ascii", errors="replace"),
            )
        )
    return out
