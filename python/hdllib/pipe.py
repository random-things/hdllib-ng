"""Named-pipe client mirroring ``tools/client/pipe_client.*``."""

from __future__ import annotations

import ctypes
import struct
import time
from collections.abc import Callable
from ctypes import wintypes
from typing import ByteString

from .exceptions import HdlPipeError
from .protocol import HDL_IPC_MORE, Reader, format_pipe_name

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_PIPE_BUSY = 231
ERROR_FILE_NOT_FOUND = 2
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000

kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
kernel32.CreateFileW.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
kernel32.ReadFile.restype = wintypes.BOOL

kernel32.WriteFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
kernel32.WriteFile.restype = wintypes.BOOL

kernel32.SetNamedPipeHandleState.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.SetNamedPipeHandleState.restype = wintypes.BOOL

kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
kernel32.WaitNamedPipeW.restype = wintypes.BOOL

kernel32.GetLastError.restype = wintypes.DWORD


def _read_exact(handle: int, size: int) -> bytes:
    out = bytearray(size)
    remaining = size
    offset = 0
    while remaining:
        got = wintypes.DWORD(0)
        view = (ctypes.c_ubyte * remaining).from_buffer(out, offset)
        ok = kernel32.ReadFile(handle, view, remaining, ctypes.byref(got), None)
        if not ok or got.value == 0:
            raise HdlPipeError(f"ReadFile failed (err={ctypes.get_last_error()})")
        offset += got.value
        remaining -= got.value
    return bytes(out)


def _write_exact(handle: int, data: ByteString) -> None:
    raw = bytearray(data)
    remaining = len(raw)
    offset = 0
    while remaining:
        wrote = wintypes.DWORD(0)
        view = (ctypes.c_ubyte * remaining).from_buffer(raw, offset)
        ok = kernel32.WriteFile(handle, view, remaining, ctypes.byref(wrote), None)
        if not ok or wrote.value == 0:
            raise HdlPipeError(f"WriteFile failed (err={ctypes.get_last_error()})")
        offset += wrote.value
        remaining -= wrote.value


class PipeClient:
    """Length-prefixed frame client for ``\\\\.\\pipe\\RPCControl_<hash>``."""

    def __init__(self, pid: int) -> None:
        self.pid = int(pid)
        self._handle: int | None = None

    def __enter__(self) -> PipeClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def connected(self) -> bool:
        return self._handle is not None

    def connect(self, timeout_ms: int = 5000) -> None:
        self.close()
        name = format_pipe_name(self.pid)
        deadline = time.monotonic() + (timeout_ms / 1000.0)
        while True:
            handle = kernel32.CreateFileW(
                name,
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                0,
                None,
            )
            if handle != INVALID_HANDLE_VALUE and handle is not None:
                mode = wintypes.DWORD(PIPE_READMODE_BYTE | PIPE_WAIT)
                kernel32.SetNamedPipeHandleState(handle, ctypes.byref(mode), None, None)
                self._handle = int(handle)
                return
            err = ctypes.get_last_error()
            if err not in (ERROR_PIPE_BUSY, ERROR_FILE_NOT_FOUND):
                raise HdlPipeError(f"CreateFileW({name!r}) failed (err={err})")
            if time.monotonic() > deadline:
                raise HdlPipeError(f"timed out connecting to {name}")
            kernel32.WaitNamedPipeW(name, 200)
            time.sleep(0.05)

    def close(self) -> None:
        if self._handle is not None:
            kernel32.CloseHandle(self._handle)
            self._handle = None

    def request(self, req: ByteString) -> bytes:
        if self._handle is None:
            raise HdlPipeError("pipe not connected")
        payload = bytes(req)
        _write_exact(self._handle, struct.pack("<I", len(payload)))
        if payload:
            _write_exact(self._handle, payload)
        return self._read_frame()

    def request_stream(
        self,
        req: ByteString,
        on_frame: Callable[[int, int, bytes], bool],
    ) -> None:
        """Send request and drain stream frames until ``HDL_IPC_MORE`` clears.

        ``on_frame(status, flags, payload_after_flags)`` — return False to abort.
        """
        if self._handle is None:
            raise HdlPipeError("pipe not connected")
        payload = bytes(req)
        _write_exact(self._handle, struct.pack("<I", len(payload)))
        if payload:
            _write_exact(self._handle, payload)
        while True:
            frame = self._read_frame()
            r = Reader(frame)
            status = r.take_i32()
            flags = r.take_u32()
            if not on_frame(status, flags, r.remaining):
                raise HdlPipeError("stream aborted by callback")
            if (flags & HDL_IPC_MORE) == 0:
                return

    def _read_frame(self) -> bytes:
        assert self._handle is not None
        size_bytes = _read_exact(self._handle, 4)
        (rsize,) = struct.unpack("<I", size_bytes)
        if rsize == 0:
            return b""
        return _read_exact(self._handle, rsize)
