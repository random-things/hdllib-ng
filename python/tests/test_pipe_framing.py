"""Offline encode/decode tests (no DLL or target process required)."""

from __future__ import annotations

import struct

from hdllib.protocol import (
    HDL_OK,
    Op,
    Reader,
    Writer,
    format_pipe_name,
    pipe_name_hash,
    status_name,
)


def test_append_take_pod_roundtrip():
    w = Writer()
    w.append_u32(Op.PING)
    w.append_u64(0x1122334455667788)
    w.append_i32(-7)
    r = Reader(w.data)
    assert r.take_u32() == Op.PING
    assert r.take_u64() == 0x1122334455667788
    assert r.take_i32() == -7
    assert r.left == 0


def test_string_encoding_includes_nul():
    w = Writer()
    w.append_string("hi")
    raw = w.data
    (n,) = struct.unpack_from("<I", raw, 0)
    assert n == 3  # h i \\0
    assert raw[4:] == b"hi\x00"
    r = Reader(raw)
    assert r.take_string() == "hi"


def test_empty_string_is_zero_length():
    w = Writer()
    w.append_string(None)
    w.append_wstring("")
    r = Reader(w.data)
    assert r.take_string() == ""
    assert r.take_wstring() == ""


def test_wstring_utf16le():
    w = Writer()
    w.append_wstring("ab")
    r = Reader(w.data)
    assert r.take_wstring() == "ab"


def test_job_trailer_layout():
    w = Writer()
    w.append_job_trailer(job_id=9, timeout_ms=1000, flags=1)
    r = Reader(w.data)
    assert r.take_u64() == 9
    assert r.take_u32() == 1000
    assert r.take_u32() == 1


def test_pipe_name_hash_stable():
    # Spot-check: same pid always same hash; known formula port
    h1 = pipe_name_hash(1234)
    h2 = pipe_name_hash(1234)
    assert h1 == h2
    assert h1 != pipe_name_hash(1235)
    name = format_pipe_name(1234)
    assert name.startswith("\\\\.\\pipe\\RPCControl_")
    assert name.endswith(f"{h1:08X}")


def test_format_pipe_name_env_exact():
    assert format_pipe_name(1, env_value="\\\\.\\pipe\\mine") == "\\\\.\\pipe\\mine"


def test_format_pipe_name_env_printf():
    assert format_pipe_name(42, env_value="\\\\.\\pipe\\x_%lu") == "\\\\.\\pipe\\x_42"


def test_status_name():
    assert status_name(HDL_OK) == "HDL_OK"
    assert "INVALID" in status_name(1)
