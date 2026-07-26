"""Offline tests for the hdlclient-equivalent shell."""

from __future__ import annotations

import io
from unittest.mock import MagicMock

from hdllib.client import CallArg, HdlClient, ModuleInfo
from hdllib.shell import (
    SHELL_CONTINUE,
    SHELL_PYTHON,
    SHELL_QUIT,
    dispatch,
    parse_hex_bytes,
    parse_int,
    tokenize,
)


def test_tokenize_quotes():
    assert tokenize('scan --pattern "48 8B ?? 90"') == [
        "scan",
        "--pattern",
        "48 8B ?? 90",
    ]


def test_parse_int_hex():
    assert parse_int("0x10") == 16
    assert parse_int("16") == 16


def test_parse_hex_bytes():
    assert parse_hex_bytes("90 90") == b"\x90\x90"
    assert parse_hex_bytes("9090") == b"\x90\x90"


def test_dispatch_help_quit_py():
    hdl = MagicMock(spec=HdlClient)
    hdl.pid = 1
    out = io.StringIO()
    assert dispatch(hdl, "help", out) == SHELL_CONTINUE
    assert "ping" in out.getvalue()
    assert dispatch(hdl, "quit", out) == SHELL_QUIT
    assert dispatch(hdl, "py", out) == SHELL_PYTHON


def test_dispatch_ping_modules():
    hdl = MagicMock(spec=HdlClient)
    hdl.pid = 42
    hdl.ping.return_value = 42
    hdl.modules.return_value = [
        ModuleInfo(base=0x1000, size=0x100, path="C:\\x\\foo.exe"),
    ]
    out = io.StringIO()
    assert dispatch(hdl, "ping", out) == SHELL_CONTINUE
    assert "remote_pid=42" in out.getvalue()
    out = io.StringIO()
    assert dispatch(hdl, "modules", out) == SHELL_CONTINUE
    assert "foo.exe" in out.getvalue()
    hdl.modules.assert_called_with(stream=False)


def test_dispatch_read_write():
    hdl = MagicMock(spec=HdlClient)
    hdl.pid = 1
    hdl.read.return_value = b"\x4d\x5a"
    hdl.write.return_value = 2
    out = io.StringIO()
    assert dispatch(hdl, "read 0x1000 2", out) == SHELL_CONTINUE
    hdl.read.assert_called_with(0x1000, 2)
    assert "4D 5A" in out.getvalue()
    out = io.StringIO()
    assert dispatch(hdl, "write 0x1000 9090", out) == SHELL_CONTINUE
    hdl.write.assert_called_with(0x1000, b"\x90\x90")


def test_dispatch_call_args():
    hdl = MagicMock(spec=HdlClient)
    hdl.pid = 1
    result = MagicMock()
    result.return_value = 3
    result.last_error = 0
    result.buffers = {}
    hdl.call_export.return_value = result
    out = io.StringIO()
    assert dispatch(hdl, "call Foo i64:1 i64:2", out) == SHELL_CONTINUE
    args = hdl.call_export.call_args
    assert args[0][0] == "Foo"
    assert isinstance(args[0][1][0], CallArg)


def test_dispatch_unknown():
    hdl = MagicMock(spec=HdlClient)
    hdl.pid = 1
    out = io.StringIO()
    assert dispatch(hdl, "nope", out) == SHELL_CONTINUE
    assert "unknown command" in out.getvalue()


def test_dispatch_scan_pattern():
    hdl = MagicMock(spec=HdlClient)
    hdl.pid = 1
    hdl.search.return_value = [0xABC]
    out = io.StringIO()
    assert dispatch(hdl, 'scan --pattern "48 8B"', out) == SHELL_CONTINUE
    hdl.search.assert_called()
    assert "0000000000000abc" in out.getvalue().lower()
