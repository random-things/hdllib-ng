"""Offline tests for McpSession write gate and attach state."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from hdllib.mcp.serialize import from_exception
from hdllib.mcp.session import (
    McpSession,
    McpSessionError,
    reset_session_for_tests,
    tool_result,
)
from hdllib.mcp.tools_memory import register as register_memory


class _FakeMem:
    def read(self, address: int, size: int) -> bytes:
        return b"\x00" * size

    def write(self, address: int, data: bytes) -> int:
        return len(data)

    def write_u32(self, address: int, value: int) -> int:
        return 4


class _FakeHdl:
    def __init__(self, pid: int = 1) -> None:
        self.pid = pid
        self.connected = True

    def ping(self) -> int:
        return self.pid

    def modules(self):
        return []

    def module_base(self, name=None) -> int:
        return 0x140000000


class _FakeDbg:
    def __init__(self, pid: int = 42) -> None:
        self.hdl = _FakeHdl(pid)
        self.pid = pid
        self.connected = True
        self.mem = _FakeMem()

    def close(self) -> None:
        self.connected = False


def test_require_write_gate():
    s = reset_session_for_tests()
    s.allow_write = False
    with pytest.raises(McpSessionError, match="allow-write"):
        s.require_write()
    s.allow_write = True
    s.require_write()


def test_require_attached():
    s = reset_session_for_tests()
    with pytest.raises(McpSessionError, match="Not attached"):
        s.require_attached()
    s.dbg = _FakeDbg()
    assert s.require_attached().pid == 42


def test_tool_result_wraps_errors():
    @tool_result
    def boom() -> str:
        raise McpSessionError("nope")

    payload = json.loads(boom())
    assert payload["ok"] is False
    assert "nope" in payload["error"]


def test_mem_write_blocked_without_allow_write(monkeypatch):
    """Exercise mem_write tool gate via a minimal FastMCP-free call path."""
    s = reset_session_for_tests()
    s.allow_write = False
    s.dbg = _FakeDbg()

    # Import the wrapped function by registering onto a stub.
    tools = {}

    class StubMcp:
        def tool(self):
            def deco(fn):
                tools[fn.__name__] = fn
                return fn

            return deco

    register_memory(StubMcp())
    result = json.loads(tools["mem_write"]("0x1000", 1, type="u32"))
    assert result["ok"] is False
    assert "allow-write" in result["error"]

    s.allow_write = True
    result_ok = json.loads(tools["mem_write"]("0x1000", 1, type="u32"))
    assert result_ok["ok"] is True


def test_detach_clears_state():
    s = reset_session_for_tests()
    s.dbg = _FakeDbg()
    s.value_scans["default"] = SimpleNamespace(close=lambda: None)
    s.detach()
    assert s.dbg is None
    assert s.value_scans == {}


def test_from_exception_mcp_session():
    payload = json.loads(from_exception(McpSessionError("x")))
    assert payload["ok"] is False
