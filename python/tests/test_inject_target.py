"""End-to-end inject + pipe tests against hdl_test_target.exe."""

from __future__ import annotations

from pathlib import Path

import pytest

from hdllib import INJECT_CREATE_REMOTE_THREAD, Session
from hdllib._dll import find_hdllib_dll
from hdllib.client import CallArg
from hdllib.process import find_processes

pytestmark = pytest.mark.inject


def test_find_hdllib_dll(hdllib_dll: Path):
    assert find_hdllib_dll() == hdllib_dll


def test_inject_ping_modules(running_target: int, hdllib_dll: Path):
    with Session(running_target) as session:
        base = session.inject(
            dll=str(hdllib_dll),
            method=INJECT_CREATE_REMOTE_THREAD,
            timeout_ms=15000,
        )
        assert base != 0
        assert session.ping() == running_target
        mods = session.modules()
        assert mods
        names = " ".join(m.path.lower() for m in mods)
        assert "hdl_test_target" in names or "hdllib.dll" in names
        # Prefer seeing both when LoadLibrary inject succeeded
        assert any("hdllib" in m.path.lower() for m in mods)


def test_read_module_base_and_export(running_target: int, hdllib_dll: Path):
    with Session(running_target) as session:
        session.inject(dll=str(hdllib_dll), timeout_ms=15000)
        base = session.module_base()
        assert base != 0
        # PE MZ header
        mz = session.read(base, 2)
        assert mz == b"MZ"
        addr = session.resolve_export("HdlTestLocateFn")
        assert addr != 0
        result = session.call_export(
            "HdlTestLocateFn",
            [CallArg.of_i64(1), CallArg.of_i64(2)],
        )
        assert result.return_value == 3


def test_aob_search_magic(running_target: int, hdllib_dll: Path):
    # Immediate 0x48444C31 little-endian bytes appear in HdlTestLocateFn
    pattern = "31 4C 44 48"
    with Session(running_target) as session:
        session.inject(dll=str(hdllib_dll), timeout_ms=15000)
        hits = session.search(pattern, max_hits=16)
        assert hits, "expected AOB hits for HDL1 magic"


def test_process_find_sees_target(running_target: int):
    procs = find_processes("hdl_test_target.exe")
    assert any(p.pid == running_target for p in procs)
