"""Offline unit tests for Memory helpers and DebugSession.locals_dict."""

from __future__ import annotations

import struct
from unittest.mock import MagicMock

from hdllib.client import CallArg, HdlClient
from hdllib.toolbox import DebugSession, Memory


def test_memory_typed_read_write():
    hdl = MagicMock(spec=HdlClient)
    mem = Memory(hdl)

    hdl.read.return_value = struct.pack("<I", 0xAABBCCDD)
    assert mem.u32(0x1000) == 0xAABBCCDD
    hdl.read.assert_called_with(0x1000, 4)

    hdl.read.return_value = struct.pack("<Q", 0x1122334455667788)
    assert mem.ptr(0x2000) == 0x1122334455667788

    hdl.read.return_value = struct.pack("<f", 1.5)
    assert mem.f32(0x3000) == 1.5

    hdl.write.return_value = 4
    assert mem.write_u32(0x4000, 42) == 4
    hdl.write.assert_called_with(0x4000, struct.pack("<I", 42))

    hdl.write.return_value = 8
    mem.write_ptr(0x5000, 0xDEADBEEF)
    hdl.write.assert_called_with(0x5000, struct.pack("<Q", 0xDEADBEEF))


def test_debug_session_locals_dict_keys():
    hdl = MagicMock(spec=HdlClient)
    hdl.pid = 99
    hdl.connected = True
    dbg = DebugSession(hdl)
    ns = dbg.locals_dict()
    expected = {
        "dbg",
        "hdl",
        "mem",
        "scan",
        "hooks",
        "watches",
        "structs",
        "graph",
        "place",
        "code",
        "pe",
        "health",
        "CallArg",
        "HdlClient",
        "DiscoverSession",
        "SearchSession",
        "FieldPred",
    }
    assert expected <= set(ns.keys())
    assert ns["dbg"] is dbg
    assert ns["hdl"] is hdl
    assert ns["mem"] is dbg.mem
    assert ns["scan"] is dbg.scan
    assert ns["hooks"] is dbg.hooks
    assert ns["watches"] is dbg.watches
    assert ns["structs"] is dbg.structs
    assert ns["graph"] is dbg.graph
    assert ns["place"] is dbg.place
    assert ns["code"] is dbg.code
    assert ns["pe"] is dbg.pe
    assert ns["health"] is dbg.health
    assert ns["CallArg"] is CallArg
    assert ns["HdlClient"] is HdlClient
    assert dbg.pid == 99
