"""Offline unit tests for CE-style strategy helpers."""

from __future__ import annotations

from unittest.mock import MagicMock

from hdllib.client import HdlClient
from hdllib.protocol import HDL_CMP_DECREASED, HDL_CMP_EXACT, HDL_VALUE_I32
from hdllib.re_ops import PointerPath
from hdllib.strategies import (
    AccessFinder,
    CheatTable,
    CodePatcher,
    PointerHelper,
    ValueScan,
    strategies_locals,
)
from hdllib.toolbox import DebugSession


def test_value_scan_exact_refine():
    hdl = MagicMock(spec=HdlClient)
    hdl.search_create.return_value = 1
    hdl.search_first.return_value = 1000
    hdl.search_next.return_value = 3
    hdl.search_get_hits.return_value = [0x1000, 0x2000, 0x3000]

    with ValueScan(hdl, HDL_VALUE_I32) as vs:
        assert vs.first_exact(100) == 1000
        assert vs.next_exact(95) == 3
        assert vs.hits() == [0x1000, 0x2000, 0x3000]

    hdl.search_close.assert_called_with(1)


def test_value_scan_unknown_decreased():
    hdl = MagicMock(spec=HdlClient)
    hdl.search_create.return_value = 2
    hdl.search_first.return_value = 50000
    hdl.search_next.return_value = 12

    vs = ValueScan(hdl, HDL_VALUE_I32)
    assert vs.first_unknown() == 50000
    assert vs.next_decreased() == 12
    assert hdl.search_first.call_args.kwargs["cmp"] != HDL_CMP_EXACT
    assert hdl.search_next.call_args.kwargs["cmp"] == HDL_CMP_DECREASED
    vs.close()


def test_cheat_table_pointer_resolve_and_write():
    hdl = MagicMock(spec=HdlClient)
    hdl.follow_pointers.return_value = 0xABCD
    hdl.read.return_value = b"\x64\x00\x00\x00"
    hdl.write.return_value = 4

    table = CheatTable(hdl)
    e = table.add(0, base=0x1000, offsets=[0x10, 0x20], description="hp")
    assert table.resolve(e) == 0xABCD
    hdl.follow_pointers.assert_called_with(0x1000, (0x10, 0x20))

    assert table.read(e) == 100
    table.write(e, 5000)
    assert hdl.write.called
    table.stop_freezer()


def test_access_finder_collects_unique_rips():
    hdl = MagicMock(spec=HdlClient)
    hit = MagicMock()
    hit.rip = 0x140001000
    hit.accessed = 0x1234
    hit.size = 4
    hit.tid = 1
    hdl.poll_watch_hits.return_value = [hit, hit]
    hdl.disasm.return_value = []
    hdl.resolve_function.side_effect = Exception("skip")

    finder = AccessFinder(hdl)
    finder._handle = 99
    out = finder.collect(disasm=True, resolve_fn=True)
    assert len(out) == 1
    assert out[0].rip == 0x140001000


def test_code_patcher_nop():
    hdl = MagicMock(spec=HdlClient)
    hdl.instr_len.return_value = 5
    hdl.patch_create.return_value = 7
    patcher = CodePatcher(hdl)
    assert patcher.nop_insn(0x1000, name="dmg") == 7
    hdl.patch_create.assert_called()
    args = hdl.patch_create.call_args
    assert args.args[0] == 0x1000
    assert args.args[1] == b"\x90" * 5
    hdl.patch_enable.assert_called_with(7, True)


def test_pointer_helper_to_entry():
    hdl = MagicMock(spec=HdlClient)
    helper = PointerHelper(hdl)
    path = PointerPath(static_base=0x140010000, depth=2, offsets=(0x10, 0x20))
    entry = helper.to_entry(path, final_offset=0x18, description="hp")
    assert entry.base == 0x140010000
    assert entry.offsets == (0x10, 0x20, 0x18)
    assert entry.description == "hp"


def test_strategies_locals_on_debug_session():
    hdl = MagicMock(spec=HdlClient)
    hdl.pid = 1
    hdl.connected = True
    dbg = DebugSession(hdl)
    ns = dbg.locals_dict()
    assert "ValueScan" in ns
    assert "ce" in ns
    assert "ptrs" in ns
    assert "aob" in ns
    extra = strategies_locals(dbg)
    assert set(extra) <= set(ns)
