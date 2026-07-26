"""Offline unit tests for feature_ops struct parsers and toolbox facades."""

from __future__ import annotations

import struct
from unittest.mock import MagicMock

from hdllib.client import HdlClient
from hdllib.feature_ops import (
    _CAVE_SIZE,
    _EXPORT_SIZE,
    _SYNTH_SIZE,
    _parse_cave,
    _parse_export,
    _parse_synth,
)
from hdllib.toolbox import (
    Code,
    DebugSession,
    DiscoverSession,
    Health,
    Pe,
    Place,
    SearchSession,
)


def test_struct_sizes_match_msvc():
    assert _CAVE_SIZE == 32
    assert _EXPORT_SIZE == 160
    assert _SYNTH_SIZE == 232


def test_parse_cave_and_export():
    raw = struct.pack("<QQQI4x", 0x1000, 64, 0x1000, 0)
    cave = _parse_cave(raw)
    assert cave.addr == 0x1000
    assert cave.size == 64

    raw_exp = struct.pack(
        "<128sIII4xQQ",
        b"Foo\x00" + b"\x00" * 124,
        7,
        0,
        0,
        0x10,
        0x140001010,
    )
    exp = _parse_export(raw_exp)
    assert exp.name == "Foo"
    assert exp.ordinal == 7
    assert exp.va == 0x140001010


def test_parse_synth_padding():
    pattern = b"48 8B ??\x00" + b"\x00" * (192 - 9)
    raw = struct.pack(
        "<192siII4xQQII",
        pattern,
        -3,
        3,
        7,
        0x140001000,
        0x140002000,
        1,
        0,
    )
    syn = _parse_synth(raw)
    assert syn.pattern.startswith("48 8B")
    assert syn.pattern_offset == -3
    assert syn.unique_hits == 1


def test_debug_session_exposes_new_facades():
    hdl = MagicMock(spec=HdlClient)
    hdl.pid = 1
    hdl.connected = True
    dbg = DebugSession(hdl)
    ns = dbg.locals_dict()
    assert ns["place"] is dbg.place
    assert ns["code"] is dbg.code
    assert ns["pe"] is dbg.pe
    assert ns["health"] is dbg.health
    assert isinstance(dbg.place, Place)
    assert isinstance(dbg.code, Code)
    assert isinstance(dbg.pe, Pe)
    assert isinstance(dbg.health, Health)


def test_search_session_context_manager():
    hdl = MagicMock(spec=HdlClient)
    hdl.search_create.return_value = 42
    with SearchSession(hdl) as s:
        assert s.id == 42
        s.first(b"\x01\x00\x00\x00", value_type=6)
    hdl.search_close.assert_called_once_with(42)


def test_discover_session_delegates():
    hdl = MagicMock(spec=HdlClient)
    hdl.discover_create.return_value = 9
    hdl.discover_add_candidate.return_value = 3
    with DiscoverSession(hdl) as d:
        assert d.add(0x1000, tag="x") == 3
        hdl.discover_add_candidate.assert_called_with(
            9, 0x1000, kind=1, tag="x"
        )
    hdl.discover_close.assert_called_once_with(9)


def test_place_and_code_facades():
    hdl = MagicMock(spec=HdlClient)
    hdl.alloc.return_value = 0x2000
    hdl.patch_create.return_value = 11
    place = Place(hdl)
    assert place.alloc(0x1000) == 0x2000
    code = Code(hdl)
    assert code.patch(0x1000, b"\x90\x90", name="nop") == 11
    hdl.patch_enable.assert_called_with(11, True)
