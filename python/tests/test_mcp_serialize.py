"""Offline tests for MCP serialize helpers."""

from __future__ import annotations

import json

from hdllib.client import ModuleInfo
from hdllib.feature_ops import Insn
from hdllib.mcp.serialize import (
    addr_dict,
    bytes_hex,
    err,
    from_exception,
    ok,
    parse_addr,
    to_jsonable,
)
from hdllib.exceptions import HdlStatusError
from hdllib.re_ops import PointerPath


def test_parse_addr_hex_and_int():
    assert parse_addr(0x1000) == 0x1000
    assert parse_addr("0x1000") == 0x1000
    assert parse_addr("4096") == 4096


def test_bytes_hex():
    assert bytes_hex(b"\x90\x90") == "9090"


def test_addr_dict():
    d = addr_dict(0x7FF6ABCD0000)
    assert d["addr"] == 0x7FF6ABCD0000
    assert d["hex"].startswith("0x")


def test_to_jsonable_dataclass_enriches_addrs():
    mod = ModuleInfo(base=0x140000000, size=0x1000, path="C:\\game.exe")
    data = to_jsonable(mod)
    assert data["base"] == 0x140000000
    assert data["base_hex"] == "0x140000000"
    assert data["path"] == "C:\\game.exe"


def test_to_jsonable_insn_and_path():
    insn = Insn(
        addr=0x1000,
        length=5,
        flags=0,
        branch_target=0,
        rip_disp_offset=0,
        rip_disp_size=0,
        mnemonic="mov",
        op_str="rax, rbx",
    )
    data = to_jsonable(insn)
    assert data["addr_hex"] == "0x1000"
    assert data["mnemonic"] == "mov"

    path = PointerPath(static_base=0x140001000, depth=2, offsets=(0x10, 0x20))
    pdata = to_jsonable(path)
    assert pdata["static_base_hex"] == "0x140001000"
    assert pdata["offsets"] == [0x10, 0x20]


def test_ok_err_json():
    payload = json.loads(ok({"x": 1}))
    assert payload["ok"] is True
    assert payload["data"]["x"] == 1

    e = json.loads(err("boom", status=1))
    assert e["ok"] is False
    assert e["error"] == "boom"
    assert e["status"] == 1


def test_from_exception_status():
    payload = json.loads(from_exception(HdlStatusError(5, "nope")))
    assert payload["ok"] is False
    assert payload["status"] == 5
