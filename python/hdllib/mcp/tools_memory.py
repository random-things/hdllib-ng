"""Memory read/write MCP tools."""

from __future__ import annotations

from typing import Any

from .serialize import bytes_hex, ok, parse_addr
from .session import get_session, tool_result

_TYPED_READERS = {
    "u8",
    "i8",
    "u16",
    "i16",
    "u32",
    "i32",
    "u64",
    "i64",
    "ptr",
    "f32",
    "f64",
    "bytes",
}


def register(mcp: Any) -> None:
    @mcp.tool()
    @tool_result
    def mem_read(
        address: int | str,
        size: int = 16,
        type: str = "bytes",
    ) -> str:
        """Read target memory.

        type: bytes (default), u8/i8/u16/i16/u32/i32/u64/i64/ptr/f32/f64.
        For typed reads, size is ignored.
        """
        addr = parse_addr(address)
        mem = get_session().require_attached().mem
        kind = (type or "bytes").lower()
        if kind not in _TYPED_READERS:
            raise ValueError(f"unsupported type {type!r}")
        if kind == "bytes":
            if size <= 0 or size > 0x100000:
                raise ValueError("size must be 1..1048576")
            raw = mem.read(addr, size)
            return ok(
                {
                    "address": addr,
                    "address_hex": f"0x{addr:x}",
                    "type": "bytes",
                    "hex": bytes_hex(raw),
                    "length": len(raw),
                }
            )
        value = getattr(mem, kind)(addr)
        return ok(
            {
                "address": addr,
                "address_hex": f"0x{addr:x}",
                "type": kind,
                "value": value,
            }
        )

    @mcp.tool()
    @tool_result
    def mem_write(
        address: int | str,
        value: int | float | str,
        type: str = "bytes",
    ) -> str:
        """Write target memory (requires --allow-write).

        type: bytes (value as hex string), or u8/i8/.../f64/ptr with numeric value.
        """
        s = get_session()
        s.require_write()
        addr = parse_addr(address)
        mem = s.require_attached().mem
        kind = (type or "bytes").lower()
        if kind == "bytes":
            if isinstance(value, (int, float)):
                raise ValueError("bytes write expects a hex string value")
            hex_text = str(value).replace(" ", "").replace("0x", "")
            raw = bytes.fromhex(hex_text)
            n = mem.write(addr, raw)
            return ok(
                {
                    "address": addr,
                    "address_hex": f"0x{addr:x}",
                    "type": "bytes",
                    "written": n,
                }
            )
        writers = {
            "u8": "write_u8",
            "i8": "write_i8",
            "u16": "write_u16",
            "i16": "write_i16",
            "u32": "write_u32",
            "i32": "write_i32",
            "u64": "write_u64",
            "i64": "write_i64",
            "ptr": "write_ptr",
            "f32": "write_f32",
            "f64": "write_f64",
        }
        if kind not in writers:
            raise ValueError(f"unsupported type {type!r}")
        method = getattr(mem, writers[kind])
        if kind in ("f32", "f64"):
            method(addr, float(value))
        else:
            if isinstance(value, str):
                value = int(value, 0)
            method(addr, int(value))
        return ok(
            {
                "address": addr,
                "address_hex": f"0x{addr:x}",
                "type": kind,
                "value": value,
            }
        )
