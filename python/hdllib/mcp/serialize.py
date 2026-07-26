"""JSON-safe encoding for MCP tool results."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any

from ..exceptions import HdlError, HdlStatusError
from ..protocol import status_name

# Field names treated as addresses when serializing dataclasses / dicts.
_ADDR_FIELDS = frozenset(
    {
        "addr",
        "address",
        "base",
        "branch_target",
        "bound_va",
        "caller",
        "end",
        "iat_va",
        "inject_addr",
        "last_exception_addr",
        "match_addr",
        "module_base",
        "region_base",
        "resolved_addr",
        "return_value",
        "rip",
        "rva",
        "start",
        "start_address",
        "static_base",
        "stub_va",
        "target",
        "to_addr",
        "from_addr",
        "va",
        "accessed",
        "watch_handle",
        "hook_id",
        "handle",
    }
)


def parse_addr(value: int | str) -> int:
    """Accept int or hex/dec string (``0x...`` or plain digits)."""
    if isinstance(value, int):
        return value
    text = str(value).strip().replace("_", "")
    if not text:
        raise ValueError("empty address")
    return int(text, 0)


def parse_optional_addr(value: int | str | None) -> int | None:
    if value is None or value == "":
        return None
    return parse_addr(value)


def bytes_hex(data: bytes | bytearray | memoryview) -> str:
    return bytes(data).hex()


def addr_dict(addr: int) -> dict[str, Any]:
    return {"addr": addr & 0xFFFFFFFFFFFFFFFF, "hex": f"0x{addr & 0xFFFFFFFFFFFFFFFF:x}"}


def _enrich_addr_fields(obj: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, val in obj.items():
        if key in _ADDR_FIELDS and isinstance(val, int):
            out[key] = val
            out[f"{key}_hex"] = f"0x{val & 0xFFFFFFFFFFFFFFFF:x}"
        elif isinstance(val, dict):
            out[key] = _enrich_addr_fields(val)
        elif isinstance(val, list):
            out[key] = [
                _enrich_addr_fields(v) if isinstance(v, dict) else v for v in val
            ]
        else:
            out[key] = val
    return out


def to_jsonable(obj: Any, *, address_fields: bool = True) -> Any:
    """Convert dataclasses, bytes, and nested containers to JSON-safe values."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes_hex(obj)
    if is_dataclass(obj) and not isinstance(obj, type):
        raw = asdict(obj)
        converted = {k: to_jsonable(v, address_fields=False) for k, v in raw.items()}
        return _enrich_addr_fields(converted) if address_fields else converted
    if isinstance(obj, dict):
        converted = {k: to_jsonable(v, address_fields=False) for k, v in obj.items()}
        return _enrich_addr_fields(converted) if address_fields else converted
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v, address_fields=address_fields) for v in obj]
    if isinstance(obj, set):
        return [to_jsonable(v, address_fields=address_fields) for v in obj]
    return str(obj)


def ok(data: Any = None, **extra: Any) -> str:
    payload: dict[str, Any] = {"ok": True}
    if data is not None:
        payload["data"] = to_jsonable(data)
    payload.update({k: to_jsonable(v) for k, v in extra.items()})
    return json.dumps(payload, separators=(",", ":"))


def err(message: str, *, status: int | None = None, **extra: Any) -> str:
    payload: dict[str, Any] = {"ok": False, "error": message}
    if status is not None:
        payload["status"] = status
        payload["status_name"] = status_name(status)
    payload.update({k: to_jsonable(v) for k, v in extra.items()})
    return json.dumps(payload, separators=(",", ":"))


def from_exception(exc: BaseException) -> str:
    if isinstance(exc, HdlStatusError):
        return err(str(exc), status=exc.status)
    if isinstance(exc, HdlError):
        return err(str(exc))
    return err(f"{type(exc).__name__}: {exc}")


def cap_list(items: list[Any], max_results: int) -> tuple[list[Any], int]:
    """Return (truncated, total_count)."""
    total = len(items)
    if max_results < 0:
        max_results = 0
    return items[:max_results], total
