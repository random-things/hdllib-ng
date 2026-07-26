"""hdlclient-equivalent command shell over :class:`HdlClient`."""

from __future__ import annotations

import shlex
import struct
from collections.abc import Callable, Sequence
from typing import TextIO

from .client import CallArg, HdlClient
from .exceptions import HdlError, HdlStatusError
from .inject import INJECT_CREATE_REMOTE_THREAD, METHOD_NAMES
from .protocol import (
    HDL_CMP_CHANGED,
    HDL_CMP_DECREASED,
    HDL_CMP_DECREASED_BY,
    HDL_CMP_EXACT,
    HDL_CMP_GREATER,
    HDL_CMP_INCREASED,
    HDL_CMP_INCREASED_BY,
    HDL_CMP_LESS,
    HDL_CMP_UNCHANGED,
    HDL_CMP_UNKNOWN,
    HDL_SEARCH_EXECUTABLE,
    HDL_SEARCH_IMAGE,
    HDL_SEARCH_MODULE,
    HDL_VALUE_BYTES,
    HDL_VALUE_F32,
    HDL_VALUE_F64,
    HDL_VALUE_I8,
    HDL_VALUE_I16,
    HDL_VALUE_I32,
    HDL_VALUE_I64,
    HDL_VALUE_STRING,
    HDL_VALUE_U8,
    HDL_VALUE_U16,
    HDL_VALUE_U32,
    HDL_VALUE_U64,
    HDL_VALUE_WSTRING,
)

_VALUE_TYPES = {
    "bytes": HDL_VALUE_BYTES,
    "i8": HDL_VALUE_I8,
    "u8": HDL_VALUE_U8,
    "i16": HDL_VALUE_I16,
    "u16": HDL_VALUE_U16,
    "i32": HDL_VALUE_I32,
    "u32": HDL_VALUE_U32,
    "i64": HDL_VALUE_I64,
    "u64": HDL_VALUE_U64,
    "f32": HDL_VALUE_F32,
    "float": HDL_VALUE_F32,
    "f64": HDL_VALUE_F64,
    "double": HDL_VALUE_F64,
    "string": HDL_VALUE_STRING,
    "wstring": HDL_VALUE_WSTRING,
}

_CMP_TYPES = {
    "exact": HDL_CMP_EXACT,
    "unknown": HDL_CMP_UNKNOWN,
    "changed": HDL_CMP_CHANGED,
    "unchanged": HDL_CMP_UNCHANGED,
    "increased": HDL_CMP_INCREASED,
    "decreased": HDL_CMP_DECREASED,
    "increased_by": HDL_CMP_INCREASED_BY,
    "decreased_by": HDL_CMP_DECREASED_BY,
    "greater": HDL_CMP_GREATER,
    "less": HDL_CMP_LESS,
}

# Switch codes for the outer loop
SHELL_CONTINUE = 0
SHELL_QUIT = -1
SHELL_PYTHON = 1

CmdHandler = Callable[[HdlClient, list[str], TextIO], int]


def tokenize(line: str) -> list[str]:
    """Split a shell line (supports double quotes, like hdlclient REPL)."""
    if not line.strip():
        return []
    try:
        # posix=False keeps Windows paths happy; strip surrounding quotes manually.
        parts = shlex.split(line, posix=False)
    except ValueError:
        parts = line.split()
    out: list[str] = []
    for p in parts:
        if len(p) >= 2 and ((p[0] == p[-1] == '"') or (p[0] == p[-1] == "'")):
            out.append(p[1:-1])
        else:
            out.append(p)
    return out


def parse_int(text: str) -> int:
    text = text.strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text, 0)


def parse_hex_bytes(text: str) -> bytes:
    cleaned = "".join(ch for ch in text if not ch.isspace())
    if cleaned.startswith("@"):
        with open(cleaned[1:], "rb") as f:
            return f.read()
    if len(cleaned) % 2 != 0:
        raise ValueError(f"odd hex length: {text!r}")
    return bytes.fromhex(cleaned)


def _flag(args: Sequence[str], name: str) -> bool:
    return name in args


def _opt(args: list[str], name: str) -> str | None:
    if name in args:
        i = args.index(name)
        if i + 1 >= len(args):
            raise ValueError(f"{name} needs a value")
        return args[i + 1]
    return None


def _take_opt(args: list[str], name: str) -> str | None:
    if name not in args:
        return None
    i = args.index(name)
    if i + 1 >= len(args):
        raise ValueError(f"{name} needs a value")
    val = args[i + 1]
    del args[i : i + 2]
    return val


def _hexdump(data: bytes, base: int = 0) -> str:
    lines: list[str] = []
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        lines.append(f"{base + off:016X}  {hexpart}")
    return "\n".join(lines)


def _parse_call_arg(text: str) -> CallArg:
    if ":" not in text:
        raise ValueError(f"call arg needs kind:value, got {text!r}")
    kind, _, rest = text.partition(":")
    kind = kind.lower()
    if kind == "u64":
        return CallArg.of_u64(parse_int(rest))
    if kind == "i64":
        return CallArg.of_i64(parse_int(rest))
    if kind == "ptr":
        return CallArg.of_ptr(parse_int(rest))
    if kind == "cstr":
        return CallArg.of_cstr(rest)
    if kind == "wstr":
        return CallArg.of_wstr(rest)
    if kind == "buf":
        return CallArg.of_buf(parse_hex_bytes(rest))
    if kind == "f32":
        return CallArg.of_f32(float(rest))
    if kind == "f64":
        return CallArg.of_f64(float(rest))
    raise ValueError(f"unknown call arg kind: {kind}")


def _encode_typed_value(value_type: int, text: str) -> bytes:
    if value_type == HDL_VALUE_BYTES:
        return text.encode("utf-8") + b"\x00"
    if value_type == HDL_VALUE_I8:
        return struct.pack("<b", parse_int(text))
    if value_type == HDL_VALUE_U8:
        return struct.pack("<B", parse_int(text) & 0xFF)
    if value_type == HDL_VALUE_I16:
        return struct.pack("<h", parse_int(text))
    if value_type == HDL_VALUE_U16:
        return struct.pack("<H", parse_int(text) & 0xFFFF)
    if value_type == HDL_VALUE_I32:
        return struct.pack("<i", parse_int(text))
    if value_type == HDL_VALUE_U32:
        return struct.pack("<I", parse_int(text) & 0xFFFFFFFF)
    if value_type == HDL_VALUE_I64:
        return struct.pack("<q", parse_int(text))
    if value_type == HDL_VALUE_U64:
        return struct.pack("<Q", parse_int(text) & 0xFFFFFFFFFFFFFFFF)
    if value_type == HDL_VALUE_F32:
        return struct.pack("<f", float(text))
    if value_type == HDL_VALUE_F64:
        return struct.pack("<d", float(text))
    if value_type == HDL_VALUE_STRING:
        return text.encode("utf-8")
    if value_type == HDL_VALUE_WSTRING:
        return text.encode("utf-16-le")
    raise ValueError(f"unsupported value type {value_type}")


def _parse_method(text: str) -> int:
    key = text.strip().lower().replace("-", "_")
    if key.lstrip("-").isdigit():
        return int(key)
    for method, name in METHOD_NAMES.items():
        if name == key:
            return method
    raise ValueError(f"unknown inject method: {text}")


HELP_TEXT = """\
hdllib shell — hdlclient-equivalent commands (Session/HdlClient)

  help / ?              this help
  quit / exit           leave the shell
  py / python           Python REPL with `hdl` bound to HdlClient

  ping
  log <0-3>
  modules [--stream]
  regions [--stream]
  modbase [--module NAME]
  read <hex-addr> <size>
  write <hex-addr> <hex-bytes|@file>
  scan --pattern "AOB" [--max N] [--start HEX] [--size HEX]
  scan --type TYPE --value VAL [--max N] [--cmp MODE] [--image] [--module NAME]
  scan --next --session ID --cmp MODE [--value VAL]
  scan --hits --session ID [--max N]
  scan --close|--reset --session ID
  resolve [--module NAME] <export>
  call [--module NAME] <export> [u64:N|i64:N|ptr:HEX|cstr:…|…]
  call --addr HEX [ARGS…]
  hooktrace <hex-addr> [--args N]
  unhook <hex-handle>
  hook-enable <hex-handle> 0|1
  hookhits [--max N] [--timeout MS]
  inject [--dll PATH] [--method NAME]

Types: bytes i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 string wstring
Cmp:   exact unknown changed unchanged increased decreased …
"""


def cmd_help(_hdl: HdlClient, _args: list[str], out: TextIO) -> int:
    out.write(HELP_TEXT)
    if not HELP_TEXT.endswith("\n"):
        out.write("\n")
    return SHELL_CONTINUE


def cmd_quit(_hdl: HdlClient, _args: list[str], _out: TextIO) -> int:
    return SHELL_QUIT


def cmd_python(_hdl: HdlClient, _args: list[str], _out: TextIO) -> int:
    return SHELL_PYTHON


def cmd_ping(hdl: HdlClient, _args: list[str], out: TextIO) -> int:
    pid = hdl.ping()
    out.write(f"status=HDL_OK remote_pid={pid}\n")
    return SHELL_CONTINUE


def cmd_log(hdl: HdlClient, args: list[str], out: TextIO) -> int:
    if not args:
        raise ValueError("usage: log <0-3>")
    hdl.set_log_level(int(args[0]))
    out.write("status=HDL_OK\n")
    return SHELL_CONTINUE


def cmd_modules(hdl: HdlClient, args: list[str], out: TextIO) -> int:
    mods = hdl.modules(stream=_flag(args, "--stream"))
    out.write(f"status=HDL_OK count={len(mods)}\n")
    for m in mods:
        out.write(f"  {m.base:016x}  {m.size:8x}  {m.path}\n")
    return SHELL_CONTINUE


def cmd_regions(hdl: HdlClient, args: list[str], out: TextIO) -> int:
    regs = hdl.regions(stream=_flag(args, "--stream"))
    out.write(f"status=HDL_OK count={len(regs)}\n")
    for r in regs:
        out.write(f"  {r.base:016x}  {r.size:8x}  prot={r.protect:08x}\n")
    return SHELL_CONTINUE


def cmd_modbase(hdl: HdlClient, args: list[str], out: TextIO) -> int:
    module = _opt(args, "--module")
    base = hdl.module_base(module)
    out.write(f"status=HDL_OK base={base:016x}\n")
    return SHELL_CONTINUE


def cmd_read(hdl: HdlClient, args: list[str], out: TextIO) -> int:
    if len(args) < 2:
        raise ValueError("usage: read <hex-addr> <size>")
    addr = parse_int(args[0])
    size = parse_int(args[1])
    data = hdl.read(addr, size)
    out.write(f"status=HDL_OK bytes={len(data)}\n")
    out.write(_hexdump(data, addr) + "\n")
    return SHELL_CONTINUE


def cmd_write(hdl: HdlClient, args: list[str], out: TextIO) -> int:
    if len(args) < 2:
        raise ValueError("usage: write <hex-addr> <hex-bytes|@file>")
    addr = parse_int(args[0])
    data = parse_hex_bytes(args[1])
    wrote = hdl.write(addr, data)
    out.write(f"status=HDL_OK wrote={wrote}\n")
    return SHELL_CONTINUE


def cmd_scan(hdl: HdlClient, args: list[str], out: TextIO) -> int:
    a = list(args)
    if _flag(a, "--close") or _flag(a, "--reset"):
        sid = _opt(a, "--session")
        if not sid:
            raise ValueError("--session required")
        session = parse_int(sid)
        if _flag(a, "--close"):
            hdl.search_close(session)
            out.write(f"status=HDL_OK session={session} closed\n")
        else:
            hdl.search_reset(session)
            out.write(f"status=HDL_OK session={session} reset\n")
        return SHELL_CONTINUE

    if _flag(a, "--hits"):
        sid = _opt(a, "--session")
        if not sid:
            raise ValueError("--session required")
        max_n = parse_int(_opt(a, "--max") or "64")
        hits = hdl.search_get_hits(parse_int(sid), max_hits=max_n)
        out.write(f"status=HDL_OK showing={len(hits)} session={sid}\n")
        for h in hits:
            out.write(f"  {h:016x}\n")
        return SHELL_CONTINUE

    if _flag(a, "--next"):
        sid = _opt(a, "--session")
        cmp_name = _opt(a, "--cmp")
        if not sid or not cmp_name:
            raise ValueError("--session and --cmp required for --next")
        cmp = _CMP_TYPES.get(cmp_name.lower())
        if cmp is None:
            raise ValueError(f"bad --cmp {cmp_name}")
        value_text = _opt(a, "--value")
        value = b""
        if value_text is not None:
            # type unknown on next; encode as u32/i32 if looks numeric else bytes pattern
            type_name = _opt(a, "--type") or "u32"
            vt = _VALUE_TYPES.get(type_name.lower())
            if vt is None:
                raise ValueError(f"bad --type {type_name}")
            value = _encode_typed_value(vt, value_text)
        count = hdl.search_next(parse_int(sid), cmp=cmp, value=value)
        out.write(f"status=HDL_OK hits={count} session={sid}\n")
        hits = hdl.search_get_hits(parse_int(sid), max_hits=parse_int(_opt(a, "--max") or "64"))
        for h in hits:
            out.write(f"  {h:016x}\n")
        return SHELL_CONTINUE

    pattern = _opt(a, "--pattern")
    type_name = _opt(a, "--type")
    max_n = parse_int(_opt(a, "--max") or "64")
    start = parse_int(_opt(a, "--start") or "0")
    size = parse_int(_opt(a, "--size") or "0")

    if pattern and not type_name:
        hits = hdl.search(pattern, start=start, size=size, max_hits=max_n)
        out.write(f"status=HDL_OK hits={len(hits)}\n")
        for h in hits:
            out.write(f"  {h:016x}\n")
        return SHELL_CONTINUE

    if not type_name:
        raise ValueError("scan needs --pattern or --type")
    vt = _VALUE_TYPES.get(type_name.lower())
    if vt is None:
        raise ValueError(f"bad --type {type_name}")
    cmp_name = (_opt(a, "--cmp") or "exact").lower()
    cmp = _CMP_TYPES.get(cmp_name)
    if cmp is None:
        raise ValueError(f"bad --cmp {cmp_name}")
    value_text = _opt(a, "--value")
    if pattern and value_text is None:
        value_text = pattern
    if cmp != HDL_CMP_UNKNOWN and value_text is None and vt != HDL_VALUE_BYTES:
        raise ValueError("--value required")
    encoded = _encode_typed_value(vt, value_text or "") if value_text is not None else b""
    flags = 0
    if _flag(a, "--image"):
        flags |= HDL_SEARCH_IMAGE
    if _flag(a, "--executable"):
        flags |= HDL_SEARCH_EXECUTABLE
    module = _opt(a, "--module")
    if module:
        flags |= HDL_SEARCH_MODULE
    sid_text = _opt(a, "--session")
    session = parse_int(sid_text) if sid_text else hdl.search_create()
    count = hdl.search_first(
        session,
        value=encoded,
        value_type=vt,
        cmp=cmp,
        start=start,
        size=size,
        alignment=1 if _flag(a, "--unaligned") else 0,
        max_results=max_n,
        flags=flags,
        module=module,
    )
    out.write(f"status=HDL_OK hits={count} session={session}\n")
    hits = hdl.search_get_hits(session, max_hits=max_n)
    for h in hits:
        out.write(f"  {h:016x}\n")
    return SHELL_CONTINUE


def cmd_resolve(hdl: HdlClient, args: list[str], out: TextIO) -> int:
    a = list(args)
    module = _take_opt(a, "--module")
    if not a:
        raise ValueError("usage: resolve [--module NAME] <export>")
    addr = hdl.resolve_export(a[0], module=module)
    out.write(f"status=HDL_OK addr={addr:016x}\n")
    return SHELL_CONTINUE


def cmd_call(hdl: HdlClient, args: list[str], out: TextIO) -> int:
    a = list(args)
    module = _take_opt(a, "--module")
    addr_text = _take_opt(a, "--addr")
    timeout = parse_int(_take_opt(a, "--timeout") or "0")
    call_args: list[CallArg] = []
    export: str | None = None
    if addr_text is None:
        if not a:
            raise ValueError("usage: call [--module NAME] <export> [ARGS…]")
        export = a[0]
        rest = a[1:]
    else:
        rest = a
    for t in rest:
        call_args.append(_parse_call_arg(t))
    if addr_text is not None:
        result = hdl.call(parse_int(addr_text), call_args, timeout_ms=timeout)
    else:
        assert export is not None
        result = hdl.call_export(export, call_args, module=module, timeout_ms=timeout)
    out.write(
        f"status=HDL_OK return={result.return_value:016x} last_error={result.last_error}\n"
    )
    for idx, blob in result.buffers.items():
        out.write(f"buf[{idx}]={blob.hex()}\n")
    return SHELL_CONTINUE


def cmd_hooktrace(hdl: HdlClient, args: list[str], out: TextIO) -> int:
    if not args:
        raise ValueError("usage: hooktrace <hex-addr> [--args N]")
    a = list(args)
    target = parse_int(a[0])
    arg_count = parse_int(_opt(a, "--args") or "0")
    handle = hdl.hook_trace(target, arg_count=arg_count)
    out.write(f"status=HDL_OK handle={handle:016x}\n")
    return SHELL_CONTINUE


def cmd_unhook(hdl: HdlClient, args: list[str], out: TextIO) -> int:
    if not args:
        raise ValueError("usage: unhook <hex-handle>")
    hdl.unhook(parse_int(args[0]))
    out.write("status=HDL_OK\n")
    return SHELL_CONTINUE


def cmd_hook_enable(hdl: HdlClient, args: list[str], out: TextIO) -> int:
    if len(args) < 2:
        raise ValueError("usage: hook-enable <hex-handle> 0|1")
    hdl.enable_hook(parse_int(args[0]), bool(int(args[1])))
    out.write("status=HDL_OK\n")
    return SHELL_CONTINUE


def cmd_hookhits(hdl: HdlClient, args: list[str], out: TextIO) -> int:
    max_n = parse_int(_opt(args, "--max") or "16")
    timeout = parse_int(_opt(args, "--timeout") or "0")
    hits = hdl.poll_hook_hits(max_n=max_n, timeout_ms=timeout)
    out.write(f"status=HDL_OK count={len(hits)}\n")
    for h in hits:
        parts = [
            f"  hook={h.hook_id:016x}",
            f"ret={h.return_value:016x}",
            f"caller={h.caller:016x}",
            f"args={h.arg_count}",
        ]
        for i, v in enumerate(h.args):
            parts.append(f"a{i}={v:x}")
        out.write(" ".join(parts) + "\n")
    return SHELL_CONTINUE


def cmd_inject(hdl: HdlClient, args: list[str], out: TextIO) -> int:
    a = list(args)
    dll = _take_opt(a, "--dll")
    method_text = _take_opt(a, "--method")
    method = _parse_method(method_text) if method_text else INJECT_CREATE_REMOTE_THREAD
    # bare path as first positional
    if a and not a[0].startswith("-"):
        dll = a[0]
    base = hdl.inject(dll=dll, method=method, connect=True)
    out.write(f"status=HDL_OK base={base:016x} pid={hdl.pid}\n")
    return SHELL_CONTINUE


COMMANDS: dict[str, CmdHandler] = {
    "help": cmd_help,
    "?": cmd_help,
    "quit": cmd_quit,
    "exit": cmd_quit,
    "py": cmd_python,
    "python": cmd_python,
    "ping": cmd_ping,
    "log": cmd_log,
    "modules": cmd_modules,
    "regions": cmd_regions,
    "modbase": cmd_modbase,
    "read": cmd_read,
    "write": cmd_write,
    "scan": cmd_scan,
    "resolve": cmd_resolve,
    "call": cmd_call,
    "hooktrace": cmd_hooktrace,
    "unhook": cmd_unhook,
    "hook-enable": cmd_hook_enable,
    "enablehook": cmd_hook_enable,
    "hookhits": cmd_hookhits,
    "inject": cmd_inject,
}


def dispatch(hdl: HdlClient, line: str, out: TextIO) -> int:
    """Run one shell line. Returns SHELL_CONTINUE / SHELL_QUIT / SHELL_PYTHON."""
    tokens = tokenize(line)
    if not tokens:
        return SHELL_CONTINUE
    cmd = tokens[0].lower()
    handler = COMMANDS.get(cmd)
    if handler is None:
        out.write(f"unknown command: {tokens[0]!r} (try help)\n")
        return SHELL_CONTINUE
    try:
        return handler(hdl, tokens[1:], out)
    except (HdlError, HdlStatusError, ValueError, OSError) as exc:
        out.write(f"error: {exc}\n")
        return SHELL_CONTINUE


def run_shell(
    hdl: HdlClient,
    *,
    game: object | None = None,
    dbg: object | None = None,
    input_fn: Callable[[str], str] | None = None,
    out: TextIO | None = None,
) -> None:
    """Interactive command loop (``hdl:PID>``). ``py`` enters the Python REPL."""
    import sys

    if out is None:
        out = sys.stdout
    if input_fn is None:
        input_fn = input

    game_note = f" game={getattr(game, 'name', game)}" if game is not None else ""
    out.write(f"hdllib shell pid={hdl.pid}{game_note}  (help | py | quit)\n")
    while True:
        try:
            line = input_fn(f"hdl:{hdl.pid}> ")
        except EOFError:
            out.write("\n")
            break
        except KeyboardInterrupt:
            out.write("\n")
            continue
        code = dispatch(hdl, line, out)
        if code == SHELL_QUIT:
            break
        if code == SHELL_PYTHON:
            run_python_repl(hdl, game=game, dbg=dbg, out=out)


def run_python_repl(
    hdl: HdlClient,
    *,
    game: object | None = None,
    dbg: object | None = None,
    out: TextIO | None = None,
) -> None:
    """Programmatic REPL with ``hdl`` (and optional ``dbg`` / ``game``) bound."""
    import code
    import sys

    if out is None:
        out = sys.stdout
    lines = [
        f"Python REPL — hdl is HdlClient(pid={hdl.pid})",
        "Examples: hdl.ping(), hdl.modules(), hdl.read(addr, 64)",
    ]
    if dbg is not None:
        lines.append(
            "Toolbox: dbg, mem, scan, hooks, watches, structs, graph"
        )
        lines.append("Examples: mem.u32(addr), scan.aob('48 8B ??'), graph.xrefs_to(addr)")
    if game is not None:
        lines.append(f"game is {type(game).__name__}({getattr(game, 'name', '?')!r})")
        lines.append("Examples: game.verify_attached(hdl), game.find_exe()")
    lines.append(
        "Ctrl-Z Enter (Windows) / Ctrl-D (Unix) returns to the command shell."
    )
    banner = "\n".join(lines) + "\n"
    ns: dict[str, object] = {
        "hdl": hdl,
        "HdlClient": HdlClient,
        "CallArg": CallArg,
    }
    if dbg is not None:
        locals_fn = getattr(dbg, "locals_dict", None)
        if callable(locals_fn):
            ns.update(locals_fn())
        else:
            ns["dbg"] = dbg
    if game is not None:
        ns["game"] = game
    import hdllib as _pkg

    ns["hdllib"] = _pkg
    console = code.InteractiveConsole(locals=ns)
    try:
        console.interact(banner=banner, exitmsg="")
    except SystemExit:
        pass
    out.write(f"(back in hdl:{hdl.pid} shell — type quit to exit)\n")
