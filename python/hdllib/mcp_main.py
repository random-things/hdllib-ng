"""``hdl-mcp`` entry: argparse + stdio FastMCP server."""

from __future__ import annotations

import argparse
import os
import sys

from .inject import (
    INJECT_AUTO,
    INJECT_CREATE_REMOTE_THREAD,
    METHOD_NAMES,
)
from .mcp.session import StartupConfig, get_session


def _parse_method(text: str) -> int:
    key = text.strip().lower().replace("-", "_")
    if key in ("auto",):
        return INJECT_AUTO
    if key.lstrip("-").isdigit():
        return int(key)
    for method, name in METHOD_NAMES.items():
        if name == key:
            return method
    raise argparse.ArgumentTypeError(f"unknown inject method: {text}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hdl-mcp",
        description=(
            "hdllib MCP server (stdio). Optional attach at startup; "
            "destructive ops require --allow-write."
        ),
    )
    p.add_argument("--pid", type=int, help="Target process id")
    p.add_argument("--exe", help="Find process by executable name")
    p.add_argument("--title", help="Resolve via window title substring")
    p.add_argument("--game", metavar="NAME", help="Game adapter registry name")
    p.add_argument(
        "--inject",
        action="store_true",
        help="Inject hdllib.dll when attaching (requires --allow-write)",
    )
    p.add_argument("--dll", help="Path to hdllib.dll (default: auto / HDL_DLL)")
    p.add_argument(
        "--method",
        type=_parse_method,
        default=INJECT_CREATE_REMOTE_THREAD,
        help="Inject method (default: create_remote_thread; or auto)",
    )
    p.add_argument("--timeout", type=int, default=10000, help="Pipe connect timeout ms")
    p.add_argument(
        "--allow-write",
        action="store_true",
        help="Enable write/inject/call/patch/hook/watch-install tools",
    )
    p.add_argument(
        "--preattach",
        action="store_true",
        help="Attach (and optionally inject) before accepting MCP requests",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)

    # Prefer explicit --pid; fall back to HDL_PID for Cursor env configs.
    pid = args.pid
    if pid is None and os.environ.get("HDL_PID"):
        try:
            pid = int(os.environ["HDL_PID"], 0)
        except ValueError:
            print(f"invalid HDL_PID={os.environ['HDL_PID']!r}", file=sys.stderr)
            return 2

    cfg = StartupConfig(
        pid=pid,
        exe=args.exe,
        title=args.title,
        game=args.game,
        inject=args.inject,
        dll=args.dll,
        method=args.method,
        timeout_ms=args.timeout,
        allow_write=args.allow_write,
        preattach=args.preattach,
    )
    session = get_session()
    session.configure(cfg)

    try:
        from .mcp import create_server
        from .mcp.session import McpSessionError

        if cfg.preattach:
            try:
                session.preattach_from_startup()
                print(
                    f"hdl-mcp: preattached pid={session.dbg.pid if session.dbg else '?'}",
                    file=sys.stderr,
                )
            except McpSessionError as exc:
                print(f"hdl-mcp: preattach failed: {exc}", file=sys.stderr)
                return 1
            except Exception as exc:
                print(f"hdl-mcp: preattach failed: {exc}", file=sys.stderr)
                return 1

        mcp = create_server()
        # stdout is the MCP transport; keep logs on stderr.
        print("hdl-mcp: starting stdio server", file=sys.stderr)
        mcp.run(transport="stdio")
        return 0
    except ImportError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
    finally:
        session.detach()


if __name__ == "__main__":
    raise SystemExit(main())
