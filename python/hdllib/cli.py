"""CLI entry: shell (hdlclient-like) and Python REPL with ``hdl`` bound."""

from __future__ import annotations

import argparse
import sys

from .client import HdlClient
from .exceptions import HdlPipeError
from .games import GameTarget, get_game, list_games
from .inject import (
    INJECT_AUTO,
    INJECT_CREATE_REMOTE_THREAD,
    METHOD_NAMES,
    inject_dll,
)
from .process import find_processes
from .shell import COMMANDS, dispatch, run_python_repl, run_shell
from .toolbox import DebugSession


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


def _resolve_pid(
    pid: int | None,
    exe: str | None,
    title: str | None,
    game: GameTarget | None = None,
) -> int:
    if pid:
        return pid
    if game is not None:
        found = game.find_pid()
        if found is None:
            raise SystemExit(
                f"game {game.name!r} not running"
                + (f" (install via {game.exe_env})" if game.exe_env else "")
            )
        return found
    if exe:
        procs = find_processes(exe)
        if not procs:
            raise SystemExit(f"no process named {exe!r}")
        if len(procs) > 1:
            print(
                f"warning: {len(procs)} matches for {exe!r}; using pid={procs[0].pid}",
                file=sys.stderr,
            )
        return procs[0].pid
    if title:
        from .inject import resolve_target

        resolved, _hwnd = resolve_target(window_title=title)
        return resolved
    raise SystemExit(
        "provide --pid, --exe, --title, or --game "
        f"(games: {', '.join(list_games()) or 'none'})"
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hdl",
        description="hdllib Python client — shell (hdlclient commands) or Python REPL",
        epilog=(
            "Examples:\n"
            "  hdl 1234                     # command shell\n"
            "  hdl 1234 --python            # Python REPL with hdl=\n"
            "  hdl --game mygame --inject  # after installing a game adapter\n"
            "  hdl --exe game.exe ping\n"
            "  hdl inject 1234              # local inject only\n"
            "In the shell, type `py` for a programmatic REPL (hdl.ping(), …).\n"
            "With --game, the Python REPL also binds `game` to the adapter."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--pid", type=int, help="Target process id")
    p.add_argument("--exe", help="Find process by executable name (e.g. game.exe)")
    p.add_argument("--title", help="Resolve via window title substring")
    p.add_argument(
        "--game",
        metavar="NAME",
        help=f"Game adapter ({', '.join(list_games()) or 'none registered'})",
    )
    p.add_argument(
        "--inject",
        action="store_true",
        help="Inject hdllib.dll before connecting",
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
        "--python",
        "-p",
        action="store_true",
        help="Start in Python REPL with hdl=HdlClient (default is command shell)",
    )
    p.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="One-shot shell command (e.g. ping). Empty => interactive.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "inject":
        return local_inject_main(["inject", *argv[1:]])
    # hdlclient-style: hdl <pid> [cmd…]
    if argv and argv[0].isdigit() and not argv[0].startswith("-"):
        argv = ["--pid", argv[0], *argv[1:]]

    args = build_parser().parse_args(argv)

    cmd_tokens = list(args.command)
    if cmd_tokens and cmd_tokens[0] == "--":
        cmd_tokens = cmd_tokens[1:]

    game: GameTarget | None = None
    if args.game:
        try:
            game = get_game(args.game)
        except KeyError as exc:
            print(exc, file=sys.stderr)
            return 2

    try:
        pid = _resolve_pid(args.pid, args.exe, args.title, game=game)
    except SystemExit as e:
        msg = e.args[0] if e.args else None
        if msg:
            print(msg, file=sys.stderr)
        code = e.code
        if code in (0, None):
            return 0
        return int(code) if isinstance(code, int) else 2

    hdl = HdlClient(pid)
    dbg: DebugSession | None = None
    try:
        if args.inject:
            base = hdl.inject(dll=args.dll, method=args.method, timeout_ms=args.timeout)
            print(f"injected base=0x{base:016x}", file=sys.stderr)
        else:
            try:
                hdl.connect(timeout_ms=args.timeout)
            except HdlPipeError as exc:
                print(
                    f"{exc}\n"
                    f"hint: inject first — hdl --pid {pid} --inject   "
                    f"or: hdl inject {pid}",
                    file=sys.stderr,
                )
                return 1

        dbg = DebugSession(hdl)

        if cmd_tokens:
            if cmd_tokens[0].lower() not in COMMANDS and cmd_tokens[0].startswith("-"):
                print(f"unexpected args: {cmd_tokens}", file=sys.stderr)
                return 2
            dispatch(hdl, " ".join(cmd_tokens), sys.stdout)
            return 0

        if args.python:
            run_python_repl(hdl, game=game, dbg=dbg)
            run_shell(hdl, game=game, dbg=dbg)
        else:
            run_shell(hdl, game=game, dbg=dbg)
        return 0
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
    finally:
        if dbg is not None:
            dbg.close()
        else:
            hdl.close()


def local_inject_main(argv: list[str] | None = None) -> int:
    """``hdl inject <pid> [dll]`` — out-of-process inject, optional shell."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] != "inject":
        return main(argv)

    p = argparse.ArgumentParser(prog="hdl inject")
    p.add_argument("pid", type=int)
    p.add_argument("dll", nargs="?", help="DLL path (default: locate hdllib.dll)")
    p.add_argument("--method", type=_parse_method, default=INJECT_CREATE_REMOTE_THREAD)
    p.add_argument("--shell", action="store_true", help="Enter command shell after inject")
    p.add_argument("--python", action="store_true", help="Enter Python REPL after inject")
    ns = p.parse_args(argv[1:])
    result = inject_dll(ns.pid, dll=ns.dll, method=ns.method)
    print(f"status=HDL_OK base=0x{result.base:016x} pid={result.pid}")
    if ns.shell or ns.python:
        follow = ["--pid", str(result.pid)]
        if ns.python:
            follow.append("--python")
        return main(follow)
    return 0 if result.status == 0 else int(result.status)
