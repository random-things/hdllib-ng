#!/usr/bin/env python3
"""Find process → inject hdllib → ping → list modules.

Examples:
  python inject_flow.py --exe hdl_test_target.exe
  python inject_flow.py --exe game.exe
  python inject_flow.py --pid 1234 --method auto
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running without install: python/ on sys.path
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from hdllib import (  # noqa: E402
    INJECT_AUTO,
    INJECT_CREATE_REMOTE_THREAD,
    Session,
    find_processes,
)
from hdllib.inject import METHOD_NAMES  # noqa: E402


def _parse_method(text: str) -> int:
    key = text.strip().lower().replace("-", "_")
    if key in ("auto",):
        return INJECT_AUTO
    if key.isdigit() or (key.startswith("-") and key[1:].isdigit()):
        return int(key)
    for method, name in METHOD_NAMES.items():
        if name == key:
            return method
    raise argparse.ArgumentTypeError(f"unknown inject method: {text}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exe", help="Process executable name (e.g. game.exe)")
    ap.add_argument("--pid", type=int, help="Target PID (overrides --exe)")
    ap.add_argument(
        "--method",
        type=_parse_method,
        default=INJECT_CREATE_REMOTE_THREAD,
        help="Inject method name or id (default: create_remote_thread; use auto)",
    )
    ap.add_argument("--dll", help="Path to hdllib.dll (default: auto-locate / HDL_DLL)")
    ap.add_argument("--no-inject", action="store_true", help="Only connect (already injected)")
    ap.add_argument("--timeout", type=int, default=10000, help="Pipe connect timeout ms")
    args = ap.parse_args()

    if args.pid:
        pid = args.pid
    elif args.exe:
        procs = find_processes(args.exe)
        if not procs:
            print(f"no process named {args.exe!r}", file=sys.stderr)
            return 1
        pid = procs[0].pid
        if len(procs) > 1:
            print(f"warning: {len(procs)} matches; using pid={pid}")
    else:
        ap.error("provide --pid or --exe")

    method_name = METHOD_NAMES.get(args.method, str(args.method))
    print(f"target pid={pid} method={method_name}")

    with Session(pid) as session:
        if not args.no_inject:
            base = session.inject(dll=args.dll, method=args.method, timeout_ms=args.timeout)
            print(f"injected base=0x{base:016x}")
        else:
            session.connect(timeout_ms=args.timeout)

        remote = session.ping()
        print(f"ping ok remote_pid={remote}")

        mods = session.modules()
        print(f"modules ({len(mods)}):")
        for m in mods[:32]:
            print(f"  0x{m.base:016x}  {m.size:8x}  {m.path}")
        if len(mods) > 32:
            print(f"  … {len(mods) - 32} more")

        print("attached — ready for read/scan/call/hook via Session")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
