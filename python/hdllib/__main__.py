"""``python -m hdllib`` entry point."""

from __future__ import annotations

import sys

from .cli import local_inject_main, main


def _entry() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "inject":
        return local_inject_main()
    return main()


if __name__ == "__main__":
    raise SystemExit(_entry())
