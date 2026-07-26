"""Locate a built ``hdllib.dll`` and copy it into ``hdllib/_native/`` for packaging."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

PYTHON_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PYTHON_ROOT.parent
DEST = PYTHON_ROOT / "hdllib" / "_native" / "hdllib.dll"


def candidate_build_dlls() -> list[Path]:
    paths: list[Path] = []
    env = os.environ.get("HDL_DLL")
    if env:
        paths.append(Path(env))
    for rel in (
        Path("build/x64-windows-vs2026/Release/hdllib.dll"),
        Path("build/x64-windows-vs/Release/hdllib.dll"),
        Path("build/x64-windows/hdllib.dll"),
        Path("build/x64-windows/Release/hdllib.dll"),
        Path("build/Release/hdllib.dll"),
        Path("hdllib.dll"),
    ):
        paths.append(REPO_ROOT / rel)
    return paths


def stage_hdllib_dll(*, required: bool = True) -> Path | None:
    """Ensure ``hdllib/_native/hdllib.dll`` exists; copy from a CMake build if needed."""
    if DEST.is_file():
        return DEST.resolve()
    for src in candidate_build_dlls():
        if src.is_file():
            DEST.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, DEST)
            return DEST.resolve()
    if required:
        raise FileNotFoundError(
            "hdllib.dll not found for packaging. Build hdllib-ng (Release x64) first, "
            "or set HDL_DLL to the full path of hdllib.dll, then re-run pip install."
        )
    return None


def main(argv: list[str] | None = None) -> int:
    required = "--optional" not in (argv or sys.argv[1:])
    try:
        path = stage_hdllib_dll(required=required)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 1
    if path is None:
        print("hdllib.dll not staged (optional)", file=sys.stderr)
        return 0
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
