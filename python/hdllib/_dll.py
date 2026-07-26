"""Locate and load ``hdllib.dll`` for out-of-process inject APIs."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path

_dll: ctypes.CDLL | None = None

# Bundled beside the package (CMake POST_BUILD / pip install staging).
_PACKAGED_DLL = Path(__file__).resolve().parent / "_native" / "hdllib.dll"


def candidate_dll_paths() -> list[Path]:
    paths: list[Path] = []
    env = os.environ.get("HDL_DLL")
    if env:
        paths.append(Path(env))
    # Installed / staged package data — preferred for Scripts after pip install.
    paths.append(_PACKAGED_DLL)
    here = Path(__file__).resolve().parent
    # python/hdllib -> repo root (editable / in-tree without staging)
    root = here.parent.parent
    for rel in (
        Path("build/x64-windows-vs2026/Release/hdllib.dll"),
        Path("build/x64-windows-vs/Release/hdllib.dll"),
        Path("build/x64-windows/hdllib.dll"),
        Path("build/x64-windows/Release/hdllib.dll"),
        Path("build/Release/hdllib.dll"),
        Path("hdllib.dll"),
    ):
        paths.append(root / rel)
    paths.append(here.parent / "hdllib.dll")
    return paths


def find_hdllib_dll() -> Path:
    for p in candidate_dll_paths():
        if p.is_file():
            return p.resolve()
    raise FileNotFoundError(
        "hdllib.dll not found. Build hdllib-ng (cmake) so it stages into "
        "hdllib/_native/, run `pip install -e .` from python/, or set HDL_DLL."
    )


def load_hdllib() -> ctypes.CDLL:
    global _dll
    if _dll is not None:
        return _dll
    path = find_hdllib_dll()
    # Exported Hdl* APIs are cdecl (HDL_API without WINAPI).
    _dll = ctypes.CDLL(str(path))
    return _dll


def dll_path() -> str:
    return str(find_hdllib_dll())
