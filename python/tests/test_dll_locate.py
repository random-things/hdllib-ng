"""Tests for packaged hdllib.dll discovery."""

from __future__ import annotations

from pathlib import Path

from hdllib._dll import _PACKAGED_DLL, candidate_dll_paths


def test_packaged_dll_is_early_candidate():
    paths = candidate_dll_paths()
    assert _PACKAGED_DLL in paths
    # After optional HDL_DLL override, packaged path should be first real default.
    non_env = [p for p in paths if p == _PACKAGED_DLL or "build" in str(p).lower()]
    assert non_env[0] == _PACKAGED_DLL


def test_packaged_path_under_native():
    assert _PACKAGED_DLL.name == "hdllib.dll"
    assert _PACKAGED_DLL.parent.name == "_native"
