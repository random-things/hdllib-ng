"""Shared fixtures and path helpers for hdllib Python tests."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _candidate_bins(name: str) -> list[Path]:
    out: list[Path] = []
    if name == "hdllib.dll" and os.environ.get("HDL_DLL"):
        out.append(Path(os.environ["HDL_DLL"]))
    if name.startswith("hdl_test_target") and os.environ.get("HDL_TEST_TARGET"):
        out.append(Path(os.environ["HDL_TEST_TARGET"]))
    for rel in (
        Path(f"build/x64-windows-vs2026/Release/{name}"),
        Path(f"build/x64-windows-vs/Release/{name}"),
        Path(f"build/x64-windows/{name}"),
        Path(f"build/x64-windows/Release/{name}"),
        Path(f"build/Release/{name}"),
        Path(name),
    ):
        out.append(REPO_ROOT / rel)
    return out


def find_bin(name: str) -> Path | None:
    for p in _candidate_bins(name):
        if p.is_file():
            return p.resolve()
    return None


@pytest.fixture(scope="session")
def hdllib_dll() -> Path:
    path = find_bin("hdllib.dll")
    if path is None:
        pytest.skip("hdllib.dll not built; set HDL_DLL or build Release x64")
    return path


@pytest.fixture(scope="session")
def test_target_exe() -> Path:
    path = find_bin("hdl_test_target.exe")
    if path is None:
        pytest.skip("hdl_test_target.exe not built; set HDL_TEST_TARGET or build tests")
    return path


@pytest.fixture
def running_target(test_target_exe: Path):
    """Spawn hdl_test_target.exe and yield its PID; terminate on teardown."""
    proc = subprocess.Popen(
        [str(test_target_exe)],
        cwd=str(test_target_exe.parent),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Give threads a moment to start
    time.sleep(0.3)
    if proc.poll() is not None:
        pytest.fail(f"hdl_test_target exited early with code {proc.returncode}")
    try:
        yield proc.pid
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
