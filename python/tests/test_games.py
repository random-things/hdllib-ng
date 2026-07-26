"""Offline tests for game target ABC + registry."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hdllib.client import HdlClient, ModuleInfo
from hdllib.games import GameTarget, get_game, list_games, register_game
from hdllib.games.base import LaunchHandle
from hdllib.process import ProcessInfo


def test_get_game_unknown():
    with pytest.raises(KeyError, match="unknown game"):
        get_game("not-a-game")


def test_launch_handle_close_only_if_spawned():
    proc = MagicMock()
    handle = LaunchHandle(pid=1, process=proc, spawned=False)
    handle.close()
    proc.terminate.assert_not_called()
    handle = LaunchHandle(pid=1, process=proc, spawned=True)
    handle.close()
    proc.terminate.assert_called_once()


def test_register_custom_game():
    class Toy(GameTarget):
        name = "toy"
        exe_names = ("toy.exe",)
        module_markers = ("toy",)

        def default_install_paths(self) -> list[Path]:
            return []

    toy = Toy()
    register_game(toy)
    try:
        assert get_game("toy") is toy
        assert "toy" in list_games()
    finally:
        from hdllib.games import _REGISTRY
        _REGISTRY.pop("toy", None)


def test_find_exe_env(tmp_path, monkeypatch):
    class Toy(GameTarget):
        name = "toy"
        exe_names = ("toy.exe",)
        exe_env = "TOY_EXE"

        def default_install_paths(self) -> list[Path]:
            return []

    toy = Toy()
    fake = tmp_path / "toy.exe"
    fake.write_bytes(b"MZ")
    monkeypatch.setenv("TOY_EXE", str(fake))
    assert toy.find_exe() == fake.resolve()


def test_find_processes_uses_exe_names():
    class Toy(GameTarget):
        name = "toy"
        exe_names = ("toy.exe",)

        def default_install_paths(self) -> list[Path]:
            return []

    toy = Toy()
    with patch("hdllib.games.base.find_processes") as fp:
        fp.return_value = [ProcessInfo(pid=7, name="toy.exe")]
        procs = toy.find_processes()
        fp.assert_called_with("toy.exe")
        assert procs[0].pid == 7


def test_verify_attached_ok():
    class Toy(GameTarget):
        name = "toy"
        exe_names = ("toy.exe",)
        module_markers = ("toy",)

        def default_install_paths(self) -> list[Path]:
            return []

    toy = Toy()
    hdl = MagicMock(spec=HdlClient)
    hdl.pid = 1
    hdl.ping.return_value = 1
    hdl.modules.return_value = [
        ModuleInfo(base=0x1000, size=0x100, path=r"C:\games\toy.exe"),
    ]
    hdl.module_base.return_value = 0x1000
    hdl.read.return_value = b"MZ"
    toy.verify_attached(hdl)


def test_verify_attached_missing_marker():
    class Toy(GameTarget):
        name = "toy"
        exe_names = ("toy.exe",)
        module_markers = ("toy",)

        def default_install_paths(self) -> list[Path]:
            return []

    toy = Toy()
    hdl = MagicMock(spec=HdlClient)
    hdl.pid = 1
    hdl.ping.return_value = 1
    hdl.modules.return_value = [
        ModuleInfo(base=0x1000, size=0x100, path=r"C:\other\game.exe"),
    ]
    with pytest.raises(AssertionError, match="module marker"):
        toy.verify_attached(hdl)
