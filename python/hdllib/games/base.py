"""Abstract game target — process discovery, attach, and smoke verification."""

from __future__ import annotations

import os
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from ..client import HdlClient
from ..inject import INJECT_CREATE_REMOTE_THREAD
from ..process import ProcessInfo, find_processes
from ..toolbox import DebugSession, open_debug_session


@dataclass
class LaunchHandle:
    """A game process started by :meth:`GameTarget.launch`."""

    pid: int
    process: subprocess.Popen | None = None
    spawned: bool = False

    def close(self, timeout: float = 10.0) -> None:
        if not self.spawned or self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()


class GameTarget(ABC):
    """Game-specific adapter over the core :class:`~hdllib.client.HdlClient`.

    Core IPC/inject lives on ``HdlClient``; subclasses supply exe names, install
    paths, and optional RE helpers without polluting the generic client.
    """

    #: Short registry id (e.g. ``"mygame"``).
    name: str
    #: Process image names matched case-insensitively.
    exe_names: tuple[str, ...]
    #: Env var for an explicit install path (subclass sets, e.g. ``MYGAME_EXE``).
    exe_env: str | None = None
    #: Substrings that should appear in module paths after a successful attach.
    module_markers: tuple[str, ...] = ()

    @abstractmethod
    def default_install_paths(self) -> list[Path]:
        """Candidate paths to ``*.exe`` on this machine (may not exist)."""

    def find_exe(self) -> Path | None:
        """Resolve install exe from env then :meth:`default_install_paths`."""
        if self.exe_env:
            env = os.environ.get(self.exe_env)
            if env:
                p = Path(env)
                if p.is_file():
                    return p.resolve()
        for p in self.default_install_paths():
            if p.is_file():
                return p.resolve()
        return None

    def find_processes(self) -> list[ProcessInfo]:
        found: list[ProcessInfo] = []
        seen: set[int] = set()
        for exe in self.exe_names:
            for proc in find_processes(exe):
                if proc.pid not in seen:
                    seen.add(proc.pid)
                    found.append(proc)
        return found

    def find_pid(self) -> int | None:
        procs = self.find_processes()
        return procs[0].pid if procs else None

    def launch(
        self,
        *,
        exe: Path | None = None,
        settle_s: float = 2.0,
        wait_s: float = 60.0,
    ) -> LaunchHandle:
        """Start the game and wait until its process appears."""
        path = exe or self.find_exe()
        if path is None:
            raise FileNotFoundError(
                f"{self.name}: no install found"
                + (f" (set {self.exe_env})" if self.exe_env else "")
            )
        proc = subprocess.Popen(
            [str(path)],
            cwd=str(path.parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + wait_s
        pid: int | None = None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(
                    f"{self.name}: process exited early with code {proc.returncode}"
                )
            found = self.find_processes()
            if found:
                pid = found[0].pid
                break
            time.sleep(0.5)
        if pid is None:
            proc.kill()
            raise TimeoutError(f"{self.name}: process did not appear within {wait_s}s")
        if settle_s > 0:
            time.sleep(settle_s)
        return LaunchHandle(pid=pid, process=proc, spawned=True)

    def resolve_pid(self, pid: int | None = None, *, launch_if_missing: bool = False) -> LaunchHandle:
        """Use ``pid``, an already-running instance, or optionally launch."""
        if pid is not None:
            return LaunchHandle(pid=int(pid), spawned=False)
        running = self.find_pid()
        if running is not None:
            return LaunchHandle(pid=running, spawned=False)
        if launch_if_missing:
            return self.launch()
        raise LookupError(
            f"{self.name}: not running"
            + (f" and no install (set {self.exe_env})" if self.exe_env else "")
        )

    def open(
        self,
        pid: int | None = None,
        *,
        inject: bool = True,
        dll: str | None = None,
        method: int = INJECT_CREATE_REMOTE_THREAD,
        timeout_ms: int = 10000,
        launch_if_missing: bool = False,
    ) -> tuple[DebugSession, LaunchHandle]:
        """Inject/connect and wrap a :class:`~hdllib.toolbox.DebugSession`."""
        handle = self.resolve_pid(pid, launch_if_missing=launch_if_missing)
        dbg = open_debug_session(
            handle.pid,
            inject=inject,
            method=method,
            dll=dll,
            timeout_ms=timeout_ms,
        )
        return dbg, handle

    def attach(
        self,
        pid: int | None = None,
        *,
        inject: bool = True,
        dll: str | None = None,
        method: int = INJECT_CREATE_REMOTE_THREAD,
        timeout_ms: int = 10000,
        launch_if_missing: bool = False,
    ) -> tuple[HdlClient, LaunchHandle]:
        """Connect (and optionally inject) to the game. Returns ``(client, handle)``.

        Prefer :meth:`open` when you want the RE toolbox (``mem`` / ``scan`` / …).
        """
        dbg, handle = self.open(
            pid,
            inject=inject,
            dll=dll,
            method=method,
            timeout_ms=timeout_ms,
            launch_if_missing=launch_if_missing,
        )
        return dbg.hdl, handle

    def verify_attached(self, hdl: HdlClient) -> None:
        """Smoke checks after inject/connect. Raises ``AssertionError`` on failure."""
        remote = hdl.ping()
        if remote != hdl.pid:
            raise AssertionError(f"ping pid mismatch: remote={remote} local={hdl.pid}")
        mods = hdl.modules()
        if not mods:
            raise AssertionError("no modules enumerated")
        if self.module_markers:
            blob = " ".join(m.path.lower() for m in mods)
            if not any(marker.lower() in blob for marker in self.module_markers):
                raise AssertionError(
                    f"expected module marker(s) {self.module_markers!r} in target"
                )
        base = hdl.module_base()
        if not base:
            raise AssertionError("module_base returned 0")
        mz = hdl.read(base, 2)
        if mz != b"MZ":
            raise AssertionError(f"main module MZ check failed: {mz!r}")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r})"
