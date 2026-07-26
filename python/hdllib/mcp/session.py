"""Process-global MCP session: attach state, write gate, strategy holders."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from ..client import HdlClient
from ..exceptions import HdlError
from ..games import GameTarget, get_game
from ..inject import INJECT_CREATE_REMOTE_THREAD
from ..process import find_processes
from ..strategies import (
    AccessFinder,
    AobInjector,
    CodePatcher,
    PointerHelper,
    ValueScan,
)
from ..toolbox import DebugSession, DiscoverSession, open_debug_session
from .serialize import from_exception, ok


class McpSessionError(HdlError):
    """MCP session precondition failure (not attached / write denied)."""


@dataclass
class StartupConfig:
    pid: int | None = None
    exe: str | None = None
    title: str | None = None
    game: str | None = None
    inject: bool = False
    dll: str | None = None
    method: int = INJECT_CREATE_REMOTE_THREAD
    timeout_ms: int = 10000
    allow_write: bool = False
    preattach: bool = False


@dataclass
class McpSession:
    """Owns the attached :class:`DebugSession` and multi-step strategy state."""

    allow_write: bool = False
    timeout_ms: int = 10000
    dll: str | None = None
    method: int = INJECT_CREATE_REMOTE_THREAD
    dbg: DebugSession | None = None
    value_scans: dict[str, ValueScan] = field(default_factory=dict)
    discover: DiscoverSession | None = None
    access_finder: AccessFinder | None = None
    code_patcher: CodePatcher | None = None
    pointer_helper: PointerHelper | None = None
    aob_injector: AobInjector | None = None
    _startup: StartupConfig | None = None

    def configure(self, cfg: StartupConfig) -> None:
        self._startup = cfg
        self.allow_write = cfg.allow_write
        self.timeout_ms = cfg.timeout_ms
        self.dll = cfg.dll
        self.method = cfg.method

    @property
    def attached(self) -> bool:
        return self.dbg is not None and self.dbg.connected

    @property
    def hdl(self) -> HdlClient:
        return self.require_attached().hdl

    def require_attached(self) -> DebugSession:
        if self.dbg is None or not self.dbg.connected:
            raise McpSessionError(
                "Not attached to a target. Call attach first "
                "(or start hdl-mcp with --preattach)."
            )
        return self.dbg

    def require_write(self) -> None:
        if not self.allow_write:
            raise McpSessionError(
                "Write/mutate operations are disabled. "
                "Restart hdl-mcp with --allow-write."
            )

    def resolve_pid(
        self,
        *,
        pid: int | None = None,
        exe: str | None = None,
        title: str | None = None,
        game: str | None = None,
    ) -> int:
        if pid:
            return int(pid)
        game_obj: GameTarget | None = None
        if game:
            game_obj = get_game(game)
            found = game_obj.find_pid()
            if found is None:
                raise McpSessionError(
                    f"game {game!r} not running"
                    + (f" (install via {game_obj.exe_env})" if game_obj.exe_env else "")
                )
            return found
        if exe:
            procs = find_processes(exe)
            if not procs:
                raise McpSessionError(f"no process named {exe!r}")
            return procs[0].pid
        if title:
            from ..inject import resolve_target

            resolved, _hwnd = resolve_target(window_title=title)
            return resolved
        env_pid = os.environ.get("HDL_PID")
        if env_pid:
            return int(env_pid, 0)
        cfg = self._startup
        if cfg is not None:
            if cfg.pid:
                return int(cfg.pid)
            if cfg.game:
                return self.resolve_pid(game=cfg.game)
            if cfg.exe:
                return self.resolve_pid(exe=cfg.exe)
            if cfg.title:
                return self.resolve_pid(title=cfg.title)
        raise McpSessionError(
            "provide pid, exe, title, game, or HDL_PID / startup --pid"
        )

    def attach(
        self,
        *,
        pid: int | None = None,
        exe: str | None = None,
        title: str | None = None,
        game: str | None = None,
        inject: bool = False,
        dll: str | None = None,
        method: int | None = None,
        timeout_ms: int | None = None,
    ) -> dict[str, Any]:
        if inject:
            self.require_write()
        target_pid = self.resolve_pid(pid=pid, exe=exe, title=title, game=game)
        self.detach()
        dbg = open_debug_session(
            target_pid,
            inject=inject,
            method=self.method if method is None else method,
            dll=dll if dll is not None else self.dll,
            timeout_ms=self.timeout_ms if timeout_ms is None else timeout_ms,
        )
        self.dbg = dbg
        self._reset_helpers()
        remote = dbg.hdl.ping()
        return {
            "pid": dbg.pid,
            "remote_pid": remote,
            "injected": inject,
            "allow_write": self.allow_write,
        }

    def detach(self) -> None:
        if self.discover is not None:
            try:
                self.discover.close()
            except Exception:
                pass
            self.discover = None
        for vs in list(self.value_scans.values()):
            try:
                vs.close()
            except Exception:
                pass
        self.value_scans.clear()
        if self.access_finder is not None:
            try:
                self.access_finder.stop()
            except Exception:
                pass
            self.access_finder = None
        self.code_patcher = None
        self.pointer_helper = None
        self.aob_injector = None
        if self.dbg is not None:
            try:
                self.dbg.close()
            except Exception:
                pass
            self.dbg = None

    def _reset_helpers(self) -> None:
        assert self.dbg is not None
        self.value_scans.clear()
        self.discover = None
        self.access_finder = AccessFinder(self.dbg)
        self.code_patcher = CodePatcher(self.dbg)
        self.pointer_helper = PointerHelper(self.dbg)
        self.aob_injector = AobInjector(self.dbg)

    def ensure_value_scan(self, scan_id: str, value_type: int) -> ValueScan:
        dbg = self.require_attached()
        vs = self.value_scans.get(scan_id)
        if vs is None:
            vs = ValueScan(dbg, value_type)
            self.value_scans[scan_id] = vs
        return vs

    def ensure_discover(self) -> DiscoverSession:
        dbg = self.require_attached()
        if self.discover is None:
            self.discover = DiscoverSession(dbg.hdl)
        return self.discover

    def preattach_from_startup(self) -> None:
        cfg = self._startup
        if cfg is None or not cfg.preattach:
            return
        inject = cfg.inject
        if inject and not cfg.allow_write:
            raise McpSessionError("--inject with --preattach requires --allow-write")
        self.attach(
            pid=cfg.pid,
            exe=cfg.exe,
            title=cfg.title,
            game=cfg.game,
            inject=inject,
            dll=cfg.dll,
            method=cfg.method,
            timeout_ms=cfg.timeout_ms,
        )


# Process-wide singleton used by tool modules.
_SESSION = McpSession()


def get_session() -> McpSession:
    return _SESSION


def reset_session_for_tests() -> McpSession:
    """Close any attach and return a fresh singleton (tests only)."""
    global _SESSION
    _SESSION.detach()
    _SESSION = McpSession()
    return _SESSION


def tool_result(fn):
    """Decorator: run tool body and always return a JSON result string."""
    import functools
    import inspect

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            result = fn(*args, **kwargs)
            if isinstance(result, str):
                return result
            return ok(result)
        except Exception as exc:
            return from_exception(exc)

    wrapper.__signature__ = inspect.signature(fn)
    return wrapper
