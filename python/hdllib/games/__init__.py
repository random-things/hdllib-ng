"""Game-specific adapters over the core :class:`~hdllib.client.HdlClient`.

Core IPC/inject stays in ``hdllib.client``; this package holds the abstract
:class:`GameTarget` ABC and a registry. Concrete games ship as separate
packages and register via ``register_game`` or the ``hdllib.games`` entry-point
group.
"""

from __future__ import annotations

from .base import GameTarget, LaunchHandle

_REGISTRY: dict[str, GameTarget] = {}
_ENTRY_POINTS_LOADED = False


def register_game(game: GameTarget) -> None:
    """Register or replace a game adapter by ``game.name``."""
    _REGISTRY[game.name.lower()] = game


def get_game(name: str) -> GameTarget:
    _ensure_entry_points()
    key = name.strip().lower()
    try:
        return _REGISTRY[key]
    except KeyError as exc:
        known = ", ".join(sorted(_REGISTRY)) or "(none)"
        raise KeyError(f"unknown game {name!r}; known: {known}") from exc


def list_games() -> list[str]:
    _ensure_entry_points()
    return sorted(_REGISTRY)


def _ensure_entry_points() -> None:
    global _ENTRY_POINTS_LOADED
    if _ENTRY_POINTS_LOADED:
        return
    _ENTRY_POINTS_LOADED = True
    try:
        from importlib.metadata import entry_points
    except ImportError:
        return
    eps = entry_points()
    if hasattr(eps, "select"):
        group = eps.select(group="hdllib.games")
    else:
        group = eps.get("hdllib.games", [])  # type: ignore[attr-defined]
    for ep in group:
        try:
            game = ep.load()
            if isinstance(game, GameTarget):
                register_game(game)
        except Exception:
            continue


__all__ = [
    "GameTarget",
    "LaunchHandle",
    "get_game",
    "list_games",
    "register_game",
]
