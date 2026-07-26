"""MCP stdio server for hdllib (optional extra: ``pip install 'hdllib[mcp]'``)."""

from __future__ import annotations

__all__ = ["create_server", "require_mcp"]


def require_mcp() -> None:
    """Import-check for the optional ``mcp`` dependency."""
    try:
        import mcp  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised when extra missing
        raise ImportError(
            "The MCP server requires the optional dependency. "
            "Install with: pip install 'hdllib[mcp]'"
        ) from exc


def create_server(**kwargs):
    """Build the FastMCP app. Lazy-imports so core ``hdllib`` stays light."""
    require_mcp()
    from .server import create_server as _create

    return _create(**kwargs)
