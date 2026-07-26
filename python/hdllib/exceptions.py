"""Exceptions for the hdllib Python client."""

from __future__ import annotations

from .protocol import status_name


class HdlError(Exception):
    """Base error for the hdllib Python package."""


class HdlStatusError(HdlError):
    """IPC or inject call returned a non-OK HdlStatus."""

    def __init__(self, status: int, message: str | None = None) -> None:
        self.status = int(status)
        detail = message or status_name(self.status)
        super().__init__(f"{detail} ({self.status})")


class HdlPipeError(HdlError):
    """Named-pipe connect or framing failure."""
