"""Build hook: stage ``hdllib.dll`` into the package before packaging/install."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure in-tree helper is importable during PEP 517 builds.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py

from _stage_dll import stage_hdllib_dll

_cmdclass: dict = {}


class build_py(_build_py):
    def run(self) -> None:
        stage_hdllib_dll(required=True)
        super().run()


_cmdclass["build_py"] = build_py

try:
    from setuptools.command.editable_wheel import editable_wheel as _editable_wheel

    class editable_wheel(_editable_wheel):
        def run(self) -> None:
            stage_hdllib_dll(required=True)
            super().run()

    _cmdclass["editable_wheel"] = editable_wheel
except ImportError:
    pass

try:
    from setuptools.command.develop import develop as _develop

    class develop(_develop):
        def run(self) -> None:
            stage_hdllib_dll(required=True)
            super().run()

    _cmdclass["develop"] = develop
except ImportError:
    pass

setup(cmdclass=_cmdclass)
