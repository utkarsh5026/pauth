"""
Compatibility layer that lets the library be imported as ``pauth.*``
while keeping the existing ``src.*`` imports working.
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.util
import sys

_ALIAS_ROOT = __name__
_TARGET_ROOT = "src"

_target_package = importlib.import_module(_TARGET_ROOT)

__all__ = getattr(_target_package, "__all__", ())
__doc__ = _target_package.__doc__
__path__ = list(getattr(_target_package, "__path__", []))


def __getattr__(name: str):
    return getattr(_target_package, name)


def __dir__():
    return sorted(set(dir(_target_package)))


def _target_name(fullname: str) -> str:
    if fullname == _ALIAS_ROOT:
        return _TARGET_ROOT
    suffix = fullname[len(_ALIAS_ROOT) + 1 :]
    return f"{_TARGET_ROOT}.{suffix}"


class _AliasLoader(importlib.abc.Loader):
    def __init__(self, fullname: str):
        self.fullname = fullname
        self.target_name = _target_name(fullname)

    def create_module(self, spec):  # type: ignore[override]
        return None

    def exec_module(self, module):  # type: ignore[override]
        target_module = sys.modules.get(self.target_name)
        if target_module is None:
            target_module = importlib.import_module(self.target_name)
        sys.modules[self.fullname] = target_module


class _AliasFinder(importlib.abc.MetaPathFinder):
    # type: ignore[override]
    def find_spec(self, fullname: str, path, target=None):
        if not (fullname == _ALIAS_ROOT or fullname.startswith(f"{_ALIAS_ROOT}.")):
            return None

        target_name = _target_name(fullname)
        target_spec = importlib.util.find_spec(target_name)
        if target_spec is None:
            return None

        return importlib.util.spec_from_loader(
            fullname,
            _AliasLoader(fullname),
            origin=target_spec.origin,
        )


if not any(isinstance(finder, _AliasFinder) for finder in sys.meta_path):
    sys.meta_path.insert(0, _AliasFinder())


for name, module in list(sys.modules.items()):
    if name.startswith(f"{_TARGET_ROOT}."):
        alias = name.replace(_TARGET_ROOT, _ALIAS_ROOT, 1)
        sys.modules.setdefault(alias, module)
