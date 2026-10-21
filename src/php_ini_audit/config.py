"""Effective configuration: the result of applying layered files in PHP's own order."""

from __future__ import annotations

import enum
from dataclasses import replace
from typing import Dict, Iterable, Iterator, List, Optional, Sequence

from . import directives
from .model import Directive, Setting


class OverlayKind(str, enum.Enum):
    SECTION = "php.ini [PATH=]/[HOST=] section"
    FPM_POOL = "php-fpm pool"
    USER_INI = ".user.ini"
    HTACCESS = ".htaccess"

    def __str__(self) -> str:
        return self.value


_PER_DIR_ONLY = (OverlayKind.USER_INI, OverlayKind.HTACCESS)
_LIST_DIRECTIVES = ("extension", "zend_extension")


class EffectiveConfig:
    def __init__(
        self,
        layers: Iterable[Directive],
        overlay: Sequence[Directive] = (),
        overlay_kind: Optional[OverlayKind] = None,
    ):
        self._current: Dict[str, Directive] = {}
        self.history: Dict[str, List[Directive]] = {}
        self.extensions: List[Directive] = []
        self.ineffective: List[Directive] = []
        self.overlay_kind = overlay_kind
        self._overlay: set = set()
        for directive in layers:
            self._apply(directive, None)
        for directive in overlay:
            applied = self._apply(directive, overlay_kind)
            if applied is not None:
                self._overlay.add(applied)

    def _apply(self, directive: Directive, kind: Optional[OverlayKind]) -> Optional[Directive]:
        if kind in _PER_DIR_ONLY and not directives.settable_per_dir(directive.name):
            self.ineffective.append(directive)
            return None
        if directive.name in _LIST_DIRECTIVES:
            self.extensions.append(directive)
            return directive
        previous = self._current.get(directive.name)
        if (
            kind is OverlayKind.FPM_POOL
            and directive.admin
            and directive.name in directives.FPM_APPENDING
            and previous is not None
            and previous.value
        ):
            directive = replace(directive, value=f"{previous.value},{directive.value}")
        self.history.setdefault(directive.name, []).append(directive)
        self._current[directive.name] = directive
        return directive

    def get(self, name: str) -> Setting:
        directive = self._current.get(name)
        if directive is None:
            return Setting(name, directives.default(name))
        return Setting(name, directive.value, directive, tuple(self.history[name][:-1]))

    def explicit(self) -> Iterator[Setting]:
        for name in sorted(self._current):
            yield self.get(name)

    def is_overlay(self, directive: Optional[Directive]) -> bool:
        return directive is not None and directive in self._overlay

    @property
    def overlay_directives(self) -> List[Directive]:
        return sorted(self._overlay, key=lambda d: (d.location.path, d.location.line or 0))
