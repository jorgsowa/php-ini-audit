"""Metadata-only inspection of paths referenced by configuration values."""

from __future__ import annotations

import os
import posixpath
import re
import stat
from dataclasses import dataclass
from typing import Optional, Sequence

from .fsutil import FileSystem
from .model import Confidence

_WEBROOT_HINT = re.compile(r"/(public_html|htdocs|httpdocs|wwwroot|www|html|public|web|webroot)(/|$)", re.IGNORECASE)
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass(frozen=True)
class PathFacts:
    path: str
    exists: bool
    is_dir: bool = False
    world_writable: bool = False
    world_readable: bool = False
    group_writable: bool = False
    sticky: bool = False
    writable_ancestor: Optional[str] = None
    writable_ancestor_sticky: bool = False


def is_absolute(path: str) -> bool:
    return path.startswith("/") or bool(_WINDOWS_ABSOLUTE.match(path))


class PathInspector:
    def __init__(self, fs: FileSystem, webroots: Sequence[str] = ()):
        self.fs = fs
        self.webroots = [posixpath.normpath(w) for w in webroots]
        self.posix_modes = os.name != "nt"

    def facts(self, path: str) -> Optional[PathFacts]:
        if not path.startswith("/") or not self.posix_modes:
            return None
        normalized = posixpath.normpath(path)
        info = self.fs.stat(normalized)
        if info is None:
            ancestor = self._nearest_existing_parent(normalized)
            return PathFacts(
                path=normalized,
                exists=False,
                writable_ancestor=ancestor[0] if ancestor and ancestor[1] else None,
                writable_ancestor_sticky=bool(ancestor and ancestor[2]),
            )
        mode = info.st_mode
        is_dir = stat.S_ISDIR(mode)
        parent = None
        parent_sticky = False
        if not is_dir:
            parent_info = self.fs.stat(posixpath.dirname(normalized))
            if parent_info and parent_info.st_mode & stat.S_IWOTH:
                parent = posixpath.dirname(normalized)
                parent_sticky = bool(parent_info.st_mode & stat.S_ISVTX)
        return PathFacts(
            path=normalized,
            exists=True,
            is_dir=is_dir,
            world_writable=bool(mode & stat.S_IWOTH),
            world_readable=bool(mode & stat.S_IROTH),
            group_writable=bool(mode & stat.S_IWGRP),
            sticky=bool(mode & stat.S_ISVTX),
            writable_ancestor=parent,
            writable_ancestor_sticky=parent_sticky,
        )

    def _nearest_existing_parent(self, path: str):
        current = posixpath.dirname(path)
        while True:
            info = self.fs.stat(current)
            if info is not None:
                if not stat.S_ISDIR(info.st_mode):
                    return None
                return current, bool(info.st_mode & stat.S_IWOTH), bool(info.st_mode & stat.S_ISVTX)
            if current == "/":
                return None
            current = posixpath.dirname(current)

    def webroot_match(self, path: str) -> Optional[Confidence]:
        if not is_absolute(path):
            return None
        normalized = posixpath.normpath(path.replace("\\", "/"))
        for root in self.webroots:
            if normalized == root or normalized.startswith(root.rstrip("/") + "/"):
                return Confidence.HIGH
        if self.webroots:
            return None
        return Confidence.LOW if _WEBROOT_HINT.search(normalized) else None
