"""Read-only filesystem access, optionally confined to an alternative root (container image, chroot, mount)."""

from __future__ import annotations

import glob as _glob
import os
import posixpath
import stat
from collections import deque
from typing import Iterator, List, Optional

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_SYMLINKS = 40
SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules"})


class ReadError(Exception):
    pass


class FileSystem:
    """Paths handed in and out are *display* paths: absolute paths as seen inside the audited system."""

    def __init__(self, root: Optional[str] = None):
        self.root = os.path.abspath(root) if root else None
        self.confined = self.root is not None or os.name != "nt"

    def to_host(self, path: str) -> str:
        if self.root is None:
            return path
        return os.path.join(self.root, path.lstrip("/\\"))

    def to_display(self, host_path: str) -> str:
        if self.root is None:
            return host_path
        rel = os.path.relpath(host_path, self.root)
        if rel == ".":
            return "/"
        if rel.startswith(".."):
            raise ValueError(f"{host_path} is outside the root {self.root}")
        return "/" + rel.replace(os.sep, "/")

    def resolve(self, path: str) -> str:
        """Resolve symlinks without ever leaving the root; absolute link targets are re-anchored at the root."""
        if not self.confined:
            return os.path.realpath(path)
        pending = deque(p for p in path.split("/") if p)
        resolved: List[str] = []
        hops = 0
        while pending:
            part = pending.popleft()
            if part == ".":
                continue
            if part == "..":
                if resolved:
                    resolved.pop()
                continue
            candidate = "/" + "/".join(resolved + [part])
            try:
                info = os.lstat(self.to_host(candidate))
            except OSError:
                resolved.append(part)
                resolved.extend(p for p in pending if p not in ("", "."))
                return posixpath.normpath("/" + "/".join(resolved))
            if stat.S_ISLNK(info.st_mode):
                hops += 1
                if hops > MAX_SYMLINKS:
                    raise ReadError(f"too many symbolic links resolving {path}")
                target = os.readlink(self.to_host(candidate))
                if target.startswith("/"):
                    resolved = []
                pending.extendleft(reversed([p for p in target.split("/") if p]))
                continue
            resolved.append(part)
        return "/" + "/".join(resolved)

    def stat(self, path: str) -> Optional[os.stat_result]:
        try:
            return os.stat(self.to_host(self.resolve(path)), follow_symlinks=False)
        except (OSError, ReadError):
            return None

    def lstat(self, path: str) -> Optional[os.stat_result]:
        try:
            return os.lstat(self.to_host(path))
        except OSError:
            return None

    def is_file(self, path: str) -> bool:
        info = self.stat(path)
        return bool(info and stat.S_ISREG(info.st_mode))

    def is_dir(self, path: str) -> bool:
        info = self.stat(path)
        return bool(info and stat.S_ISDIR(info.st_mode))

    def listdir(self, path: str) -> List[str]:
        try:
            return sorted(os.listdir(self.to_host(self.resolve(path))))
        except (OSError, ReadError):
            return []

    def glob(self, pattern: str) -> List[str]:
        if self.root is None:
            matches = _glob.glob(pattern)
        else:
            matches = _glob.glob(os.path.join(_glob.escape(self.root), pattern.lstrip("/")))
        return sorted({self.to_display(m) for m in matches})

    def read_text(self, path: str) -> str:
        try:
            host = self.to_host(self.resolve(path))
            flags = (
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOCTTY", 0)
                | getattr(os, "O_BINARY", 0)
            )
            fd = os.open(host, flags)
        except OSError as exc:
            raise ReadError(f"cannot open {path}: {exc.strerror or exc}") from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ReadError(f"{path} is not a regular file")
            if info.st_size > MAX_FILE_BYTES:
                raise ReadError(f"{path} is larger than {MAX_FILE_BYTES} bytes")
            chunks = []
            remaining = MAX_FILE_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.close(fd)
        data = b"".join(chunks)
        if len(data) > MAX_FILE_BYTES:
            raise ReadError(f"{path} is larger than {MAX_FILE_BYTES} bytes")
        if b"\x00" in data:
            raise ReadError(f"{path} contains binary data")
        return data.decode("utf-8", errors="replace").lstrip("﻿")

    def walk(self, top: str, max_depth: int = 12, max_files: int = 100_000) -> Iterator[str]:
        """Yield files below top without following directory symlinks."""
        host_top = self.to_host(self.resolve(top))
        base_depth = host_top.rstrip(os.sep).count(os.sep)
        seen = 0
        for dirpath, dirnames, filenames in os.walk(host_top, followlinks=False):
            depth = dirpath.rstrip(os.sep).count(os.sep) - base_depth
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS) if depth < max_depth else []
            for name in sorted(filenames):
                seen += 1
                if seen > max_files:
                    return
                yield self.to_display(os.path.join(dirpath, name))
