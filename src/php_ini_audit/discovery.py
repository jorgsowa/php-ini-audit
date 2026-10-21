"""Locate PHP configuration files on a system or below user-supplied paths."""

from __future__ import annotations

import os
import posixpath
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .fsutil import FileSystem
from .versions import VersionFinder, pick

# Locations of php.ini across distributions, packagers and bundles.
POSIX_INI_PATTERNS = (
    "/etc/php.ini",
    "/etc/php/php.ini",
    "/etc/php/*/*/php.ini",
    "/etc/php*/php.ini",
    "/etc/php*/*/php.ini",
    "/etc/opt/remi/php*/php.ini",
    "/usr/local/etc/php.ini",
    "/usr/local/etc/php/php.ini",
    "/usr/local/etc/php/*/php.ini",
    "/usr/local/lib/php.ini",
    "/usr/local/php*/lib/php.ini",
    "/usr/local/zend/etc/php.ini",
    "/opt/homebrew/etc/php/*/php.ini",
    "/opt/cpanel/ea-php*/root/etc/php.ini",
    "/opt/plesk/php/*/etc/php.ini",
    "/opt/alt/php*/etc/php.ini",
    "/opt/lampp/etc/php.ini",
    "/opt/bitnami/php/etc/php.ini",
    "/Applications/XAMPP/xamppfiles/etc/php.ini",
    "/Applications/MAMP/bin/php/php*/conf/php.ini",
)
WINDOWS_INI_PATTERNS = (
    "C:/php/php.ini",
    "C:/php*/php.ini",
    "C:/tools/php*/php.ini",
    "C:/xampp/php/php.ini",
    "C:/wamp64/bin/php/php*/php.ini",
    "C:/wamp/bin/php/php*/php.ini",
    "C:/laragon/bin/php/*/php.ini",
    "C:/Program Files/PHP/*/php.ini",
)
SCAN_DIR_NAMES = ("conf.d", "php.d")
POOL_DIR_NAMES = ("pool.d", "php-fpm.d")
TEMPLATE_NAMES = ("php.ini-production", "php.ini-development")
# Packagers that keep extension ini files outside the php.ini directory.
SCAN_DIR_OVERRIDES = {
    "/etc/php.ini": ("/etc/php.d",),
    "/usr/local/etc/php.ini": ("/usr/local/etc/php",),
}
_SAPI_DIRS = {
    "cli": "cli",
    "phpdbg": "cli",
    "fpm": "fpm",
    "php-fpm": "fpm",
    "apache2": "apache2",
    "apache": "apache2",
    "cgi": "cgi",
    "litespeed": "litespeed",
    "lsapi": "litespeed",
    "embed": "embed",
}
_VERSION = re.compile(r"(?:^|/)(?:ea-)?php[-_/]?(\d)(?:\.?(\d{1,2}))?(?=[/.\-_]|$)")


@dataclass
class Installation:
    label: str
    ini: Optional[str]
    scan_files: List[str] = field(default_factory=list)
    scan_dirs: List[str] = field(default_factory=list)
    fpm_files: List[str] = field(default_factory=list)
    sapi: str = "unknown"
    php_version: Optional[Tuple[int, ...]] = None
    version_source: Optional[str] = None
    version_backports: bool = False
    defaults_reason: Optional[str] = None


@dataclass
class Discovery:
    installations: List[Installation] = field(default_factory=list)
    user_inis: List[str] = field(default_factory=list)
    htaccess: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def resolve_versions(self, fs: FileSystem) -> None:
        """Upgrade path-derived MAJOR.MINOR to an exact version where the system records one."""
        evidence = VersionFinder(fs).collect()
        for installation in self.installations:
            branch = installation.php_version[:2] if installation.php_version else None
            chosen = pick(evidence, branch, installation.ini or (installation.scan_dirs or [None])[0])
            if chosen is not None:
                installation.php_version = chosen.version
                installation.version_source = chosen.source
                installation.version_backports = chosen.backports


def detect_sapi(path: str) -> str:
    for part in reversed(path.replace("\\", "/").split("/")):
        if part.lower() in _SAPI_DIRS:
            return _SAPI_DIRS[part.lower()]
    return "unknown"


def detect_version(path: str) -> Optional[Tuple[int, int]]:
    match = _VERSION.search(path.replace("\\", "/"))
    if not match:
        return None
    major = int(match.group(1))
    if major < 4:
        return None
    if match.group(2):
        return major, int(match.group(2))
    return None


class Discoverer:
    def __init__(self, fs: FileSystem):
        self.fs = fs

    def scan_files_in(self, directory: str) -> List[str]:
        """PHP reads *.ini from a scan dir in alphabetical order."""
        return [
            posixpath.join(directory, name)
            for name in self.fs.listdir(directory)
            if name.endswith(".ini") and self.fs.is_file(posixpath.join(directory, name))
        ]

    def _join(self, *parts: str) -> str:
        return posixpath.join(*parts) if parts[0].startswith("/") else os.path.join(*parts)

    def _dirname(self, path: str) -> str:
        return posixpath.dirname(path) if path.startswith("/") else os.path.dirname(path)

    def build(self, ini: Optional[str], directory: str, scan_dirs: Optional[List[str]] = None) -> Installation:
        if scan_dirs is None:
            scan_dirs = list(SCAN_DIR_OVERRIDES.get(ini or "", ()))
            scan_dirs += [self._join(directory, name) for name in SCAN_DIR_NAMES]
            scan_dirs = [d for d in dict.fromkeys(scan_dirs) if self.fs.is_dir(d)]
        scan_files: List[str] = []
        for scan_dir in scan_dirs:
            scan_files.extend(f for f in self.scan_files_in(scan_dir) if f != ini)
        reference = ini or directory
        sapi = detect_sapi(reference)
        fpm_files: List[str] = []
        if sapi in ("fpm", "unknown"):
            parent = self._dirname(directory)
            for base in (directory, parent):
                conf = self._join(base, "php-fpm.conf")
                if self.fs.is_file(conf) and conf not in fpm_files:
                    fpm_files.append(conf)
                for name in POOL_DIR_NAMES:
                    pool_dir = self._join(base, name)
                    if self.fs.is_dir(pool_dir):
                        for entry in self.fs.listdir(pool_dir):
                            candidate = self._join(pool_dir, entry)
                            if entry.endswith(".conf") and self.fs.is_file(candidate) and candidate not in fpm_files:
                                fpm_files.append(candidate)
        return Installation(
            label=ini or f"{directory} (no php.ini)",
            ini=ini,
            scan_files=scan_files,
            scan_dirs=scan_dirs,
            fpm_files=fpm_files,
            sapi=sapi,
            php_version=detect_version(reference),
        )

    def system(self) -> Discovery:
        result = Discovery()
        patterns = list(POSIX_INI_PATTERNS)
        if os.name == "nt" and self.fs.root is None:
            patterns = list(WINDOWS_INI_PATTERNS)
        seen: Set[str] = set()
        candidate_dirs: List[str] = []
        for pattern in patterns:
            for directory in self.fs.glob(self._dirname(pattern)):
                if directory not in candidate_dirs and self.fs.is_dir(directory):
                    candidate_dirs.append(directory)
        for directory in candidate_dirs:
            ini = self._join(directory, "php.ini")
            if self.fs.is_file(ini):
                key = self.fs.resolve(ini)
                if key in seen:
                    continue
                seen.add(key)
                result.installations.append(self.build(ini, directory))
                continue
            templates = [t for t in TEMPLATE_NAMES if self.fs.is_file(self._join(directory, t))]
            has_scan_dir = any(self.fs.is_dir(self._join(directory, n)) for n in SCAN_DIR_NAMES)
            if templates or (has_scan_dir and "php" in directory.lower()):
                key = self.fs.resolve(directory)
                if key in seen:
                    continue
                seen.add(key)
                installation = self.build(None, directory)
                reason = f"no php.ini in {directory}"
                if templates:
                    reason += f" ({', '.join(templates)} present but not loaded)"
                installation.defaults_reason = reason
                result.installations.append(installation)
        return result

    def paths(self, paths: List[str], max_depth: int = 12) -> Discovery:
        result = Discovery()
        loose_ini: Dict[str, List[str]] = {}
        loose_fpm: List[str] = []
        consumed: Set[str] = set()

        def classify(path: str) -> None:
            name = os.path.basename(path)
            if name == ".user.ini":
                result.user_inis.append(path)
            elif name == ".htaccess":
                result.htaccess.append(path)
            elif name == "php.ini" or name.endswith("php.ini"):
                installation = self.build(path, self._dirname(path))
                result.installations.append(installation)
                consumed.update(installation.scan_files)
                consumed.update(installation.fpm_files)
            elif name.endswith(".ini"):
                loose_ini.setdefault(self._dirname(path), []).append(path)
            elif name.endswith(".conf") and _looks_like_fpm(path):
                loose_fpm.append(path)

        for path in paths:
            if self.fs.is_dir(path):
                for found in self.fs.walk(path, max_depth=max_depth):
                    name = os.path.basename(found)
                    if name in (".user.ini", ".htaccess") or name.endswith(".ini"):
                        classify(found)
                    elif name.endswith(".conf") and _looks_like_fpm(found):
                        classify(found)
            elif self.fs.is_file(path):
                classify(path)
                if path.endswith(".conf") and path not in loose_fpm:
                    loose_fpm.append(path)
            else:
                result.warnings.append(f"{path}: not found or not readable")

        for directory, files in sorted(loose_ini.items()):
            remaining = [f for f in files if f not in consumed]
            if remaining:
                result.installations.append(
                    Installation(
                        label=f"{directory}/*.ini",
                        ini=None,
                        scan_files=sorted(remaining),
                        scan_dirs=[directory],
                        sapi=detect_sapi(directory),
                        php_version=detect_version(directory),
                    )
                )
        pools = [f for f in loose_fpm if f not in consumed]
        if pools:
            result.installations.append(
                Installation(label="php-fpm configuration", ini=None, fpm_files=pools, sapi="fpm",
                             php_version=detect_version(pools[0]))
            )
        return result


def _looks_like_fpm(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")
    return (
        parts[-1] in ("php-fpm.conf", "www.conf")
        or any(p in POOL_DIR_NAMES for p in parts[:-1])
        or "fpm" in path.lower()
    )
