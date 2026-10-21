"""Find exact PHP versions from files on disk (headers, package databases) without running PHP."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .fsutil import FileSystem, ReadError

Version = Tuple[int, ...]

HEADER_PATTERNS = (
    "/usr/local/include/php/main/php_version.h",
    "/usr/include/php/main/php_version.h",
    "/usr/include/php/*/main/php_version.h",
    "/usr/include/php*/main/php_version.h",
    "/opt/remi/php*/root/usr/include/php/main/php_version.h",
    "/opt/cpanel/ea-php*/root/usr/include/php/main/php_version.h",
    "/opt/plesk/php/*/include/php/main/php_version.h",
    "/opt/homebrew/opt/php*/include/php/main/php_version.h",
    "/usr/local/opt/php*/include/php/main/php_version.h",
)
DPKG_STATUS = "/var/lib/dpkg/status"
APK_INSTALLED = "/lib/apk/db/installed"
# Homebrew links the active keg under opt/; the Cellar may also hold outdated kegs.
HOMEBREW_LINKS = ("/opt/homebrew/opt/php*", "/usr/local/opt/php*")

_HEADER_VERSION = re.compile(r'^#define\s+PHP_VERSION\s+"(\d+)\.(\d+)\.(\d+)', re.MULTILINE)
_UPSTREAM = re.compile(r"^(?:\d+:)?(\d+)\.(\d+)\.(\d+)")
_DPKG_PACKAGE = re.compile(r"^(?:php(\d)\.(\d+)-(?:common|cli|fpm|cgi)|libapache2-mod-php(\d)\.(\d+))$")
_APK_PACKAGE = re.compile(r"^php(\d)(\d)(?:-common|-fpm|-cgi|-cli)?$")


@dataclass(frozen=True)
class VersionEvidence:
    version: Version
    source: str
    backports: bool = False

    @property
    def branch(self) -> Tuple[int, int]:
        return self.version[0], self.version[1]


def format_version(version: Optional[Sequence[int]]) -> str:
    return ".".join(map(str, version)) if version else "unknown"


def parse_version(text: str) -> Version:
    return tuple(int(part) for part in text.split("."))


class VersionFinder:
    def __init__(self, fs: FileSystem):
        self.fs = fs

    def _read(self, path: str) -> Optional[str]:
        try:
            return self.fs.read_text(path)
        except ReadError:
            return None

    def collect(self) -> List[VersionEvidence]:
        found: List[VersionEvidence] = []
        for pattern in HEADER_PATTERNS:
            for path in self.fs.glob(pattern):
                text = self._read(path)
                match = _HEADER_VERSION.search(text or "")
                if match:
                    found.append(VersionEvidence(tuple(map(int, match.groups())), path))
        found.extend(self._dpkg())
        found.extend(self._apk())
        for pattern in HOMEBREW_LINKS:
            for link in self.fs.glob(pattern):
                match = _UPSTREAM.match(posixpath.basename(self.fs.resolve(link)))
                if match:
                    found.append(VersionEvidence(tuple(map(int, match.groups())), link))
        return self._dedupe(found)

    @staticmethod
    def _dedupe(found: List[VersionEvidence]) -> List[VersionEvidence]:
        unique: Dict[Tuple[Version, str], VersionEvidence] = {}
        for evidence in found:
            unique.setdefault((evidence.version, evidence.source), evidence)
        return list(unique.values())

    def _stanzas(self, path: str):
        text = self._read(path)
        if not text:
            return
        for block in text.split("\n\n"):
            fields: Dict[str, str] = {}
            for line in block.splitlines():
                key, sep, value = line.partition(":")
                if sep and not line.startswith(" "):
                    fields[key.strip()] = value.strip()
            yield fields

    def _dpkg(self) -> List[VersionEvidence]:
        found = []
        for fields in self._stanzas(DPKG_STATUS):
            package = _DPKG_PACKAGE.match(fields.get("Package", ""))
            if not package or "installed" not in fields.get("Status", "").split():
                continue
            match = _UPSTREAM.match(fields.get("Version", ""))
            if match:
                version = fields["Version"]
                # deb.sury.org builds track upstream releases; distribution builds backport fixes.
                found.append(
                    VersionEvidence(tuple(map(int, match.groups())), f"{DPKG_STATUS} ({fields['Package']} {version})",
                                    backports="sury" not in version)
                )
        return found

    def _apk(self) -> List[VersionEvidence]:
        found = []
        for fields in self._stanzas(APK_INSTALLED):
            if not _APK_PACKAGE.match(fields.get("P", "")):
                continue
            match = _UPSTREAM.match(fields.get("V", ""))
            if match:
                found.append(VersionEvidence(tuple(map(int, match.groups())),
                                             f"{APK_INSTALLED} ({fields['P']} {fields['V']})"))
        return found


def pick(evidence: Sequence[VersionEvidence], branch: Optional[Tuple[int, int]],
         near: Optional[str] = None) -> Optional[VersionEvidence]:
    """Choose the evidence for one installation; ambiguous branches resolve only by shared path prefix."""
    candidates = [e for e in evidence if branch is None or e.branch == branch]
    if not candidates:
        return None
    distinct = {e.version for e in candidates}
    if len(distinct) == 1:
        exact = [e for e in candidates if not e.backports]
        return exact[0] if exact else candidates[0]
    if near:
        def shared(e: VersionEvidence) -> int:
            path = e.source.split(" ", 1)[0]
            return len(posixpath.commonprefix([path, near]))

        best = max(candidates, key=shared)
        if shared(best) > len("/opt/"):
            return best
    return None
