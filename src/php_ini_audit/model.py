"""Core data types shared by the parser, the rules and the reporters."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Optional, Tuple

from . import values


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, text: str) -> "Severity":
        try:
            return cls[text.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {text!r}") from None

    def __str__(self) -> str:
        return self.name.lower()


class Confidence(enum.IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2

    def __str__(self) -> str:
        return self.name.lower()


class SourceKind(str, enum.Enum):
    PHP_INI = "php.ini"
    SCAN_DIR = "scan-dir ini"
    FPM = "php-fpm config"
    USER_INI = ".user.ini"
    HTACCESS = ".htaccess"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Location:
    path: str
    line: Optional[int] = None

    def __str__(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path


@dataclass(frozen=True)
class Directive:
    """One assignment as written in a configuration file."""

    name: str
    value: str
    raw: str
    location: Location
    kind: SourceKind
    section: Optional[str] = None
    admin: bool = False
    unresolved: bool = False


@dataclass(frozen=True)
class Setting:
    """Effective value of a directive: the last assignment, or PHP's built-in default."""

    name: str
    value: Optional[str]
    directive: Optional[Directive] = None
    overridden: Tuple[Directive, ...] = ()

    @property
    def is_set(self) -> bool:
        return self.directive is not None

    @property
    def location(self) -> Optional[Location]:
        return self.directive.location if self.directive else None

    @property
    def unresolved(self) -> bool:
        return bool(self.directive and self.directive.unresolved)

    def as_bool(self) -> bool:
        return values.to_bool(self.value)

    def as_int(self) -> int:
        return values.atoi(self.value)

    def as_bytes(self) -> Optional[int]:
        return values.to_bytes(self.value)

    def as_list(self) -> list:
        return values.split_list(self.value)

    @property
    def text(self) -> str:
        return (self.value or "").strip()

    def describe(self) -> str:
        shown = self.value if self.value not in (None, "") else "(empty)"
        return f"{self.name} = {shown}"


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    message: str
    recommendation: str
    target: str
    directive: Optional[str] = None
    value: Optional[str] = None
    location: Optional[Location] = None
    from_default: bool = False
    cwe: Optional[str] = None
    references: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "severity": str(self.severity),
            "confidence": str(self.confidence),
            "message": self.message,
            "recommendation": self.recommendation,
            "target": self.target,
            "directive": self.directive,
            "value": self.value,
            "file": self.location.path if self.location else None,
            "line": self.location.line if self.location else None,
            "from_default": self.from_default,
            "cwe": self.cwe,
            "references": list(self.references),
        }
