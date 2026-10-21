"""Rule registry and the contexts rules are evaluated against."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, Iterable, Optional, Sequence, Tuple, Union

from ..model import Confidence, Directive, Location, Setting, Severity, SourceKind

CRITICAL = Severity.CRITICAL
HIGH = Severity.HIGH
MEDIUM = Severity.MEDIUM
LOW = Severity.LOW
INFO = Severity.INFO

CATEGORIES = {
    "EXEC": "Code execution",
    "FS": "Filesystem and paths",
    "ERR": "Information disclosure",
    "SESS": "Session security",
    "RES": "Resource limits and DoS",
    "CGI": "CGI / FastCGI",
    "EXT": "Debug and profiling extensions",
    "OPC": "OPcache",
    "DB": "Database and credentials",
    "ENC": "Character encoding",
    "CFG": "Configuration hygiene",
    "FPM": "PHP-FPM pools",
    "HTA": "Apache .htaccess",
    "VULN": "PHP version support",
    "CVE": "Known vulnerabilities",
}

WEB_SAPIS: FrozenSet[str] = frozenset({"fpm", "cgi", "apache2", "litespeed", "unknown"})
FASTCGI_SAPIS: FrozenSet[str] = frozenset({"fpm", "cgi", "litespeed", "unknown"})

Evidence = Union[Setting, Directive]


@dataclass
class Hit:
    message: str
    evidence: Tuple[Evidence, ...] = ()
    severity: Optional[Severity] = None
    confidence: Confidence = Confidence.HIGH
    location: Optional[Location] = None


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    check: Callable[..., Iterable[Hit]]
    directives: Tuple[str, ...] = ()
    scope: str = "config"
    sapis: Optional[FrozenSet[str]] = None
    production_only: bool = False
    dev_severity: Optional[Severity] = None
    cwe: Optional[str] = None
    references: Tuple[str, ...] = ()

    @property
    def category(self) -> str:
        return self.id.split("-", 1)[0]

    @property
    def category_name(self) -> str:
        return CATEGORIES.get(self.category, self.category)


REGISTRY: Dict[str, Rule] = {}


def rule(rule_id: str, title: str, **attributes):
    def register(check):
        if rule_id in REGISTRY:
            raise ValueError(f"duplicate rule id {rule_id}")
        directive_names = attributes.pop("directives", ())
        REGISTRY[rule_id] = Rule(
            id=rule_id,
            title=title,
            check=check,
            directives=tuple(directive_names),
            references=tuple(attributes.pop("references", ())),
            **attributes,
        )
        return check

    return register


def security_directives() -> FrozenSet[str]:
    return frozenset(name for r in REGISTRY.values() for name in r.directives)


@dataclass
class Context:
    """What a config-scope or pool-scope rule sees."""

    config: object
    sapi: str
    profile: str
    php_version: Optional[Tuple[int, ...]]
    version_source: Optional[str] = None
    version_backports: bool = False
    platform: str = "posix"
    paths: object = None
    pool: object = None
    pools: Sequence[object] = ()
    defaults_reason: Optional[str] = None
    overlay_kind: object = None
    extra: dict = field(default_factory=dict)

    def get(self, name: str) -> Setting:
        return self.config.get(name)

    def on(self, name: str) -> bool:
        return self.get(name).as_bool()

    @property
    def production(self) -> bool:
        return self.profile == "production"

    @property
    def is_web(self) -> bool:
        return self.sapi in WEB_SAPIS

    def version_below(self, major: int, minor: int = 0) -> Optional[bool]:
        if self.php_version is None:
            return None
        return self.php_version < (major, minor)


@dataclass
class FileContext:
    """What a file-scope rule sees: one parsed file, independent of how it is layered."""

    file: object
    profile: str
    php_version: Optional[Tuple[int, ...]]
    paths: object = None

    @property
    def path(self) -> str:
        return self.file.path

    @property
    def kind(self) -> SourceKind:
        return self.file.kind


def overlay_set(setting: Setting) -> bool:
    return setting.directive is not None and setting.directive.kind in (SourceKind.USER_INI, SourceKind.HTACCESS)


def names(items: Sequence[str]) -> str:
    return ", ".join(items)


