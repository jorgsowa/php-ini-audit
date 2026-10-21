"""Turn discovered files into audit targets and evaluate every rule against them."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from .config import EffectiveConfig, OverlayKind
from .discovery import Discovery, Installation
from .fsutil import FileSystem, ReadError
from .model import Confidence, Directive, Finding, Location, Setting, Severity, SourceKind
from .parser import FpmPool, IniFile, is_conditional, parse_fpm, parse_htaccess, parse_ini
from .paths import PathInspector
from .rules import REGISTRY, Context, FileContext, Rule

PROFILES = ("production", "development")
_WINDOWS_PATH = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass
class Options:
    profile: str = "production"
    sapi: Optional[str] = None
    php_version: Optional[Tuple[int, ...]] = None
    path_checks: bool = True
    webroots: Sequence[str] = ()
    min_severity: Severity = Severity.INFO
    only: Sequence[str] = ()
    skip: Sequence[str] = ()


@dataclass
class Target:
    label: str
    sapi: str
    php_version: Optional[Tuple[int, ...]]
    files: List[str]
    config: EffectiveConfig
    version_source: Optional[str] = None
    version_backports: bool = False
    platform: str = "posix"
    layers: List[Directive] = field(default_factory=list)
    overlay: Optional[str] = None
    pool: Optional[FpmPool] = None
    pools: List[FpmPool] = field(default_factory=list)
    defaults_reason: Optional[str] = None
    synthetic: bool = False
    # Directive names a phpinfo() dump lists; the rest do not exist in that PHP build.
    observed: Optional[FrozenSet[str]] = None

    @property
    def name(self) -> str:
        return f"{self.label} + {self.overlay}" if self.overlay else self.label

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "base": self.label,
            "overlay": self.overlay,
            "sapi": self.sapi,
            "php_version": ".".join(map(str, self.php_version)) if self.php_version else None,
            "php_version_source": self.version_source,
            "files": self.files,
            "defaults_only": self.defaults_reason is not None,
        }


@dataclass
class AuditResult:
    targets: List[Target]
    findings: List[Finding]
    files: List[str]
    warnings: List[str]
    rules_evaluated: int
    path_checks: bool


def selected_rules(options: Options) -> List[Rule]:
    def matches(rule: Rule, selectors: Sequence[str]) -> bool:
        return any(rule.id == s.upper() or rule.category == s.upper() for s in selectors)

    rules = sorted(REGISTRY.values(), key=lambda r: r.id)
    if options.only:
        rules = [r for r in rules if matches(r, options.only)]
    return [r for r in rules if not matches(r, options.skip)]


class Auditor:
    def __init__(self, fs: FileSystem, options: Options):
        self.fs = fs
        self.options = options
        self.paths = PathInspector(fs, options.webroots) if options.path_checks else None
        self.parsed: Dict[str, object] = {}
        self.file_versions: Dict[str, Optional[Tuple[int, ...]]] = {}
        self.warnings: List[str] = []

    def _load(self, path: str, parser, *args):
        if path in self.parsed:
            return self.parsed[path]
        try:
            text = self.fs.read_text(path)
        except ReadError as exc:
            self.warnings.append(str(exc))
            self.parsed[path] = None
            return None
        parsed = parser(text, path, *args)
        self.parsed[path] = parsed
        return parsed

    def _remember_version(self, path: str, version: Optional[Tuple[int, ...]]) -> None:
        if self.file_versions.get(path) is None:
            self.file_versions[path] = version

    def build_targets(self, discovery: Discovery) -> List[Target]:
        self.warnings.extend(discovery.warnings)
        targets: List[Target] = []
        for installation in discovery.installations:
            targets.extend(self._installation_targets(installation))
        overlays = (
            (discovery.user_inis, OverlayKind.USER_INI, ("fpm", "cgi", "litespeed", "unknown")),
            (discovery.htaccess, OverlayKind.HTACCESS, ("apache2", "unknown")),
        )
        for paths, kind, sapis in overlays:
            for path in paths:
                if kind is OverlayKind.USER_INI:
                    parsed = self._load(path, parse_ini, SourceKind.USER_INI)
                else:
                    parsed = self._load(path, parse_htaccess)
                if parsed is None:
                    continue
                hosts = [t for t in targets if t.overlay is None and t.sapi in sapis]
                if not hosts:
                    defaults = Target(
                        label="PHP built-in defaults",
                        sapi=self.options.sapi or "unknown",
                        php_version=self.options.php_version,
                        files=[],
                        config=EffectiveConfig(()),
                        synthetic=True,
                    )
                    targets.append(defaults)
                    hosts = [defaults]
                for host in hosts:
                    targets.append(self._overlay(host, parsed.php_directives, kind, path, source=path))
        return targets

    def _installation_targets(self, installation: Installation) -> List[Target]:
        if self.options.php_version:
            version, source, backports = self.options.php_version, "--php-version", False
        else:
            version = installation.php_version
            source = installation.version_source or ("path" if version else None)
            backports = installation.version_backports
        layers: List[Directive] = []
        files: List[str] = []
        ini_files: List[IniFile] = []
        sources = ([(installation.ini, SourceKind.PHP_INI)] if installation.ini else []) + [
            (f, SourceKind.SCAN_DIR) for f in installation.scan_files
        ]
        for path, kind in sources:
            parsed = self._load(path, parse_ini, kind)
            if parsed is None:
                continue
            self._remember_version(path, version)
            ini_files.append(parsed)
            files.append(path)
            layers.extend(parsed.base_directives)
        pools: List[FpmPool] = []
        for path in installation.fpm_files:
            parsed = self._load(path, parse_fpm)
            if parsed is not None:
                self._remember_version(path, version)
                pools.extend(parsed.pools)
        base = Target(
            label=installation.label,
            sapi=self.options.sapi or installation.sapi,
            php_version=version,
            files=files,
            config=EffectiveConfig(layers),
            version_source=source,
            version_backports=backports,
            platform=self._platform([installation.ini or ""] + installation.scan_files + installation.fpm_files, layers),
            layers=layers,
            pools=pools,
            defaults_reason=installation.defaults_reason,
        )
        targets = [base]
        for ini in ini_files:
            sections: Dict[str, List[Directive]] = {}
            for directive in ini.directives:
                if is_conditional(directive.section):
                    sections.setdefault(directive.section, []).append(directive)
            for section, conditional in sections.items():
                targets.append(self._overlay(base, conditional, OverlayKind.SECTION, f"[{section}]"))
        for pool in pools:
            label = f"pool [{pool.name}] ({pool.location.path})"
            pool_target = self._overlay(base, pool.php, OverlayKind.FPM_POOL, label, source=pool.location.path)
            pool_target.sapi = self.options.sapi or "fpm"
            pool_target.pool = pool
            targets.append(pool_target)
        return targets

    def _platform(self, paths: Sequence[str], layers: Sequence[Directive]) -> str:
        if any(_WINDOWS_PATH.match(p) for p in paths):
            return "windows"
        for directive in layers:
            if directive.name in ("extension", "zend_extension", "extension_dir") and (
                _WINDOWS_PATH.match(directive.value) or directive.value.lower().endswith(".dll")
            ):
                return "windows"
        if self.fs.root is None and os.name == "nt":
            return "windows"
        return "posix"

    def _overlay(
        self, base: Target, overlay: Sequence[Directive], kind: OverlayKind, label: str, source: Optional[str] = None
    ) -> Target:
        sources = {d.location.path for d in overlay} | ({source} if source else set())
        return Target(
            label=base.label,
            sapi=base.sapi,
            php_version=base.php_version,
            files=base.files + sorted(sources - set(base.files)),
            config=EffectiveConfig(base.layers, overlay, kind),
            version_source=base.version_source,
            version_backports=base.version_backports,
            platform=base.platform,
            layers=base.layers,
            overlay=label if kind is OverlayKind.FPM_POOL else f"{kind}: {label}",
            pools=base.pools,
        )

    def run(self, discovery: Discovery) -> AuditResult:
        return self.evaluate(self.build_targets(discovery))

    def evaluate(self, targets: List[Target]) -> AuditResult:
        rules = selected_rules(self.options)
        findings: List[Finding] = []
        for target in targets:
            if target.synthetic:
                continue
            context = Context(
                config=target.config,
                sapi=target.sapi,
                profile=self.options.profile,
                php_version=target.php_version,
                version_source=target.version_source,
                version_backports=target.version_backports,
                platform=target.platform,
                paths=self.paths,
                pool=target.pool,
                pools=target.pools,
                defaults_reason=target.defaults_reason,
                overlay_kind=target.config.overlay_kind,
            )
            for rule in rules:
                if not self._applies(rule, target):
                    continue
                for hit in rule.check(context):
                    if target.overlay and rule.scope == "config" and not self._touches_overlay(hit, target):
                        continue
                    if target.observed is not None and not self._observed(hit, target.observed):
                        continue
                    findings.append(self._finding(rule, hit, target.name))
        for path, parsed in sorted(self.parsed.items()):
            if parsed is None:
                continue
            context = FileContext(parsed, self.options.profile, self.file_versions.get(path, self.options.php_version),
                                  self.paths)
            for rule in rules:
                if rule.scope != "file" or (rule.production_only and self.options.profile != "production"):
                    continue
                for hit in rule.check(context):
                    findings.append(self._finding(rule, hit, self._owner(path, targets)))
        findings = [f for f in findings if f.severity >= self.options.min_severity]
        findings.sort(key=lambda f: (-f.severity, -f.confidence, f.rule_id, f.target, str(f.location or "")))
        return AuditResult(
            targets=[t for t in targets if not t.synthetic],
            findings=findings,
            files=sorted(p for p, v in self.parsed.items() if v is not None),
            warnings=self.warnings,
            rules_evaluated=len(rules),
            path_checks=self.paths is not None,
        )

    @staticmethod
    def _owner(path: str, targets: Sequence[Target]) -> str:
        """Attribute file-level findings to the narrowest configuration that reads the file."""
        owners = [t for t in targets if path in t.files and not t.synthetic]
        if not owners:
            return path
        return min(owners, key=lambda t: len(t.files)).name

    def _applies(self, rule: Rule, target: Target) -> bool:
        if rule.scope == "file":
            return False
        if rule.scope == "pool" and target.pool is None:
            return False
        if rule.production_only and self.options.profile != "production":
            return False
        return rule.sapis is None or target.sapi in rule.sapis

    @staticmethod
    def _touches_overlay(hit, target: Target) -> bool:
        for item in hit.evidence:
            directive = item.directive if isinstance(item, Setting) else item
            if target.config.is_overlay(directive) or directive in target.config.ineffective:
                return True
        return False

    @staticmethod
    def _observed(hit, observed: FrozenSet[str]) -> bool:
        settings = [e for e in hit.evidence if isinstance(e, Setting)]
        return len(settings) < len(hit.evidence) or not settings or any(s.name in observed for s in settings)

    def _finding(self, rule: Rule, hit, target_name: str) -> Finding:
        severity = hit.severity if hit.severity is not None else rule.severity
        if self.options.profile == "development" and rule.dev_severity is not None:
            severity = min(severity, rule.dev_severity)
        confidence = hit.confidence
        primary = hit.evidence[0] if hit.evidence else None
        directive_name = value = None
        location: Optional[Location] = hit.location
        from_default = False
        if isinstance(primary, Setting):
            directive_name, value = primary.name, primary.value
            location = location or primary.location
            from_default = not primary.is_set
            if any(isinstance(e, Setting) and e.unresolved for e in hit.evidence):
                confidence = Confidence.LOW
        elif isinstance(primary, Directive):
            directive_name, value = primary.name, primary.value
            location = location or primary.location
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            category=rule.category_name,
            severity=severity,
            confidence=confidence,
            message=hit.message,
            recommendation=rule.recommendation,
            target=target_name,
            directive=directive_name,
            value=value,
            location=location,
            from_default=from_default,
            cwe=rule.cwe,
            references=rule.references,
        )
