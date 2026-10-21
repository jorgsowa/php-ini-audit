"""Parsers for php.ini-style files, php-fpm configs and .htaccess PHP directives.

Parsing is purely textual: nothing is expanded, included or executed.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .model import Directive, Location, SourceKind

_BOOL_WORDS = {
    "on": "1",
    "yes": "1",
    "true": "1",
    "off": "",
    "no": "",
    "false": "",
    "none": "",
    "null": "",
}
_CONDITIONAL_SECTION = re.compile(r"^(PATH|HOST)\s*=", re.IGNORECASE)
_FPM_PHP_KEY = re.compile(r"^(php_value|php_flag|php_admin_value|php_admin_flag)\[(.+)\]$")
_FPM_ENV_KEY = re.compile(r"^env\[(.+)\]$")
_MAX_CONTINUATION_LINES = 100


@dataclass(frozen=True)
class ParseIssue:
    location: Location
    message: str


@dataclass
class IniFile:
    path: str
    kind: SourceKind
    directives: List[Directive] = field(default_factory=list)
    issues: List[ParseIssue] = field(default_factory=list)
    conditional_sections: List[Tuple[str, Location]] = field(default_factory=list)

    @property
    def php_directives(self) -> List[Directive]:
        return self.directives

    @property
    def base_directives(self) -> List[Directive]:
        return [d for d in self.directives if not is_conditional(d.section)]


@dataclass
class FpmPool:
    name: str
    location: Location
    settings: Dict[str, Directive] = field(default_factory=dict)
    php: List[Directive] = field(default_factory=list)
    env: List[Directive] = field(default_factory=list)


@dataclass
class FpmFile:
    path: str
    kind: SourceKind = SourceKind.FPM
    pools: List[FpmPool] = field(default_factory=list)
    global_settings: Dict[str, Directive] = field(default_factory=dict)
    issues: List[ParseIssue] = field(default_factory=list)

    @property
    def php_directives(self) -> List[Directive]:
        return [d for pool in self.pools for d in pool.php]


@dataclass(frozen=True)
class HandlerMapping:
    location: Location
    statement: str
    extensions: Tuple[str, ...]
    files_pattern: Optional[str]


@dataclass
class HtaccessFile:
    path: str
    kind: SourceKind = SourceKind.HTACCESS
    directives: List[Directive] = field(default_factory=list)
    issues: List[ParseIssue] = field(default_factory=list)
    handlers: List[HandlerMapping] = field(default_factory=list)

    @property
    def php_directives(self) -> List[Directive]:
        return self.directives


def is_conditional(section: Optional[str]) -> bool:
    return bool(section and _CONDITIONAL_SECTION.match(section))


def scan_value(text: str) -> Tuple[str, bool, bool]:
    """Return (value, has_env_reference, unterminated_quote) for the right-hand side of '='."""
    parts: List[Tuple[str, str]] = []
    unresolved = False
    i, n = 0, len(text)
    while i < n:
        char = text[i]
        if char == ";":
            break
        if char == '"':
            j, buf = i + 1, []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n and text[j + 1] in '"\\$':
                    buf.append(text[j + 1])
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            if j >= n:
                return "", unresolved, True
            chunk = "".join(buf)
            unresolved = unresolved or "${" in chunk
            parts.append(("quoted", chunk))
            i = j + 1
            continue
        if char == "'":
            j = text.find("'", i + 1)
            if j == -1:
                return "", unresolved, True
            parts.append(("quoted", text[i + 1 : j]))
            i = j + 1
            continue
        j = i
        while j < n and text[j] not in ";\"'":
            j += 1
        chunk = text[i:j]
        unresolved = unresolved or "${" in chunk
        parts.append(("bare", chunk))
        i = j

    has_quotes = any(kind == "quoted" for kind, _ in parts)
    pieces = [chunk.strip() if kind == "bare" and has_quotes else chunk for kind, chunk in parts]
    value = "".join(pieces).strip() if not has_quotes else "".join(pieces)
    if len(parts) == 1 and parts[0][0] == "bare":
        value = _BOOL_WORDS.get(value.lower(), value)
    return value, unresolved, False


def parse_ini(text: str, path: str, kind: SourceKind) -> IniFile:
    result = IniFile(path=path, kind=kind)
    lines = text.splitlines()
    section: Optional[str] = None
    index = 0
    while index < len(lines):
        lineno = index + 1
        stripped = lines[index].strip()
        index += 1
        location = Location(path, lineno)
        if not stripped or stripped.startswith(";"):
            continue
        if stripped.startswith("#"):
            result.issues.append(
                ParseIssue(location, "'#' is not a comment since PHP 7.0; use ';' (the line may abort INI parsing)")
            )
            continue
        if stripped.startswith("["):
            end = stripped.find("]")
            if end == -1:
                result.issues.append(ParseIssue(location, "unterminated section header"))
                continue
            section = stripped[1:end].strip()
            if is_conditional(section):
                result.conditional_sections.append((section, location))
            continue
        if "=" not in stripped:
            result.issues.append(ParseIssue(location, f"line without '=' is a syntax error: {stripped[:60]!r}"))
            continue
        key, _, rest = stripped.partition("=")
        key = key.strip()
        if not key:
            result.issues.append(ParseIssue(location, "assignment without a directive name"))
            continue
        value, unresolved, unterminated = scan_value(rest)
        extra = 0
        while unterminated and index < len(lines) and extra < _MAX_CONTINUATION_LINES:
            rest += "\n" + lines[index]
            index += 1
            extra += 1
            value, unresolved, unterminated = scan_value(rest)
        if unterminated:
            result.issues.append(ParseIssue(location, f"unterminated quoted value for {key}"))
            continue
        result.directives.append(
            Directive(
                name=key,
                value=value,
                raw=rest.strip(),
                location=location,
                kind=kind,
                section=section,
                unresolved=unresolved,
            )
        )
    return result


def parse_fpm(text: str, path: str) -> FpmFile:
    """php-fpm.conf / pool.d files share the INI grammar; sections name the pools."""
    ini = parse_ini(text, path, SourceKind.FPM)
    result = FpmFile(path=path, issues=list(ini.issues))
    pools: Dict[str, FpmPool] = {}
    for directive in ini.directives:
        section = directive.section or "global"
        if section.lower() == "global":
            result.global_settings[directive.name] = directive
            continue
        pool = pools.get(section)
        if pool is None:
            pool = FpmPool(name=section, location=Location(path, directive.location.line))
            pools[section] = pool
            result.pools.append(pool)
        php_match = _FPM_PHP_KEY.match(directive.name)
        env_match = _FPM_ENV_KEY.match(directive.name)
        if php_match:
            pool.php.append(
                Directive(
                    name=php_match.group(2).strip(),
                    value=directive.value,
                    raw=directive.raw,
                    location=directive.location,
                    kind=SourceKind.FPM,
                    section=section,
                    admin=php_match.group(1).startswith("php_admin"),
                    unresolved=directive.unresolved,
                )
            )
        elif env_match:
            pool.env.append(
                Directive(
                    name=env_match.group(1).strip(),
                    value=directive.value,
                    raw=directive.raw,
                    location=directive.location,
                    kind=SourceKind.FPM,
                    section=section,
                )
            )
        else:
            pool.settings[directive.name] = directive
    return result


_HTACCESS_PHP = {"php_value", "php_flag", "php_admin_value", "php_admin_flag"}
_FILES_OPEN = re.compile(r"^<\s*(FilesMatch|Files)\s+(.+?)\s*>$", re.IGNORECASE)
_FILES_CLOSE = re.compile(r"^</\s*(FilesMatch|Files)\s*>$", re.IGNORECASE)


def parse_htaccess(text: str, path: str) -> HtaccessFile:
    result = HtaccessFile(path=path)
    files_stack: List[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        location = Location(path, lineno)
        if not stripped or stripped.startswith("#"):
            continue
        opening = _FILES_OPEN.match(stripped)
        if opening:
            files_stack.append(opening.group(2).strip().strip("\"'"))
            continue
        if _FILES_CLOSE.match(stripped):
            if files_stack:
                files_stack.pop()
            continue
        try:
            tokens = shlex.split(stripped, posix=True)
        except ValueError:
            tokens = stripped.split()
        if not tokens:
            continue
        keyword = tokens[0].lower()
        pattern = files_stack[-1] if files_stack else None
        if keyword in _HTACCESS_PHP:
            if keyword.startswith("php_admin"):
                result.issues.append(
                    ParseIssue(location, f"{tokens[0]} is not allowed in .htaccess (Apache answers 500)")
                )
                continue
            if len(tokens) < 2:
                result.issues.append(ParseIssue(location, f"{tokens[0]} without a directive name"))
                continue
            raw = " ".join(tokens[2:])
            value = raw
            if keyword == "php_flag" or raw.lower() in ("none", ""):
                value = _BOOL_WORDS.get(raw.lower(), raw)
            result.directives.append(
                Directive(
                    name=tokens[1],
                    value=value,
                    raw=raw,
                    location=location,
                    kind=SourceKind.HTACCESS,
                    unresolved="${" in raw,
                )
            )
        elif keyword in ("addtype", "addhandler") and len(tokens) >= 3 and "php" in tokens[1].lower():
            result.handlers.append(HandlerMapping(location, stripped, tuple(t.lower() for t in tokens[2:]), pattern))
        elif keyword == "sethandler" and len(tokens) >= 2 and "php" in tokens[1].lower():
            result.handlers.append(HandlerMapping(location, stripped, (), pattern))
    return result
