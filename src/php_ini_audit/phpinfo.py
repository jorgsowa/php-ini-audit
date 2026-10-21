"""Audit the effective configuration shown by phpinfo(): `php -i` text, the HTML page, or text copied from it."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple

from . import directives, values
from .config import EffectiveConfig
from .engine import AuditResult, Auditor, Options, Target
from .fsutil import FileSystem
from .model import Directive, Location, SourceKind

SOURCE = "phpinfo()"
_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*$")
_MODULE = re.compile(r"^[A-Za-z][A-Za-z0-9_ +]*$")
_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)(.*)$")
_HEADINGS = {"phpinfo()", "configuration", "additional modules", "environment", "php variables", "php credits",
             "php license", "directive", "variable", "credits", "php core", "php group", "language design & concept"}
# phpinfo() prints display names ("Apache 2.0 Handler"); PHP_SAPI prints "apache2handler", "cli".
_SAPIS = (("fpm", "fpm"), ("command line", "cli"), ("apache 2", "apache2"), ("apache2", "apache2"), ("cgi", "cgi"),
          ("litespeed", "litespeed"), ("embed", "embed"), ("cli", "cli"))
# Displayers that print something other than the INI value.
_DISPLAYED = {
    "display_errors": {"stdout": "1", "stderr": "stderr"},
    "odbc.default_cursortype": {"forward only cursor": "0", "keyset driven cursor": "1", "dynamic cursor": "2",
                                "static cursor": "3"},
    "odbc.defaultbinmode": {"passthru": "0", "return as is": "1", "return as char": "2"},
    "odbc.defaultlrl": {"passthru": "0"},
}
_RETURN_BYTES = re.compile(r"^return up to (\d+) bytes$")


@dataclass
class Phpinfo:
    fields: Dict[str, str] = field(default_factory=dict)
    settings: Dict[str, Tuple[str, int]] = field(default_factory=dict)
    modules: List[Tuple[str, int]] = field(default_factory=list)


def _clean(name: str, value: str) -> str:
    value = value.strip()
    if value == "no value":
        return ""
    if value == "Unlimited":
        return "-1"
    match = _RETURN_BYTES.match(value)
    if match:
        return match.group(1)
    return _DISPLAYED.get(name, {}).get(value.lower(), value)


def _module_name(text: str) -> str:
    name = text.strip().lower()
    return re.sub(r"^zend\s+", "", name).replace(" ", "_")


def _add_row(info: Phpinfo, cells: List[str], line: int) -> None:
    cells = [c.strip() for c in cells]
    if len(cells) == 2 and cells[0] and cells[0] not in info.fields:
        info.fields[cells[0]] = cells[1]
    elif len(cells) == 3 and _NAME.match(cells[0]) and cells[0] != "Directive":
        info.settings.setdefault(cells[0], (_clean(cells[0], cells[1]), line))


class _HtmlRows(HTMLParser):
    def __init__(self, info: Phpinfo):
        super().__init__(convert_charrefs=True)
        self.info = info
        self.row: Optional[List[str]] = None
        self.cell: Optional[List[str]] = None
        self.row_line = 0
        self.module: Optional[List[str]] = None
        self.module_line = 0
        self.title: Optional[List[str]] = None

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.row, self.row_line = [], self.getpos()[0]
        elif tag in ("td", "th") and self.row is not None:
            self.cell = []
        elif tag == "a" and (dict(attrs).get("name") or "").startswith("module_"):
            self.module, self.module_line = [], self.getpos()[0]
        elif tag == "h1":
            self.title = []

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.cell is not None and self.row is not None:
            self.row.append("".join(self.cell))
            self.cell = None
        elif tag == "tr" and self.row is not None:
            _add_row(self.info, self.row, self.row_line)
            self.row = None
        elif tag == "a" and self.module is not None:
            self.info.modules.append((_module_name("".join(self.module)), self.module_line))
            self.module = None
        elif tag == "h1" and self.title is not None:
            match = re.match(r"PHP Version (\S+)", "".join(self.title).strip())
            if match:
                self.info.fields.setdefault("PHP Version", match.group(1))
            self.title = None

    def handle_data(self, data):
        for buffer in (self.cell, self.module, self.title):
            if buffer is not None:
                buffer.append(data)


def _parse_text(text: str, info: Phpinfo) -> None:
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index].rstrip()
        number = index + 1
        index += 1
        if "\t" in line:
            cells = line.split("\t")
        elif " => " in line:
            cells = line.split(" => ")
            # `php -i` wraps long lists such as "Additional .ini files parsed" after each comma.
            while len(cells) == 2 and cells[1].endswith(",") and index < len(lines):
                cells[1] += lines[index].strip()
                index += 1
        else:
            stripped = line.strip()
            before = lines[number - 2].strip() if number >= 2 else ""
            after = lines[number].strip() if number < len(lines) else ""
            match = re.match(r"^PHP Version (\S+)$", stripped)
            if match:
                info.fields.setdefault("PHP Version", match.group(1))
            elif (_MODULE.match(stripped) and not before and not after
                  and stripped.lower() not in _HEADINGS):
                info.modules.append((_module_name(stripped), number))
            continue
        _add_row(info, cells, number)


def parse(text: str) -> Phpinfo:
    info = Phpinfo()
    if re.search(r"<t[dr][\s>]", text, re.IGNORECASE):
        _HtmlRows(info).feed(text)
    else:
        _parse_text(text, info)
    if not info.settings:
        raise ValueError("no phpinfo() directive table found: paste the output of phpinfo() or `php -i`")
    return info


def _sapi(server_api: str) -> str:
    lowered = server_api.lower()
    return next((sapi for marker, sapi in _SAPIS if marker in lowered), "unknown")


def _version(text: str) -> Tuple[Optional[Tuple[int, ...]], bool]:
    match = _VERSION.match(text.strip())
    if not match:
        return None, False
    suffix = match.group(4).lower()
    # Distribution builds (8.2.7-1~deb12u1) backport fixes; deb.sury.org builds track upstream.
    backports = bool(re.search(r"deb|ubuntu|el\d", suffix)) and "sury" not in suffix
    return tuple(int(p) for p in match.groups()[:3]), backports


def _same(value: str, default: Optional[str]) -> bool:
    if default is None:
        return False
    if value in ("On", "Off"):
        return values.to_bool(value) == values.to_bool(default)
    return value == default


def build_target(info: Phpinfo, options: Options) -> Target:
    layers = []
    for name, (value, line) in info.settings.items():
        if _same(value, directives.default(name)):
            continue
        layers.append(Directive(name, value, value, Location(SOURCE, line), SourceKind.PHPINFO))
    for module, line in info.modules:
        layers.append(Directive("extension", module, module, Location(SOURCE, line), SourceKind.PHPINFO))
    version, backports = _version(info.fields.get("PHP Version", ""))
    source = SOURCE if version else None
    if options.php_version:
        version, source, backports = options.php_version, "--php-version", False
    loaded = info.fields.get("Loaded Configuration File", "")
    scanned = [p.strip() for p in info.fields.get("Additional .ini files parsed", "").split(",")]
    files = [p for p in [loaded] + scanned if p and p != "(none)"]
    return Target(
        label=SOURCE,
        sapi=options.sapi or _sapi(info.fields.get("Server API", "")),
        php_version=version,
        files=files,
        config=EffectiveConfig(layers),
        version_source=source,
        version_backports=backports,
        platform="windows" if info.fields.get("System", "").startswith("Windows") else "posix",
        layers=layers,
        defaults_reason="phpinfo() reports no loaded php.ini" if loaded == "(none)" else None,
        observed=frozenset(info.settings),
    )


def audit(text: str, options: Optional[Options] = None) -> AuditResult:
    options = options or Options()
    options.path_checks = False
    return Auditor(FileSystem(), options).evaluate([build_target(parse(text), options)])
