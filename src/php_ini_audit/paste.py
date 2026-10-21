"""Audit configuration pasted as text, recognising what kind of input it is."""

from __future__ import annotations

import re
from typing import Optional, Tuple

from . import phpinfo
from .discovery import Discovery, Installation
from .engine import AuditResult, Auditor, Options
from .fsutil import FileSystem
from .model import SourceKind
from .parser import parse_fpm, parse_htaccess, parse_ini

# kind -> (label, path the findings point at)
KINDS = {
    "phpinfo": ("phpinfo() output", "phpinfo()"),
    "php.ini": ("php.ini", "php.ini"),
    "user.ini": (".user.ini", ".user.ini"),
    "fpm": ("PHP-FPM configuration", "php-fpm.conf"),
    "htaccess": (".htaccess", ".htaccess"),
}
_PHPINFO = re.compile(r'<td class="e">|\bLocal Value\b|^PHP Version\b|^phpinfo\(\)', re.MULTILINE)
_HTACCESS = re.compile(
    r"^[ \t]*(?:php_(?:admin_)?(?:value|flag)\s+[\w.]+\s|<(?:IfModule|FilesMatch|Files|Directory|Location)\b"
    r"|(?:AddHandler|AddType|SetHandler|RewriteEngine|RewriteRule|Options|Require|DirectoryIndex)\s)",
    re.MULTILINE | re.IGNORECASE,
)
_FPM = re.compile(
    r"^[ \t]*(?:listen|pm|pm\.[\w.]+|php_(?:admin_)?(?:value|flag)\[[\w.]+\]|security\.limit_extensions|clear_env"
    r"|catch_workers_output|request_terminate_timeout|process_control_timeout|daemonize|ping\.path)[ \t]*=",
    re.MULTILINE,
)


def detect(text: str) -> str:
    if _PHPINFO.search(text):
        return "phpinfo"
    if _HTACCESS.search(text):
        return "htaccess"
    if _FPM.search(text):
        return "fpm"
    return "php.ini"


def parse_version(text: str) -> Optional[Tuple[int, ...]]:
    text = text.strip()
    if not text:
        return None
    if not re.fullmatch(r"\d+\.\d+(\.\d+)?", text):
        raise ValueError("PHP version must look like 8.3 or 8.3.12")
    return tuple(int(p) for p in text.split("."))


def audit(text: str, kind: Optional[str] = None, options: Optional[Options] = None) -> Tuple[str, AuditResult]:
    """Return the input kind (detected unless given) and the audit of the pasted text."""
    options = options or Options()
    options.path_checks = False
    kind = kind or detect(text)
    if kind not in KINDS:
        raise ValueError(f"unknown input kind: {kind}")
    if kind == "phpinfo":
        return kind, phpinfo.audit(text, options)

    path = KINDS[kind][1]
    discovery = Discovery()
    if kind == "fpm":
        parsed = parse_fpm(text, path)
        found = bool(parsed.pools or parsed.global_settings)
        discovery.installations.append(Installation(label="pasted PHP-FPM configuration", ini=None, fpm_files=[path],
                                                    sapi="fpm"))
    elif kind == "htaccess":
        parsed = parse_htaccess(text, path)
        found = bool(parsed.directives or parsed.handlers)
        discovery.htaccess.append(path)
    elif kind == "user.ini":
        parsed = parse_ini(text, path, SourceKind.USER_INI)
        found = bool(parsed.directives)
        discovery.user_inis.append(path)
    else:
        parsed = parse_ini(text, path, SourceKind.PHP_INI)
        found = bool(parsed.directives)
        discovery.installations.append(Installation(label="pasted php.ini", ini=path))
    if not found:
        raise ValueError(f"no {KINDS[kind][0]} settings found in the pasted text")
    auditor = Auditor(FileSystem(), options)
    # Seeding the parse cache keeps the file system out of it: nothing is read from disk.
    auditor.parsed[path] = parsed
    return kind, auditor.run(discovery)
