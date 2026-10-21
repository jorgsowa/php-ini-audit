"""Filesystem confinement and the safety of paths referenced by the configuration."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator, Optional, Tuple

from ..model import Confidence, Setting, Severity
from ..paths import is_absolute
from .base import CRITICAL, FASTCGI_SAPIS, HIGH, INFO, LOW, MEDIUM, WEB_SAPIS, Hit, names, rule

_WINDOWS_LIST = re.compile(r"(^|;)[A-Za-z]:[\\/]")


def split_path_list(value: str):
    separator = ";" if _WINDOWS_LIST.search(value) else ":"
    return [entry.strip() for entry in value.split(separator) if entry.strip()]


def session_dir(value: str) -> str:
    """session.save_path accepts "N;MODE;/path"; the directory is the last segment."""
    return value.rsplit(";", 1)[-1].strip()


@dataclass(frozen=True)
class PathSpec:
    directive: str
    kind: str
    purpose: str
    writable: Optional[Severity]
    webroot: Optional[Severity]


PATH_SPECS: Tuple[PathSpec, ...] = (
    PathSpec("extension_dir", "dir", "PHP loads extension shared objects from it", CRITICAL, HIGH),
    PathSpec("auto_prepend_file", "file", "it is executed before every script", CRITICAL, None),
    PathSpec("auto_append_file", "file", "it is executed after every script", CRITICAL, None),
    PathSpec("include_path", "list", "include/require search it", HIGH, None),
    PathSpec("open_basedir", "list", "scripts may read and write there", LOW, None),
    PathSpec("session.save_path", "session", "it stores session data", MEDIUM, HIGH),
    PathSpec("upload_tmp_dir", "dir", "it receives uploaded files", LOW, HIGH),
    PathSpec("sys_temp_dir", "dir", "it holds temporary files", None, MEDIUM),
    PathSpec("error_log", "log", "it receives error messages", MEDIUM, HIGH),
    PathSpec("mail.log", "log", "it records every mail() call", MEDIUM, HIGH),
    PathSpec("opcache.file_cache", "dir", "PHP executes the compiled opcodes cached there", HIGH, HIGH),
    PathSpec("opcache.preload", "file", "it is executed at server start-up", CRITICAL, None),
    PathSpec("opcache.lockfile_path", "dir", "it holds OPcache lock files", LOW, None),
    PathSpec("opcache.error_log", "log", "it receives OPcache errors", MEDIUM, HIGH),
    PathSpec("opcache.blacklist_filename", "file", "it controls which files bypass OPcache", LOW, None),
    PathSpec("browscap", "file", "get_browser() parses it", LOW, None),
    PathSpec("openssl.cafile", "file", "it is the trusted CA bundle for TLS", HIGH, None),
    PathSpec("openssl.capath", "dir", "it holds trusted CA certificates", HIGH, None),
    PathSpec("curl.cainfo", "file", "it is the trusted CA bundle for cURL", HIGH, None),
    PathSpec("soap.wsdl_cache_dir", "dir", "SoapClient trusts the WSDL files cached there", MEDIUM, MEDIUM),
    PathSpec("sqlite3.extension_dir", "dir", "SQLite3::loadExtension() loads native code from it", HIGH, HIGH),
    PathSpec("sendmail_path", "command", "mail() executes it", CRITICAL, None),
    PathSpec("xdebug.output_dir", "dir", "it receives profiler and trace dumps", None, MEDIUM),
    PathSpec("xdebug.log", "log", "it receives Xdebug logs", None, MEDIUM),
)


def configured_paths(ctx) -> Iterator[Tuple[PathSpec, object, str]]:
    for spec in PATH_SPECS:
        setting = ctx.get(spec.directive)
        value = setting.text
        if not value or setting.unresolved:
            continue
        if spec.kind == "list":
            candidates = split_path_list(value)
        elif spec.kind == "session":
            candidates = [session_dir(value)]
        elif spec.kind == "command":
            candidates = value.split()[:1]
        elif spec.kind == "log" and value.lower() == "syslog":
            continue
        else:
            candidates = [value]
        for path in candidates:
            if path and is_absolute(path):
                yield spec, setting, path
    for directive in ctx.config.extensions:
        if is_absolute(directive.value):
            spec = PathSpec(directive.name, "file", "it is loaded as a native extension", CRITICAL, HIGH)
            yield spec, directive, directive.value


@rule(
    "FS-001",
    "open_basedir is not set",
    severity=MEDIUM,
    directives=("open_basedir",),
    sapis=WEB_SAPIS,
    cwe="CWE-22",
    description="Without open_basedir, a path traversal or file-inclusion bug can reach any file the PHP user "
    "can read (/etc/passwd, other sites, keys). PHP does not treat it as a hard security boundary, but it "
    "limits the impact of common bugs.",
    recommendation="Set open_basedir to the application directory plus its temp/session/upload directories, "
    "each with a trailing slash.",
    references=("https://www.php.net/manual/en/ini.core.php#ini.open-basedir",),
)
def open_basedir_unset(ctx):
    setting = ctx.get("open_basedir")
    if not setting.text:
        yield Hit("open_basedir is empty", (setting,), confidence=Confidence.MEDIUM)


@rule(
    "FS-002",
    "open_basedir allows the whole filesystem",
    severity=MEDIUM,
    directives=("open_basedir",),
    cwe="CWE-22",
    description="An open_basedir entry of '/' (or a bare drive) disables the restriction entirely.",
    recommendation="List only the directories the application needs.",
)
def open_basedir_root(ctx):
    setting = ctx.get("open_basedir")
    broad = [e for e in split_path_list(setting.text) if e in ("/", "\\") or re.fullmatch(r"[A-Za-z]:[\\/]?", e)]
    if broad:
        yield Hit(f"open_basedir contains {names(broad)}", (setting,))


@rule(
    "FS-003",
    "open_basedir entries match by prefix",
    severity=LOW,
    directives=("open_basedir",),
    cwe="CWE-22",
    description="open_basedir compares prefixes: '/var/www/site' also allows '/var/www/site-backup'. A trailing "
    "separator restricts the entry to that directory.",
    recommendation="End every directory entry with '/' (or '\\' on Windows).",
)
def open_basedir_prefix(ctx):
    setting = ctx.get("open_basedir")
    loose = [
        e
        for e in split_path_list(setting.text)
        if is_absolute(e) and not e.endswith(("/", "\\")) and e not in ("/", "\\")
    ]
    if loose:
        yield Hit(f"entries without trailing separator: {names(loose)}", (setting,))


@rule(
    "FS-004",
    "open_basedir uses relative entries",
    severity=LOW,
    directives=("open_basedir",),
    cwe="CWE-22",
    description="Relative entries such as '.' are resolved against the current working directory, which "
    "changes with chdir() and the requested script.",
    recommendation="Use absolute directories only.",
)
def open_basedir_relative(ctx):
    setting = ctx.get("open_basedir")
    relative = [e for e in split_path_list(setting.text) if not is_absolute(e)]
    if relative:
        yield Hit(f"relative entries: {names(relative)}", (setting,))


@rule(
    "FS-005",
    "Security-relevant path is world-writable",
    severity=HIGH,
    scope="config",
    cwe="CWE-732",
    description="A path PHP loads code, certificates, sessions or logs from is writable by every local user, "
    "or sits in a world-writable directory where it can be created or replaced.",
    recommendation="Make the path owned by root (or the deploy user) and not writable by others; use a "
    "dedicated directory instead of /tmp.",
)
def world_writable_paths(ctx):
    if ctx.paths is None:
        return
    for spec, setting, path in configured_paths(ctx):
        if spec.writable is None:
            continue
        facts = ctx.paths.facts(path)
        if facts is None:
            continue
        label = f"{setting.name} path {path}"
        default_value = isinstance(setting, Setting) and not setting.is_set
        if facts.world_writable:
            sticky = " (sticky)" if facts.sticky else ""
            yield Hit(
                f"{label} is world-writable{sticky}; {spec.purpose}",
                (setting,),
                severity=spec.writable,
                confidence=Confidence.LOW if default_value else Confidence.HIGH,
            )
        elif facts.writable_ancestor:
            state = "does not exist" if not facts.exists else "exists"
            replaceable = not facts.writable_ancestor_sticky or not facts.exists
            if replaceable:
                yield Hit(
                    f"{label} {state} in world-writable {facts.writable_ancestor}; {spec.purpose}",
                    (setting,),
                    severity=spec.writable,
                    confidence=Confidence.LOW if default_value else Confidence.MEDIUM,
                )


@rule(
    "FS-006",
    "Sensitive path inside a web-served directory",
    severity=HIGH,
    cwe="CWE-538",
    description="Logs, sessions, uploads or caches under the document root can be downloaded, and log or "
    "session files that are both web-reachable and includable enable log-poisoning attacks.",
    recommendation="Move the path outside the document root. Pass --webroot to make this check exact.",
)
def webroot_paths(ctx):
    if ctx.paths is None:
        return
    for spec, setting, path in configured_paths(ctx):
        if spec.webroot is None:
            continue
        confidence = ctx.paths.webroot_match(path)
        if confidence is not None:
            yield Hit(
                f"{setting.name} path {path} appears to be web-served; {spec.purpose}",
                (setting,),
                severity=spec.webroot,
                confidence=confidence,
            )


@rule(
    "FS-007",
    "Configured path does not exist",
    severity=INFO,
    description="An explicitly configured path does not exist on the audited system; PHP silently falls "
    "back or fails at runtime, and whoever creates the path first controls it.",
    recommendation="Create the path with the intended owner and permissions, or remove the directive.",
)
def missing_paths(ctx):
    if ctx.paths is None:
        return
    for spec, setting, path in configured_paths(ctx):
        if isinstance(setting, Setting) and not setting.is_set:
            continue
        facts = ctx.paths.facts(path)
        if facts is not None and not facts.exists and not facts.writable_ancestor:
            yield Hit(f"{setting.name} path {path} does not exist", (setting,))


@rule(
    "FS-008",
    "Per-directory .user.ini overrides enabled",
    severity=INFO,
    directives=("user_ini.filename",),
    sapis=FASTCGI_SAPIS,
    cwe="CWE-15",
    description="With CGI/FastCGI, any directory may carry a .user.ini that changes PERDIR settings such as "
    "auto_prepend_file. An upload vulnerability then becomes persistent code execution.",
    recommendation="Set user_ini.filename = (empty) if applications do not need per-directory settings.",
)
def user_ini_enabled(ctx):
    setting = ctx.get("user_ini.filename")
    if setting.text:
        yield Hit(f"per-directory overrides read from {setting.text!r}", (setting,))


@rule(
    "FS-009",
    "HTTP file uploads enabled",
    severity=INFO,
    directives=("file_uploads",),
    sapis=WEB_SAPIS,
    cwe="CWE-434",
    description="file_uploads lets every script receive files; disable it on hosts that never accept uploads.",
    recommendation="Set file_uploads = Off where uploads are not needed.",
)
def file_uploads(ctx):
    setting = ctx.get("file_uploads")
    if setting.as_bool():
        yield Hit("file_uploads is On", (setting,), confidence=Confidence.LOW)


@rule(
    "FS-010",
    "Uploads stored in the shared system temp directory",
    severity=INFO,
    directives=("upload_tmp_dir", "file_uploads"),
    sapis=WEB_SAPIS,
    cwe="CWE-377",
    description="Without upload_tmp_dir, uploads land in the system temp directory shared with every other "
    "process, which eases temp-file races and LFI-via-upload techniques.",
    recommendation="Point upload_tmp_dir at a dedicated directory owned by the PHP user, mode 0700.",
)
def upload_tmp_dir(ctx):
    uploads = ctx.get("file_uploads")
    setting = ctx.get("upload_tmp_dir")
    if uploads.as_bool() and not setting.text:
        yield Hit("upload_tmp_dir is not set", (setting,))


@rule(
    "FS-011",
    "Configuration file writable by other users",
    severity=CRITICAL,
    scope="file",
    cwe="CWE-732",
    description="Anyone who can write a PHP configuration file or its directory can enable auto_prepend_file, "
    "load extensions or disable protections.",
    recommendation="Make configuration files and their directories owned by root and not writable by group "
    "or others.",
)
def config_file_permissions(fctx):
    if fctx.paths is None:
        return
    facts = fctx.paths.facts(fctx.path)
    if facts is None or not facts.exists:
        return
    if facts.world_writable:
        yield Hit(f"{fctx.path} is world-writable")
    elif facts.writable_ancestor and not facts.writable_ancestor_sticky:
        yield Hit(f"{fctx.path} is in world-writable directory {facts.writable_ancestor}")
    elif facts.group_writable:
        yield Hit(f"{fctx.path} is group-writable", severity=LOW, confidence=Confidence.MEDIUM)

