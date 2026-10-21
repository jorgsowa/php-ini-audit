"""Debug extensions, OPcache, database drivers and character encoding."""

from __future__ import annotations

import os
import re

from ..model import Confidence
from .base import CRITICAL, FASTCGI_SAPIS, HIGH, INFO, LOW, MEDIUM, WEB_SAPIS, Hit, names, rule

DEV_EXTENSIONS = ("xhprof", "tideways", "tideways_xhprof", "pcov", "uopz", "runkit", "runkit7", "spx")
CREDENTIAL_DIRECTIVES = (
    "mysqli.default_pw",
    "mysql.default_password",
    "odbc.default_pw",
    "ibase.default_password",
    "pdo_odbc.default_pw",
)
_CREDENTIAL_NAME = re.compile(r"(^|[._])(pw|pass|passwd|password|secret)$", re.IGNORECASE)
_MULTIBYTE_RISK = re.compile(r"^(gbk|gb2312|gb18030|big5(-hkscs)?|sjis|shift[_-]?jis|cp932|cp936|cp949|cp950|euc-?jp-?ms)$", re.IGNORECASE)


def loaded_extension(ctx, name: str):
    for directive in ctx.config.extensions:
        base = os.path.basename(directive.value.replace("\\", "/")).lower()
        stem = re.sub(r"^(php_)?|(\.so|\.dll)$", "", base)
        if stem == name:
            return directive
    return None


def _xdebug_settings_present(ctx) -> bool:
    return any(s.name.startswith("xdebug.") for s in ctx.config.explicit())


@rule(
    "EXT-001",
    "Xdebug accepts debugger connections for any client",
    severity=CRITICAL,
    dev_severity=HIGH,
    directives=("xdebug.mode", "xdebug.discover_client_host", "xdebug.remote_enable", "xdebug.remote_connect_back"),
    cwe="CWE-489",
    description="With discover_client_host (Xdebug 3) or remote_connect_back (Xdebug 2), Xdebug connects back "
    "to whoever sent the request and hands them a debugger that can evaluate arbitrary PHP.",
    recommendation="Never enable client discovery on reachable hosts; remove Xdebug from production.",
    references=("https://xdebug.org/docs/all_settings#discover_client_host",),
)
def xdebug_connect_back(ctx):
    if not (loaded_extension(ctx, "xdebug") or _xdebug_settings_present(ctx)):
        return
    mode = ctx.get("xdebug.mode")
    discover = ctx.get("xdebug.discover_client_host")
    if "debug" in [m.strip() for m in mode.text.lower().split(",")] and discover.as_bool():
        yield Hit("xdebug.mode includes debug with discover_client_host = 1", (mode, discover))
    remote = ctx.get("xdebug.remote_enable")
    connect_back = ctx.get("xdebug.remote_connect_back")
    if remote.as_bool() and connect_back.as_bool():
        yield Hit("xdebug.remote_enable with remote_connect_back = 1 (Xdebug 2)", (remote, connect_back))


@rule(
    "EXT-002",
    "Xdebug loaded",
    severity=HIGH,
    dev_severity=INFO,
    directives=("zend_extension", "xdebug.mode"),
    cwe="CWE-489",
    description="Xdebug in production slows every request and, depending on xdebug.mode, exposes debugging, "
    "tracing and profiling output.",
    recommendation="Do not install Xdebug on production systems.",
)
def xdebug_loaded(ctx):
    directive = loaded_extension(ctx, "xdebug")
    if directive is None:
        return
    mode = ctx.get("xdebug.mode")
    if mode.text.lower() == "off":
        yield Hit("Xdebug is loaded with xdebug.mode = off", (directive, mode), severity=LOW)
    else:
        yield Hit(f"Xdebug is loaded ({mode.describe()})", (directive, mode))


@rule(
    "EXT-003",
    "Development or profiling extension loaded",
    severity=LOW,
    production_only=True,
    directives=("extension", "zend_extension"),
    cwe="CWE-489",
    description="Profilers, coverage drivers and runtime-patching extensions (uopz, runkit) are not meant for "
    "production and can change behaviour or leak data.",
    recommendation="Remove development extensions from production images.",
)
def dev_extensions(ctx):
    for name in DEV_EXTENSIONS:
        directive = loaded_extension(ctx, name)
        if directive is not None:
            yield Hit(f"{name} is loaded", (directive,))


@rule(
    "OPC-001",
    "OPcache file cache enabled",
    severity=MEDIUM,
    directives=("opcache.file_cache",),
    cwe="CWE-494",
    description="Compiled scripts in opcache.file_cache are executed without re-reading the source. Anyone who "
    "can write there (or an arbitrary-file-write bug) can plant opcodes and get code execution.",
    recommendation="Disable the file cache, or keep it in a root-owned directory the PHP user cannot write "
    "except through OPcache.",
)
def file_cache(ctx):
    setting = ctx.get("opcache.file_cache")
    if setting.text:
        yield Hit(setting.describe(), (setting,), severity=MEDIUM if ctx.is_web else LOW)


@rule(
    "OPC-002",
    "OPcache API not restricted",
    severity=LOW,
    directives=("opcache.restrict_api",),
    sapis=WEB_SAPIS,
    cwe="CWE-284",
    description="Any script can call opcache_get_status() (revealing every cached path) or opcache_reset(). "
    "This matters on shared hosting.",
    recommendation="Set opcache.restrict_api to the path prefix of trusted admin scripts.",
)
def restrict_api(ctx):
    setting = ctx.get("opcache.restrict_api")
    if not setting.text:
        yield Hit("opcache.restrict_api is empty", (setting,), confidence=Confidence.LOW)


@rule(
    "OPC-003",
    "OPcache does not isolate users",
    severity=INFO,
    directives=("opcache.validate_permission", "opcache.validate_root"),
    sapis=FASTCGI_SAPIS,
    cwe="CWE-653",
    description="On shared hosting without validate_permission/validate_root, one user's scripts may hit "
    "another user's cached files.",
    recommendation="Enable opcache.validate_permission (and validate_root with chroot) on multi-tenant hosts.",
)
def opcache_isolation(ctx):
    off = [n for n in ("opcache.validate_permission", "opcache.validate_root") if not ctx.on(n)]
    if off:
        yield Hit(f"{names(off)} Off", tuple(ctx.get(n) for n in off), confidence=Confidence.LOW)


@rule(
    "DB-001",
    "MySQL LOAD DATA LOCAL enabled",
    severity=MEDIUM,
    directives=("mysqli.allow_local_infile",),
    cwe="CWE-73",
    description="A malicious or spoofed MySQL server can ask the client to send any local file the PHP user "
    "can read.",
    recommendation="Set mysqli.allow_local_infile = Off, or restrict mysqli.local_infile_directory.",
)
def local_infile(ctx):
    setting = ctx.get("mysqli.allow_local_infile")
    if setting.as_bool():
        yield Hit("mysqli.allow_local_infile is On", (setting,))


@rule(
    "DB-002",
    "Credentials stored in PHP configuration",
    severity=MEDIUM,
    directives=CREDENTIAL_DIRECTIVES,
    cwe="CWE-260",
    description="Default passwords in INI files are readable by every user that can read the configuration and "
    "are printed by phpinfo() and ini_get_all().",
    recommendation="Pass credentials from the application's secret storage instead.",
)
def credentials(ctx):
    for setting in ctx.config.explicit():
        if setting.text and (setting.name in CREDENTIAL_DIRECTIVES or _CREDENTIAL_NAME.search(setting.name)):
            yield Hit(f"{setting.name} holds a value", (setting,))


@rule(
    "DB-003",
    "SQLite safety features relaxed",
    severity=LOW,
    directives=("sqlite3.defensive", "sqlite3.extension_dir"),
    cwe="CWE-114",
    description="sqlite3.defensive = Off allows SQL to corrupt the database file; sqlite3.extension_dir enables "
    "SQLite3::loadExtension(), which loads native code.",
    recommendation="Keep sqlite3.defensive = On and leave sqlite3.extension_dir unset.",
)
def sqlite(ctx):
    defensive = ctx.get("sqlite3.defensive")
    if not defensive.as_bool():
        yield Hit("sqlite3.defensive is Off", (defensive,))
    extension_dir = ctx.get("sqlite3.extension_dir")
    if extension_dir.text:
        yield Hit(f"{extension_dir.describe()} enables loadExtension()", (extension_dir,))


@rule(
    "ENC-001",
    "Unsafe default character set",
    severity=MEDIUM,
    directives=("default_charset",),
    sapis=WEB_SAPIS,
    cwe="CWE-838",
    description="Multi-byte charsets such as GBK, Big5 or Shift_JIS let a trailing byte swallow escape "
    "characters (addslashes/escaping bypass, SQL injection); an empty charset leaves browsers guessing (XSS).",
    recommendation="Set default_charset = \"UTF-8\".",
)
def default_charset(ctx):
    setting = ctx.get("default_charset")
    charset = setting.text
    if not charset:
        yield Hit("default_charset is empty", (setting,), severity=LOW)
    elif _MULTIBYTE_RISK.match(charset):
        yield Hit(f"default_charset = {charset}", (setting,))
    elif charset.upper().replace("_", "-") not in ("UTF-8", "UTF8"):
        yield Hit(f"default_charset = {charset}", (setting,), severity=LOW)


@rule(
    "ENC-002",
    "mbstring function overloading enabled",
    severity=MEDIUM,
    directives=("mbstring.func_overload",),
    cwe="CWE-704",
    description="mbstring.func_overload silently changes strlen()/substr() into multibyte versions, breaking "
    "binary-safe code such as cryptography and length checks. Removed in PHP 8.0.",
    recommendation="Set mbstring.func_overload = 0 and call mb_* functions explicitly.",
)
def func_overload(ctx):
    setting = ctx.get("mbstring.func_overload")
    if setting.as_int() == 0:
        return
    below_8 = ctx.version_below(8, 0)
    if below_8 is False:
        return
    yield Hit(setting.describe(), (setting,), confidence=Confidence.HIGH if below_8 else Confidence.LOW)


@rule(
    "ENC-003",
    "Multibyte script parsing enabled",
    severity=LOW,
    directives=("zend.multibyte",),
    cwe="CWE-838",
    description="zend.multibyte lets scripts be parsed in non-ASCII-compatible encodings such as Shift_JIS, "
    "which complicates reviewing code and can hide payloads.",
    recommendation="Set zend.multibyte = Off unless legacy encodings are required.",
)
def zend_multibyte(ctx):
    setting = ctx.get("zend.multibyte")
    if setting.as_bool():
        yield Hit("zend.multibyte is On", (setting,))


@rule(
    "ENC-004",
    "Automatic input encoding translation",
    severity=LOW,
    directives=("mbstring.encoding_translation",),
    sapis=WEB_SAPIS,
    cwe="CWE-838",
    description="mbstring.encoding_translation converts request input before the application validates it, "
    "which can undo validation done on raw bytes.",
    recommendation="Set mbstring.encoding_translation = Off and convert explicitly.",
)
def encoding_translation(ctx):
    setting = ctx.get("mbstring.encoding_translation")
    if setting.as_bool():
        yield Hit("mbstring.encoding_translation is On", (setting,))
