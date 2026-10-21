"""Known PHP vulnerabilities whose exploitability depends on the configuration, matched to the PHP version.

Fixed-in releases come from the official changelogs (php.net/ChangeLog-7.php, ChangeLog-8.php) and
support dates from php.net/supported-versions.php and php.net/eol.php.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, replace
from typing import Callable, Dict, Optional, Tuple

from .. import directives
from ..config import OverlayKind
from ..model import Confidence, Setting, Severity
from ..versions import format_version, parse_version
from .base import CRITICAL, HIGH, INFO, LOW, MEDIUM, WEB_SAPIS, Hit, rule
from .execution import disabled_functions
from .extensions import loaded_extension

Branch = Tuple[int, int]
# (reason, evidence) or (reason, evidence, confidence); None when the configuration is not exposed.
Match = Optional[tuple]

# Branch -> (end of security support, last release when already end-of-life).
SUPPORT: Dict[Branch, Tuple[datetime.date, Optional[str]]] = {
    (5, 6): (datetime.date(2018, 12, 31), "5.6.40"),
    (7, 0): (datetime.date(2019, 1, 10), "7.0.33"),
    (7, 1): (datetime.date(2019, 12, 1), "7.1.33"),
    (7, 2): (datetime.date(2020, 11, 30), "7.2.34"),
    (7, 3): (datetime.date(2021, 12, 6), "7.3.33"),
    (7, 4): (datetime.date(2022, 11, 28), "7.4.33"),
    (8, 0): (datetime.date(2023, 11, 26), "8.0.30"),
    (8, 1): (datetime.date(2025, 12, 31), "8.1.34"),
    (8, 2): (datetime.date(2026, 12, 31), None),
    (8, 3): (datetime.date(2027, 12, 31), None),
    (8, 4): (datetime.date(2028, 12, 31), None),
    (8, 5): (datetime.date(2029, 12, 31), None),
}
EOL_WARNING_DAYS = 180


@dataclass(frozen=True)
class Advisory:
    cve: str
    title: str
    severity: Severity
    fixed: Tuple[str, ...]
    condition: Callable[..., Match]
    description: str
    mitigation: str
    cwe: Optional[str] = None
    scope: str = "config"
    sapis: Optional[frozenset] = None

    @property
    def fixes(self) -> Dict[Branch, int]:
        result = {}
        for text in self.fixed:
            major, minor, patch = parse_version(text)
            result[(major, minor)] = patch
        return result

    def status(self, version: Tuple[int, ...]) -> str:
        """'affected', 'possible' (patch level unknown), 'fixed' or 'untracked' (older than every listed fix)."""
        fixes = self.fixes
        branch = (version[0], version[1])
        if branch in fixes:
            if len(version) < 3:
                return "possible"
            return "affected" if version[2] < fixes[branch] else "fixed"
        if branch > max(fixes):
            return "fixed"
        if branch < min(fixes):
            return "untracked"
        return "affected"

    def fixed_for(self, version: Tuple[int, ...]) -> str:
        branch = (version[0], version[1])
        patch = self.fixes.get(branch)
        if patch is not None:
            return f"{branch[0]}.{branch[1]}.{patch}"
        return "a supported branch (" + ", ".join(self.fixed) + ")"


def _fpm(ctx) -> bool:
    return ctx.sapi == "fpm" or bool(ctx.pools)


def _cgi_confidence(ctx) -> Optional[Confidence]:
    """php-cgi is certain for the cgi SAPI, plausible for an unknown SAPI without FPM pools."""
    if ctx.sapi == "cgi":
        return Confidence.HIGH
    if ctx.sapi == "unknown" and not ctx.pools:
        return Confidence.MEDIUM if ctx.platform == "windows" else Confidence.LOW
    return None


def windows_cgi(ctx) -> Match:
    confidence = _cgi_confidence(ctx)
    if ctx.platform == "windows" and confidence is not None:
        return "PHP runs on Windows and may be served through php-cgi", (), confidence
    return None


def force_redirect_cgi(ctx) -> Match:
    setting = ctx.get("cgi.force_redirect")
    confidence = _cgi_confidence(ctx)
    if confidence is not None and setting.as_bool():
        return "php-cgi relies on cgi.force_redirect", (setting,), confidence
    return None


def windows_proc_open(ctx) -> Match:
    if ctx.platform == "windows" and "proc_open" not in disabled_functions(ctx):
        return "proc_open() is callable on Windows", (ctx.get("disable_functions"),)
    return None


def fpm_any(ctx) -> Match:
    return ("PHP-FPM is in use", ()) if _fpm(ctx) else None


def fpm_multi_pool(ctx) -> Match:
    if _fpm(ctx) and len(ctx.pools) > 1:
        return f"{len(ctx.pools)} FPM pools share one OPcache", ()
    return None


def pool_catch_output(ctx) -> Match:
    directive = ctx.pool.settings.get("catch_workers_output")
    if directive is not None and directive.value and directive.value.lower() not in ("no", "0", "off", "false"):
        return "catch_workers_output is enabled", (directive,)
    return None


def pool_allowed_clients(ctx) -> Match:
    listen = ctx.pool.settings.get("listen")
    allowed = ctx.pool.settings.get("listen.allowed_clients")
    if listen is not None and not listen.value.startswith("/") and allowed is not None and allowed.value.strip():
        return f"TCP listener restricted only by listen.allowed_clients = {allowed.value}", (allowed, listen)
    return None


def pool_status_page(ctx) -> Match:
    directive = ctx.pool.settings.get("pm.status_path")
    if directive is not None and directive.value.strip():
        return f"pm.status_path = {directive.value}", (directive,)
    return None


def imap_loaded(ctx) -> Match:
    directive = loaded_extension(ctx, "imap")
    return ("the imap extension is loaded", (directive,)) if directive is not None else None


def url_fopen(ctx) -> Match:
    setting = ctx.get("allow_url_fopen")
    return ("allow_url_fopen lets file functions fetch http:// URLs", (setting,)) if setting.as_bool() else None


def post_reading(ctx) -> Match:
    setting = ctx.get("enable_post_data_reading")
    if ctx.is_web and setting.as_bool():
        return "PHP parses multipart request bodies", (setting,)
    return None


def uploads(ctx) -> Match:
    setting = ctx.get("file_uploads")
    if ctx.is_web and setting.as_bool():
        return "file_uploads is On", (setting,)
    return None


def upload_progress(ctx) -> Match:
    setting = ctx.get("session.upload_progress.enabled")
    if ctx.is_web and setting.as_bool():
        return "session.upload_progress.enabled is On", (setting,)
    return None


MIB = 1024**2
SMALL_POST_LIMIT = 32 * MIB


def oom_path(ctx) -> Match:
    memory = ctx.get("memory_limit")
    size = memory.as_bytes()
    if size is not None and size < 0:
        reason = "memory_limit = -1 removes PHP's own limit, but allocation failures still reach the vulnerable path"
        confidence = Confidence.MEDIUM
    else:
        reason = f"{memory.describe()} lets a request run into the out-of-memory path"
        confidence = Confidence.HIGH
    evidence = (memory,)
    post = ctx.get("post_max_size")
    post_size = post.as_bytes()
    if post_size is not None and (post_size <= 0 or post_size > SMALL_POST_LIMIT):
        reason += f"; {post.describe()} accepts large request bodies"
        evidence += (post,)
    return reason, evidence, confidence


def _before_request_parsing(ctx, name: str) -> Tuple[Setting, Optional[Setting]]:
    """The value in force while the request body is parsed, and the .user.ini override that comes too late."""
    setting = ctx.get(name)
    if ctx.overlay_kind is not OverlayKind.USER_INI or not ctx.config.is_overlay(setting.directive):
        return setting, None
    if setting.overridden:
        previous = setting.overridden[-1]
        return Setting(name, previous.value, previous, setting.overridden[:-1]), setting
    return Setting(name, directives.default(name)), setting


def stale_state(ctx) -> Match:
    progress, late = _before_request_parsing(ctx, "session.upload_progress.enabled")
    paths, evidence = [], []
    if progress.as_bool():
        if late is not None:
            paths.append(f"session upload progress stays On because {late.describe()} in .user.ini applies after "
                         "request parsing")
            evidence.append(late)
        else:
            paths.append("session.upload_progress.enabled is On")
            evidence.append(progress)
    backtraces = ctx.get("fatal_error_backtraces")
    if ctx.php_version is not None and ctx.php_version >= (8, 5) and backtraces.as_bool():
        paths.append("fatal_error_backtraces is On")
        evidence.append(backtraces)
    if paths:
        return "; ".join(paths), tuple(evidence)
    return "the confirmed paths are closed, but other variants remain", (late or progress,), Confidence.MEDIUM


def prefixed_session_cookie(ctx) -> Match:
    setting = ctx.get("session.name")
    if setting.text.startswith(("__Host-", "__Secure-")):
        return f"session.name = {setting.text} relies on the cookie prefix", (setting,)
    return None


_HTTP_WRAPPER = "PHP's http:// stream wrapper"
_FPM_SAPIS = frozenset({"fpm", "unknown"})

_PHP2SHELL_FIXED = ("8.2.35", "8.3.36", "8.4.27", "8.5.12")

ADVISORIES: Tuple[Advisory, ...] = (
    Advisory("CVE-2026-109618", "Remote code execution after an out-of-memory error", CRITICAL, _PHP2SHELL_FIXED,
             oom_path,
             "When an allocation fails, PHP aborts the request and leaves request memory in an invalid state that "
             "shutdown code still uses, so a crafted request can corrupt memory and run code (exploited in the "
             "wild). Configuration only reduces exposure.",
             "Upgrade. Until then set memory_limit = -1 with php_admin_value so applications cannot lower it, keep "
             "post_max_size at 8M (32M with uploads), and bound memory with a container or cgroup limit rather "
             "than RLIMIT_AS/RLIMIT_DATA.", "CWE-416", sapis=WEB_SAPIS),
    Advisory("CVE-2026-109619", "Remote code execution through stale request state", CRITICAL, _PHP2SHELL_FIXED,
             stale_state,
             "Request-owned state survives a fatal error into the next request on the same worker and is used "
             "before initialisation. Confirmed paths are session upload progress and, on PHP 8.5, fatal error "
             "backtraces; other variants remain.",
             "Upgrade. Until then set session.upload_progress.enabled = 0 in php.ini or the FPM pool (not "
             ".user.ini or ini_set()), on PHP 8.5 set fatal_error_backtraces = 0, restart every worker, and remove "
             "deprecated settings from .user.ini/.htaccess.", "CWE-416", sapis=WEB_SAPIS),
    Advisory("CVE-2024-4577", "php-cgi argument injection on Windows", CRITICAL, ("8.1.29", "8.2.20", "8.3.8"),
             windows_cgi,
             "Windows 'Best-Fit' character conversion lets a soft hyphen in the query string become a php-cgi "
             "command-line option, giving remote code execution (exploited in the wild, e.g. default XAMPP).",
             "Upgrade; until then do not expose php-cgi (use PHP-FPM or mod_php).", "CWE-78",
             sapis=frozenset({"cgi", "unknown"})),
    Advisory("CVE-2024-8926", "Bypass of the CVE-2024-4577 fix", CRITICAL, ("8.1.30", "8.2.24", "8.3.12"),
             windows_cgi,
             "Certain Windows code pages still allow php-cgi argument injection after the CVE-2024-4577 fix.",
             "Upgrade; do not expose php-cgi on Windows.", "CWE-88", sapis=frozenset({"cgi", "unknown"})),
    Advisory("CVE-2024-8927", "cgi.force_redirect bypass", HIGH, ("8.1.30", "8.2.24", "8.3.12"),
             force_redirect_cgi,
             "An environment variable collision lets requests bypass the cgi.force_redirect protection and invoke "
             "php-cgi directly.",
             "Upgrade; do not expose php-cgi directly.", "CWE-284", sapis=frozenset({"cgi", "unknown"})),
    Advisory("CVE-2024-1874", "Command injection through proc_open() on Windows", HIGH,
             ("8.1.28", "8.2.18", "8.3.6"), windows_proc_open,
             "Array-form proc_open() commands are not escaped correctly for .bat/.cmd files on Windows.",
             "Upgrade, or add proc_open to disable_functions if unused.", "CWE-78"),
    Advisory("CVE-2024-5585", "Bypass of the CVE-2024-1874 fix", HIGH, ("8.1.29", "8.2.20", "8.3.8"),
             windows_proc_open,
             "Trailing spaces in the command name bypass the CVE-2024-1874 escaping fix for proc_open() on Windows.",
             "Upgrade, or add proc_open to disable_functions if unused.", "CWE-78"),
    Advisory("CVE-2019-11043", "PHP-FPM env_path_info underflow (remote code execution)", CRITICAL,
             ("7.1.33", "7.2.24", "7.3.11"), fpm_any,
             "With nginx configurations that use fastcgi_split_path_info with a regex that can be broken by a "
             "newline, a crafted URL corrupts FPM memory and leads to remote code execution (exploited in the wild).",
             "Upgrade; add try_files $fastcgi_script_name =404 before fastcgi_pass.", "CWE-787", sapis=_FPM_SAPIS),
    Advisory("CVE-2021-21703", "PHP-FPM local privilege escalation to root", HIGH,
             ("7.3.32", "7.4.25", "8.0.12"), fpm_any,
             "A compromised FPM worker can write to shared memory of the root master process and escalate to root.",
             "Upgrade.", "CWE-787", sapis=_FPM_SAPIS),
    Advisory("CVE-2018-10545", "FPM workers can bypass OPcache access controls", MEDIUM,
             ("7.0.29", "7.1.16", "7.2.4"), fpm_multi_pool,
             "Dumpable FPM child processes let one pool read another pool's OPcache data via ptrace.",
             "Upgrade; keep process.dumpable = no.", "CWE-284", sapis=_FPM_SAPIS),
    Advisory("CVE-2024-9026", "PHP-FPM worker output can alter log entries", LOW, ("8.1.30", "8.2.24", "8.3.12"),
             pool_catch_output,
             "With catch_workers_output, a worker can emit messages that strip characters from log lines, "
             "hiding or forging log entries.",
             "Upgrade, or disable catch_workers_output.", "CWE-117", scope="pool"),
    Advisory("CVE-2026-91768", "IPv6 bypass of listen.allowed_clients", HIGH,
             ("8.2.34", "8.3.35", "8.4.26", "8.5.11"), pool_allowed_clients,
             "listen.allowed_clients compares IPv6 addresses partially, so clients outside the list can reach the "
             "unauthenticated FastCGI port.",
             "Upgrade; also firewall the FastCGI port or use a Unix socket.", "CWE-284", scope="pool"),
    Advisory("CVE-2026-6735", "XSS in the PHP-FPM status page", MEDIUM, ("8.2.31", "8.3.31", "8.4.21", "8.5.6"),
             pool_status_page,
             "The FPM status endpoint reflects request data without escaping in its HTML output.",
             "Upgrade, or remove pm.status_path / restrict it to administrators.", "CWE-79", scope="pool"),
    Advisory("CVE-2018-19518", "imap_open() runs shell commands", HIGH, ("7.0.33", "7.1.25", "7.2.13"),
             imap_loaded,
             "Before the fix, rsh/ssh mailbox names in imap_open() could inject commands; there was no "
             "imap.enable_insecure_rsh switch.",
             "Upgrade and keep imap.enable_insecure_rsh = Off.", "CWE-78"),
    Advisory("CVE-2025-1861", "HTTP wrapper truncates redirect locations", MEDIUM,
             ("8.1.32", "8.2.28", "8.3.19", "8.4.5"), url_fopen,
             f"{_HTTP_WRAPPER} truncates Location headers to 1024 bytes, so redirects can lead somewhere else.",
             "Upgrade, or set allow_url_fopen = Off.", "CWE-131"),
    Advisory("CVE-2025-1736", "HTTP wrapper header check may omit headers", MEDIUM,
             ("8.1.32", "8.2.28", "8.3.19", "8.4.5"), url_fopen,
             f"{_HTTP_WRAPPER} may miss user-supplied Authorization headers and send unintended headers.",
             "Upgrade, or set allow_url_fopen = Off.", "CWE-20"),
    Advisory("CVE-2025-1734", "HTTP wrapper accepts headers without a colon", LOW,
             ("8.1.32", "8.2.28", "8.3.19", "8.4.5"), url_fopen,
             f"{_HTTP_WRAPPER} accepts malformed response headers, enabling response confusion.",
             "Upgrade, or set allow_url_fopen = Off.", "CWE-436"),
    Advisory("CVE-2025-1217", "HTTP wrapper mishandles folded headers", LOW,
             ("8.1.32", "8.2.28", "8.3.19", "8.4.5"), url_fopen,
             f"{_HTTP_WRAPPER} does not handle folded headers, so response headers can be misinterpreted.",
             "Upgrade, or set allow_url_fopen = Off.", "CWE-436"),
    Advisory("CVE-2025-1219", "libxml uses the wrong content type after redirects", LOW,
             ("8.1.32", "8.2.28", "8.3.19", "8.4.5"), url_fopen,
             "Remote documents loaded by DOM/SimpleXML through redirects are parsed with the wrong charset.",
             "Upgrade, or set allow_url_fopen = Off.", "CWE-436"),
    Advisory("CVE-2024-11234", "CRLF injection through stream proxy configuration", MEDIUM,
             ("8.1.31", "8.2.26", "8.3.14"), url_fopen,
             f"{_HTTP_WRAPPER} with a proxy configured allows CRLF injection in the request URI.",
             "Upgrade, or set allow_url_fopen = Off.", "CWE-93"),
    Advisory("CVE-2026-91766", "HTTP wrapper leaks credentials across origins on redirect", HIGH,
             ("8.2.34", "8.3.35", "8.4.26", "8.5.11"), url_fopen,
             f"{_HTTP_WRAPPER} forwards credentials to a different origin when following redirects.",
             "Upgrade, or set allow_url_fopen = Off.", "CWE-200"),
    Advisory("CVE-2026-93682", "HTTP wrapper out-of-bounds read on empty redirect", MEDIUM,
             ("8.2.34", "8.3.35", "8.4.26", "8.5.11"), url_fopen,
             f"A redirect with an empty Location header makes {_HTTP_WRAPPER} read out of bounds.",
             "Upgrade, or set allow_url_fopen = Off.", "CWE-125"),
    Advisory("CVE-2023-0662", "Denial of service through multipart request bodies", MEDIUM,
             ("8.0.28", "8.1.16", "8.2.3"), post_reading,
             "Requests with many multipart parts consume excessive CPU; the fix introduced "
             "max_multipart_body_parts.",
             "Upgrade and keep max_input_vars/max_file_uploads modest.", "CWE-400", sapis=WEB_SAPIS),
    Advisory("CVE-2024-8925", "Erroneous parsing of multipart form data", MEDIUM, ("8.1.30", "8.2.24", "8.3.12"),
             post_reading,
             "Malformed multipart boundaries are parsed inconsistently with upstream proxies and WAFs, letting "
             "attackers smuggle form fields past filtering.",
             "Upgrade.", "CWE-436", sapis=WEB_SAPIS),
    Advisory("CVE-2019-11048", "Upload temp files left behind by long names", MEDIUM,
             ("7.2.31", "7.3.18", "7.4.6"), uploads,
             "Long file or variable names in multipart requests exhaust memory and leave temporary upload files on "
             "disk.",
             "Upgrade.", "CWE-190", sapis=WEB_SAPIS),
    Advisory("CVE-2020-7062", "Crash in session upload progress", MEDIUM, ("7.2.28", "7.3.15", "7.4.3"),
             upload_progress,
             "A crafted upload with session upload progress enabled dereferences a NULL pointer and crashes the "
             "worker.",
             "Upgrade, or set session.upload_progress.enabled = Off.", "CWE-476", sapis=WEB_SAPIS),
    Advisory("CVE-2024-2756", "__Host-/__Secure- cookie prefix bypass", MEDIUM, ("8.1.28", "8.2.18", "8.3.6"),
             prefixed_session_cookie,
             "Cookie name mangling lets a non-secure origin set cookies that PHP reads as __Host-/__Secure- "
             "cookies (incomplete fix of CVE-2022-31629).",
             "Upgrade.", "CWE-565", sapis=WEB_SAPIS),
    Advisory("CVE-2022-31629", "__Host- cookie names can be spoofed", MEDIUM, ("7.4.32", "8.0.24", "8.1.11"),
             prefixed_session_cookie,
             "HTTP variable name mangling lets an attacker set cookies that PHP treats as __Host- prefixed.",
             "Upgrade.", "CWE-565", sapis=WEB_SAPIS),
    Advisory("CVE-2020-7070", "Encoded cookie names allow __Host- spoofing", MEDIUM, ("7.2.34", "7.3.23", "7.4.11"),
             prefixed_session_cookie,
             "PHP URL-decodes cookie names, so a crafted name is read as a __Host- cookie.",
             "Upgrade.", "CWE-565", sapis=WEB_SAPIS),
)


def _register(advisory: Advisory) -> None:
    def check(ctx):
        version = ctx.php_version
        if not version or advisory.status(version) != "affected":
            return
        match = advisory.condition(ctx)
        if match is None:
            return
        reason, evidence = match[0], match[1]
        confidence = match[2] if len(match) > 2 else Confidence.HIGH
        message = f"PHP {format_version(version)} is affected (fixed in {advisory.fixed_for(version)}); {reason}"
        if ctx.version_backports:
            message += f"; version from {ctx.version_source}, which may carry a backported fix"
            confidence = Confidence.LOW
        yield Hit(message, evidence, confidence=confidence)

    rule(
        advisory.cve,
        advisory.title,
        severity=advisory.severity,
        scope=advisory.scope,
        sapis=advisory.sapis,
        cwe=advisory.cwe,
        description=f"{advisory.description} Fixed in PHP {', '.join(advisory.fixed)}.",
        recommendation=advisory.mitigation,
        references=(f"https://nvd.nist.gov/vuln/detail/{advisory.cve}",),
    )(check)


for _advisory in ADVISORIES:
    _register(_advisory)

_BY_CVE = {a.cve: a for a in ADVISORIES}


def exposed_to(cve: str, version: Optional[Tuple[int, ...]]) -> bool:
    """Whether the version is, or may be, older than the fix; False when the version is unknown."""
    return bool(version) and _BY_CVE[cve].status(version) in ("affected", "possible")


@rule(
    "VULN-001",
    "PHP branch without security support",
    severity=HIGH,
    cwe="CWE-1104",
    description="Branches past their end of life receive no security fixes, so every vulnerability found after "
    "that date stays open. A branch nearing its end of life is reported early.",
    recommendation="Upgrade to a supported PHP branch (see php.net/supported-versions.php).",
    references=("https://www.php.net/supported-versions.php", "https://www.php.net/eol.php"),
)
def end_of_life(ctx, today: Optional[datetime.date] = None):
    version = ctx.php_version
    if not version:
        return
    today = today or datetime.date.today()
    branch = (version[0], version[1])
    if branch not in SUPPORT:
        if branch < min(SUPPORT):
            yield Hit(f"PHP {format_version(version)} reached end of life long ago", severity=CRITICAL)
        return
    end, last_release = SUPPORT[branch]
    source = f" (version from {ctx.version_source})" if ctx.version_source else ""
    if end < today:
        last = f"; last release {last_release}" if last_release else ""
        yield Hit(f"PHP {branch[0]}.{branch[1]} security support ended on {end.isoformat()}{last}{source}")
    elif (end - today).days <= EOL_WARNING_DAYS:
        yield Hit(
            f"PHP {branch[0]}.{branch[1]} security support ends on {end.isoformat()} "
            f"({(end - today).days} days){source}",
            severity=LOW,
        )


@rule(
    "VULN-002",
    "Known vulnerabilities depend on the exact PHP version",
    severity=INFO,
    description="Some known CVEs apply to this configuration, but the exact PHP patch version could not be read "
    "from the system (php_version.h, dpkg, apk or Homebrew), so the scanner cannot tell whether the fix is "
    "installed.",
    recommendation="Pass --php-version X.Y.Z (from `php -v` run by you), or scan with --root so package metadata "
    "can be read.",
)
def version_unknown(ctx):
    version = ctx.php_version
    if version and len(version) >= 3:
        return
    if ctx.pool is not None or ctx.overlay_kind is not None:
        return
    pending = []
    for advisory in ADVISORIES:
        if advisory.sapis is not None and ctx.sapi not in advisory.sapis:
            continue
        if version and advisory.status(version) != "possible":
            continue
        contexts = [replace(ctx, pool=pool) for pool in ctx.pools] if advisory.scope == "pool" else [ctx]
        if not any(advisory.condition(c) is not None for c in contexts):
            continue
        needed = advisory.fixed_for(version) if version else "/".join(advisory.fixed)
        pending.append(f"{advisory.cve} (fixed in {needed})")
    if pending:
        known = f"PHP {format_version(version)}" if version else "PHP version unknown"
        yield Hit(f"{known}; this configuration is exposed to {len(pending)} CVE(s) unless patched: "
                  + ", ".join(pending), confidence=Confidence.MEDIUM)
