"""CGI/FastCGI settings, PHP-FPM pools and Apache handler mappings."""

from __future__ import annotations

import re

from .. import values
from ..model import Confidence
from .base import CRITICAL, FASTCGI_SAPIS, HIGH, LOW, MEDIUM, Hit, names, rule

PHP_EXTENSIONS = frozenset({".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".phar"})
_NON_PHP_PATTERN = re.compile(
    r"jpe?g|png|gif|bmp|webp|svg|ico|txt|html?|css|js|json|xml|pdf|zip|docx?|xlsx?|csv|mp[34]|\.\*|^\.$|^\*$",
    re.IGNORECASE,
)
_SECRET_NAME = re.compile(r"pass(word)?|secret|token|api[_-]?key|private[_-]?key|credential", re.IGNORECASE)
_LOOPBACK = re.compile(r"^(127\.\d+\.\d+\.\d+|::1|\[::1\]|localhost)$", re.IGNORECASE)


def _limit_extensions(pool):
    directive = pool.settings.get("security.limit_extensions")
    if directive is None:
        return None, None
    return directive, [e.lower() for e in values.split_list(directive.value)]


@rule(
    "CGI-001",
    "php-cgi callable without web-server redirect",
    severity=HIGH,
    directives=("cgi.force_redirect",),
    sapis=frozenset({"cgi", "unknown"}),
    cwe="CWE-88",
    description="cgi.force_redirect = 0 lets php-cgi be invoked directly, the precondition for argument "
    "injection such as CVE-2012-1823 and CVE-2024-4577.",
    recommendation="Keep cgi.force_redirect = 1 (only IIS needs it off), or move to PHP-FPM.",
    references=(
        "https://nvd.nist.gov/vuln/detail/CVE-2012-1823",
        "https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
    ),
)
def force_redirect(ctx):
    setting = ctx.get("cgi.force_redirect")
    if setting.as_bool():
        return
    if ctx.sapi == "cgi":
        yield Hit("cgi.force_redirect is Off for php-cgi", (setting,))
    else:
        yield Hit(
            "cgi.force_redirect is Off (matters if this config serves php-cgi)",
            (setting,),
            severity=MEDIUM,
            confidence=Confidence.LOW,
        )


@rule(
    "CGI-002",
    "PATH_INFO fix-up executes files by path prefix",
    severity=MEDIUM,
    directives=("cgi.fix_pathinfo",),
    sapis=FASTCGI_SAPIS,
    cwe="CWE-434",
    description="With cgi.fix_pathinfo = 1 a request for /uploads/avatar.jpg/x.php can make PHP execute "
    "avatar.jpg when the web server forwards any *.php path. PHP-FPM's security.limit_extensions blocks it.",
    recommendation="Set cgi.fix_pathinfo = 0, or make sure the web server checks that the script exists "
    "(try_files $fastcgi_script_name =404) and security.limit_extensions = .php.",
    references=("https://nvd.nist.gov/vuln/detail/CVE-2019-11043",),
)
def fix_pathinfo(ctx):
    setting = ctx.get("cgi.fix_pathinfo")
    if not setting.as_bool():
        return
    if ctx.sapi == "fpm" or ctx.pools:
        restricted = all(
            exts is None or (exts and set(exts) <= PHP_EXTENSIONS) for _, exts in map(_limit_extensions, ctx.pools)
        )
        if restricted:
            yield Hit(
                "cgi.fix_pathinfo = 1; mitigated by security.limit_extensions in PHP-FPM",
                (setting,),
                severity=LOW,
            )
            return
    yield Hit("cgi.fix_pathinfo = 1", (setting,), confidence=Confidence.MEDIUM)


@rule(
    "FPM-001",
    "FastCGI port reachable from the network",
    severity=CRITICAL,
    scope="pool",
    cwe="CWE-306",
    description="FastCGI has no authentication. Anyone who reaches the port can pass PHP_VALUE / "
    "PHP_ADMIN_VALUE (e.g. auto_prepend_file = php://input) and execute code.",
    recommendation="Listen on a Unix socket or 127.0.0.1, and set listen.allowed_clients; never publish the "
    "port outside the host or container network.",
)
def fpm_listen(ctx):
    listen = ctx.pool.settings.get("listen")
    if listen is None:
        return
    address = listen.value.strip()
    if address.startswith("/") or not address:
        return
    if address.isdigit():
        host = "*"
    else:
        host = address.rsplit(":", 1)[0] if ":" in address else address
    host = host.strip()
    if _LOOPBACK.match(host):
        return
    allowed = ctx.pool.settings.get("listen.allowed_clients")
    all_interfaces = host in ("*", "0.0.0.0", "[::]", "::")
    if allowed is not None and allowed.value.strip():
        yield Hit(
            f"listen = {address}; restricted by listen.allowed_clients = {allowed.value}",
            (listen, allowed),
            severity=MEDIUM,
        )
    elif all_interfaces:
        yield Hit(
            f"listen = {address} binds every interface without listen.allowed_clients",
            (listen,),
            confidence=Confidence.MEDIUM,
        )
    else:
        yield Hit(f"listen = {address} without listen.allowed_clients", (listen,), severity=HIGH,
                  confidence=Confidence.MEDIUM)


@rule(
    "FPM-002",
    "Non-PHP files executable by the pool",
    severity=HIGH,
    scope="pool",
    cwe="CWE-434",
    description="security.limit_extensions restricts which files FPM will execute. An empty list or image/text "
    "extensions turn uploaded files into code.",
    recommendation="Use security.limit_extensions = .php",
)
def limit_extensions(ctx):
    directive, exts = _limit_extensions(ctx.pool)
    if directive is None:
        return
    if not exts:
        yield Hit("security.limit_extensions is empty: every file may be executed", (directive,))
        return
    extra = [e for e in exts if e not in PHP_EXTENSIONS]
    if extra:
        yield Hit(f"security.limit_extensions allows {names(extra)}", (directive,))


@rule(
    "FPM-003",
    "FastCGI socket writable by every user",
    severity=MEDIUM,
    scope="pool",
    cwe="CWE-276",
    description="A world-writable FPM socket lets any local user send FastCGI requests and run code as the "
    "pool user.",
    recommendation="Use listen.mode = 0660 with listen.owner/listen.group set to the web server.",
)
def socket_mode(ctx):
    directive = ctx.pool.settings.get("listen.mode")
    if directive is None:
        return
    mode = values.parse_octal(directive.value)
    if mode is not None and mode & 0o002:
        yield Hit(f"listen.mode = {directive.value}", (directive,))


@rule(
    "FPM-004",
    "Pool workers run as root",
    severity=HIGH,
    scope="pool",
    cwe="CWE-250",
    description="Running PHP as root turns any application bug into full system compromise.",
    recommendation="Run each pool as a dedicated unprivileged user and group.",
)
def pool_user(ctx):
    for key in ("user", "group"):
        directive = ctx.pool.settings.get(key)
        if directive is not None and directive.value.strip() in ("root", "0"):
            yield Hit(f"{key} = {directive.value}", (directive,))


@rule(
    "FPM-005",
    "Status or ping endpoint enabled",
    severity=LOW,
    scope="pool",
    cwe="CWE-200",
    description="pm.status_path and ping.path expose pool internals (client IPs, request URIs) if the web "
    "server forwards them.",
    recommendation="Remove them or restrict access in the web server.",
)
def status_path(ctx):
    for key in ("pm.status_path", "ping.path"):
        directive = ctx.pool.settings.get(key)
        if directive is not None and directive.value.strip():
            yield Hit(f"{key} = {directive.value}", (directive,), confidence=Confidence.MEDIUM)


@rule(
    "FPM-006",
    "Full environment passed to PHP",
    severity=LOW,
    scope="pool",
    cwe="CWE-526",
    description="clear_env = no gives PHP every environment variable of the FPM master.",
    recommendation="Keep clear_env = yes and pass only needed variables with env[NAME].",
)
def clear_env(ctx):
    directive = ctx.pool.settings.get("clear_env")
    if directive is not None and not values.to_bool(directive.value):
        yield Hit("clear_env = no", (directive,))


@rule(
    "FPM-007",
    "Secret stored in pool configuration",
    severity=MEDIUM,
    scope="pool",
    cwe="CWE-260",
    description="Literal secrets in env[] entries end up in configuration backups and in phpinfo()/$_SERVER.",
    recommendation="Reference the master environment (env[DB_PASSWORD] = $DB_PASSWORD) or use a secret store.",
)
def env_secrets(ctx):
    for directive in ctx.pool.env:
        if _SECRET_NAME.search(directive.name) and directive.value and not directive.value.startswith("$"):
            yield Hit(f"env[{directive.name}] holds a literal value", (directive,), confidence=Confidence.MEDIUM)


@rule(
    "FPM-008",
    "Workers are dumpable",
    severity=LOW,
    scope="pool",
    cwe="CWE-528",
    description="process.dumpable = yes allows core dumps and ptrace of workers by the same user, exposing "
    "secrets held in memory.",
    recommendation="Keep process.dumpable = no.",
)
def dumpable(ctx):
    directive = ctx.pool.settings.get("process.dumpable")
    if directive is not None and values.to_bool(directive.value):
        yield Hit("process.dumpable = yes", (directive,))


@rule(
    "HTA-001",
    "Non-PHP files mapped to the PHP handler",
    severity=HIGH,
    scope="file",
    cwe="CWE-434",
    description="AddType/AddHandler/SetHandler mapping images, text or every file to PHP makes uploads "
    "executable.",
    recommendation="Map only .php to the PHP handler, inside <FilesMatch \"\\.php$\">.",
)
def htaccess_handlers(fctx):
    for mapping in getattr(fctx.file, "handlers", ()):
        if mapping.extensions:
            extra = [e for e in mapping.extensions if ("." + e.lstrip(".")) not in PHP_EXTENSIONS]
            if extra:
                yield Hit(f"{mapping.statement} maps {names(extra)} to PHP", location=mapping.location)
        elif mapping.files_pattern is None:
            yield Hit(f"{mapping.statement} executes every file in the directory as PHP", location=mapping.location)
        elif _NON_PHP_PATTERN.search(mapping.files_pattern):
            yield Hit(
                f"{mapping.statement} inside <Files {mapping.files_pattern}> covers non-PHP files",
                location=mapping.location,
                confidence=Confidence.MEDIUM,
            )
