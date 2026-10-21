"""Configuration hygiene: syntax, obsolete or misspelled directives, overrides that do not apply."""

from __future__ import annotations

import difflib

from .. import directives
from ..model import Confidence
from .base import CRITICAL, HIGH, INFO, LOW, MEDIUM, Hit, rule, security_directives

_KNOWN_NAMES = sorted(set(directives.KNOWN) | set(directives.OBSOLETE))
_KNOWN_LOWER = {n.lower(): n for n in _KNOWN_NAMES}
_KNOWN_PREFIXES = {name.split(".", 1)[0] for name in _KNOWN_NAMES if "." in name}
_LEGACY_PROTECTIONS = {"safe_mode", "magic_quotes_gpc", "sql.safe_mode"}
_LEGACY_DANGERS = {"register_globals"}


@rule(
    "CFG-001",
    "Syntax problem in configuration file",
    severity=LOW,
    scope="file",
    description="Lines PHP cannot parse are ignored or stop INI parsing at that point, so later settings "
    "silently do not apply.",
    recommendation="Fix the reported lines; use ';' for comments.",
)
def syntax(fctx):
    for issue in fctx.file.issues:
        yield Hit(issue.message, location=issue.location)


@rule(
    "CFG-002",
    "Obsolete directive",
    severity=INFO,
    scope="file",
    description="Directives removed from PHP are ignored. Settings such as safe_mode or magic_quotes_gpc give "
    "a false sense of protection; register_globals = On is critical on the old versions that still honour it.",
    recommendation="Remove obsolete directives and use their modern replacements.",
)
def obsolete(fctx):
    for directive in fctx.file.php_directives:
        removed = directives.removed_in(directive.name)
        if removed is None:
            continue
        removed_version = directives.version_tuple(removed)
        still_active = fctx.php_version is not None and fctx.php_version < removed_version
        if still_active:
            if directive.name in _LEGACY_DANGERS and directive.value and directive.value != "0":
                yield Hit(f"{directive.name} = On on PHP {fctx.php_version[0]}.{fctx.php_version[1]}", (directive,),
                          severity=CRITICAL)
            continue
        if directive.name in _LEGACY_DANGERS and directive.value and directive.value != "0":
            severity = INFO if fctx.php_version else HIGH
            confidence = Confidence.HIGH if fctx.php_version else Confidence.LOW
            yield Hit(
                f"{directive.name} is set On; ignored since PHP {removed} but critical on older versions",
                (directive,),
                severity=severity,
                confidence=confidence,
            )
        elif directive.name in _LEGACY_PROTECTIONS and directive.value and directive.value != "0":
            yield Hit(
                f"{directive.name} was removed in PHP {removed}; it no longer protects anything",
                (directive,),
                severity=LOW,
            )
        else:
            yield Hit(f"{directive.name} was removed in PHP {removed} and is ignored", (directive,))


@rule(
    "CFG-003",
    "Unknown directive resembling a known one",
    severity=LOW,
    scope="file",
    description="PHP ignores unknown directive names (and names are case-sensitive), so a typo such as "
    "'display_error' leaves the intended protection unset.",
    recommendation="Correct the directive name.",
)
def typos(fctx):
    sensitive = security_directives()
    for directive in fctx.file.php_directives:
        name = directive.name
        if directives.is_known(name) or directives.removed_in(name):
            continue
        suggestion = _KNOWN_LOWER.get(name.lower())
        if suggestion is None:
            prefix = name.split(".", 1)[0] if "." in name else None
            if prefix is not None and prefix not in _KNOWN_PREFIXES:
                continue
            matches = difflib.get_close_matches(name, _KNOWN_NAMES, n=1, cutoff=0.9)
            suggestion = matches[0] if matches else None
        if suggestion is not None:
            yield Hit(
                f"unknown directive {name!r}; did you mean {suggestion!r}?",
                (directive,),
                severity=MEDIUM if suggestion in sensitive else LOW,
                confidence=Confidence.MEDIUM,
            )


@rule(
    "CFG-004",
    "Directive redefined with a different value",
    severity=INFO,
    description="When php.ini, scan-dir files and pool settings disagree, the last one read wins. Reviewers "
    "looking at only one file get the wrong picture.",
    recommendation="Keep each security directive in one place.",
)
def redefinitions(ctx):
    sensitive = security_directives()
    for name, history in sorted(ctx.config.history.items()):
        if len(history) < 2 or name not in sensitive:
            continue
        distinct = {d.value for d in history}
        if len(distinct) < 2:
            continue
        final = history[-1]
        earlier = ", ".join(f"{d.value or '(empty)'} at {d.location}" for d in history[:-1])
        yield Hit(f"{name} = {final.value or '(empty)'} overrides {earlier}", (ctx.get(name),))


@rule(
    "CFG-005",
    "Per-directory override that PHP ignores",
    severity=LOW,
    description=".user.ini and .htaccess can only change PHP_INI_PERDIR/PHP_INI_ALL directives. Hardening "
    "attempted there for PHP_INI_SYSTEM directives (disable_functions, allow_url_fopen, expose_php, ...) does "
    "not take effect.",
    recommendation="Move the setting to php.ini or to php_admin_value in the FPM pool / Apache vhost.",
)
def ineffective(ctx):
    sensitive = security_directives()
    for directive in ctx.config.ineffective:
        yield Hit(
            f"{directive.name} cannot be changed from {directive.kind} and is ignored",
            (directive,),
            severity=LOW if directive.name in sensitive else INFO,
        )


@rule(
    "CFG-006",
    "No php.ini loaded: built-in defaults in effect",
    severity=MEDIUM,
    description="Without php.ini, PHP runs with compiled-in defaults: display_errors = On, "
    "register_argc_argv = On, expose_php = On, enable_dl = On and no disable_functions. Official Docker "
    "images ship this way.",
    recommendation="Copy php.ini-production to php.ini and adjust it.",
)
def no_php_ini(ctx):
    if ctx.defaults_reason:
        yield Hit(ctx.defaults_reason)


@rule(
    "CFG-007",
    "Value depends on an environment variable",
    severity=INFO,
    scope="file",
    description="${VAR} is expanded by PHP at start-up from its own environment, so a static audit cannot know "
    "the effective value; rules evaluated the literal text.",
    recommendation="Check the variable in the PHP process environment, or use a literal value.",
)
def unresolved(fctx):
    sensitive = security_directives()
    for directive in fctx.file.php_directives:
        if directive.unresolved:
            yield Hit(
                f"{directive.name} = {directive.raw}",
                (directive,),
                severity=LOW if directive.name in sensitive else INFO,
            )


@rule(
    "CFG-008",
    "Development configuration used in production",
    severity=LOW,
    production_only=True,
    directives=("display_errors", "zend.assertions", "mysqlnd.collect_memory_statistics"),
    description="The combination of display_errors, zend.assertions and mysqlnd memory statistics matches "
    "php.ini-development.",
    recommendation="Start from php.ini-production.",
)
def development_template(ctx):
    display = ctx.get("display_errors")
    markers = [
        ctx.get(n)
        for n in ("zend.assertions", "mysqlnd.collect_memory_statistics")
        if ctx.get(n).is_set and ctx.get(n).as_int() == 1
    ]
    if display.is_set and display.as_bool() and markers:
        yield Hit("settings match php.ini-development", (display, *markers), confidence=Confidence.MEDIUM)


@rule(
    "CFG-009",
    "Conditional [PATH=]/[HOST=] section",
    severity=INFO,
    scope="file",
    description="Directives in [PATH=...] or [HOST=...] sections apply only to matching requests under "
    "CGI/FastCGI; they are audited as separate overlays.",
    recommendation="Verify these sections still match deployed paths and hosts.",
)
def conditional_sections(fctx):
    for section, location in getattr(fctx.file, "conditional_sections", ()):
        yield Hit(f"[{section}] overrides settings for matching requests", location=location)


@rule(
    "CFG-010",
    "Deprecated directive",
    severity=INFO,
    scope="file",
    description="Deprecated directives set to a non-default value still work but emit warnings and will "
    "disappear in a future release.",
    recommendation="Plan to remove the directive.",
)
def deprecated(fctx):
    for directive in fctx.file.php_directives:
        since = directives.DEPRECATED.get(directive.name)
        if since is None:
            continue
        if fctx.php_version is not None and fctx.php_version < directives.version_tuple(since):
            continue
        if directive.value == directives.default(directive.name):
            continue
        yield Hit(f"{directive.name} is deprecated since PHP {since}", (directive,))

