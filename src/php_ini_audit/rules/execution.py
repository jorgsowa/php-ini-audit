"""Settings that enable or widen code and command execution paths."""

from __future__ import annotations

import re

from ..model import Confidence
from .base import CRITICAL, HIGH, INFO, LOW, MEDIUM, WEB_SAPIS, Hit, names, overlay_set, rule

EXEC_FUNCTIONS = ("exec", "passthru", "shell_exec", "system", "proc_open", "popen", "pcntl_exec")
MAIL_LAUNCHERS = ("mail", "mb_send_mail", "imap_mail", "error_log")
_STREAM_WRAPPER = re.compile(r"^\s*(?:([a-z][a-z0-9+.\-]*)://|data:)", re.IGNORECASE)
_SENDMAIL_DANGER = re.compile(r"(?:^|\s)(-X|-O|-C|-be)\S*")


def disabled_functions(ctx) -> set:
    return {name.lower() for name in ctx.get("disable_functions").as_list()}


@rule(
    "EXEC-001",
    "Remote file inclusion enabled",
    severity=CRITICAL,
    directives=("allow_url_include", "allow_url_fopen"),
    cwe="CWE-98",
    description="allow_url_include lets include/require load code from http://, ftp:// and data:// URLs, "
    "turning any file-inclusion bug into remote code execution.",
    recommendation="Set allow_url_include = Off. The directive has been deprecated since PHP 7.4.",
    references=("https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-include",),
)
def allow_url_include(ctx):
    setting = ctx.get("allow_url_include")
    if not setting.as_bool():
        return
    fopen = ctx.get("allow_url_fopen")
    if fopen.as_bool():
        yield Hit("allow_url_include is enabled", (setting,))
    else:
        yield Hit(
            "allow_url_include is enabled; allow_url_fopen = Off blocks remote wrappers today, "
            "but a single change re-enables remote inclusion",
            (setting, fopen),
            severity=HIGH,
        )


@rule(
    "EXEC-002",
    "Remote URLs accepted by file functions",
    severity=MEDIUM,
    directives=("allow_url_fopen",),
    cwe="CWE-918",
    description="allow_url_fopen lets fopen(), file_get_contents(), getimagesize() and friends fetch http:// and "
    "ftp:// URLs, which turns user-controlled paths into server-side request forgery.",
    recommendation="Set allow_url_fopen = Off and use an HTTP client (cURL) with explicit allow-lists where "
    "remote fetches are needed.",
    references=("https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-fopen",),
)
def allow_url_fopen(ctx):
    setting = ctx.get("allow_url_fopen")
    if setting.as_bool():
        yield Hit(
            "allow_url_fopen is enabled",
            (setting,),
            severity=MEDIUM if ctx.is_web else LOW,
            confidence=Confidence.MEDIUM,
        )


@rule(
    "EXEC-003",
    "Auto-prepended/appended file loaded through a stream wrapper",
    severity=CRITICAL,
    directives=("auto_prepend_file", "auto_append_file"),
    cwe="CWE-94",
    description="auto_prepend_file/auto_append_file pointing at php://input, data:, http:// or another wrapper "
    "executes request- or network-supplied code on every request; this is a classic FastCGI exploitation payload.",
    recommendation="Remove the directive or point it at a root-owned local file.",
)
def prepend_wrapper(ctx):
    for name in ("auto_prepend_file", "auto_append_file"):
        setting = ctx.get(name)
        match = _STREAM_WRAPPER.match(setting.text)
        if match and (match.group(1) or "").lower() != "file":
            yield Hit(f"{setting.describe()} loads code through a stream wrapper", (setting,))


@rule(
    "EXEC-004",
    "Code automatically prepended or appended to every script",
    severity=INFO,
    directives=("auto_prepend_file", "auto_append_file"),
    cwe="CWE-506",
    description="auto_prepend_file/auto_append_file run a file before/after every script. Security plugins use it "
    "legitimately, but a value set from .user.ini or .htaccess is a common web-shell persistence technique.",
    recommendation="Confirm the file is expected, root-owned and not writable by the PHP user; set "
    "user_ini.filename = to stop per-directory overrides if they are not needed.",
)
def prepend_local(ctx):
    for name in ("auto_prepend_file", "auto_append_file"):
        setting = ctx.get(name)
        value = setting.text
        if not value or value.lower() == "none" or _STREAM_WRAPPER.match(value):
            continue
        if overlay_set(setting):
            yield Hit(
                f"{setting.describe()} is set from a per-directory file ({setting.directive.kind})",
                (setting,),
                severity=MEDIUM,
                confidence=Confidence.LOW,
            )
        elif not value.startswith("/") and not re.match(r"^[A-Za-z]:[\\/]", value):
            yield Hit(
                f"{setting.describe()} is a relative path resolved through include_path and the working directory",
                (setting,),
                severity=LOW,
            )
        else:
            yield Hit(f"{setting.describe()} runs for every request", (setting,))


@rule(
    "EXEC-005",
    "Command execution functions are available",
    severity=MEDIUM,
    directives=("disable_functions",),
    sapis=WEB_SAPIS,
    cwe="CWE-78",
    description="Functions that spawn processes turn code injection, deserialization gadgets and file uploads "
    "into full operating-system command execution.",
    recommendation="List the functions the application does not use in disable_functions (php.ini or "
    "php_admin_value in the FPM pool). Composer and symfony/process need proc_open.",
    references=("https://www.php.net/manual/en/ini.core.php#ini.disable-functions",),
)
def exec_functions(ctx):
    setting = ctx.get("disable_functions")
    disabled = disabled_functions(ctx)
    available = [f for f in EXEC_FUNCTIONS if f not in disabled]
    if not available:
        return
    if len(available) == len(EXEC_FUNCTIONS):
        message = f"no command-execution function is disabled ({names(available)})"
    else:
        message = f"disable_functions is partial; still callable: {names(available)}"
    yield Hit(message, (setting,), confidence=Confidence.MEDIUM)


@rule(
    "EXEC-006",
    "disable_functions can be bypassed",
    severity=MEDIUM,
    directives=("disable_functions",),
    sapis=WEB_SAPIS,
    cwe="CWE-693",
    description="With every exec-style function disabled, putenv() combined with a function that launches "
    "sendmail lets an attacker set LD_PRELOAD and run native code anyway.",
    recommendation="Also disable putenv and the mail launchers that are not needed, or run PHP with a "
    "seccomp/AppArmor profile instead of relying on disable_functions.",
    references=("https://www.php.net/manual/en/function.putenv.php",),
)
def disable_functions_bypass(ctx):
    disabled = disabled_functions(ctx)
    if not all(f in disabled for f in EXEC_FUNCTIONS):
        return
    launchers = [f for f in MAIL_LAUNCHERS if f not in disabled]
    if "putenv" not in disabled and launchers:
        yield Hit(
            f"putenv() and {names(launchers)} remain callable (LD_PRELOAD bypass)",
            (ctx.get("disable_functions"),),
            confidence=Confidence.MEDIUM,
        )


@rule(
    "EXEC-007",
    "FFI available to every script",
    severity=HIGH,
    directives=("ffi.enable",),
    cwe="CWE-749",
    description="ffi.enable = On lets any script call arbitrary C functions, which bypasses disable_functions, "
    "open_basedir and every other PHP-level restriction.",
    recommendation="Use ffi.enable = preload (the default) so that only preloaded code can use FFI.",
    references=("https://www.php.net/manual/en/ffi.configuration.php",),
)
def ffi_enabled(ctx):
    setting = ctx.get("ffi.enable")
    if setting.text.lower() != "preload" and setting.as_bool():
        yield Hit("ffi.enable allows FFI from any script", (setting,), confidence=Confidence.MEDIUM)


@rule(
    "EXEC-008",
    "Runtime extension loading (dl) enabled",
    severity=LOW,
    directives=("enable_dl",),
    cwe="CWE-114",
    description="enable_dl permits dl() to load shared objects at runtime. dl() is only available to the CLI and "
    "embed SAPIs, so the impact is limited to scripts run from the command line.",
    recommendation="Set enable_dl = Off.",
)
def enable_dl(ctx):
    setting = ctx.get("enable_dl")
    if setting.as_bool():
        yield Hit("enable_dl is enabled", (setting,), confidence=Confidence.HIGH if ctx.sapi == "cli" else Confidence.MEDIUM)


@rule(
    "EXEC-009",
    "Phar archives writable at runtime",
    severity=MEDIUM,
    directives=("phar.readonly",),
    cwe="CWE-502",
    description="phar.readonly = Off allows scripts to create and modify Phar archives, which helps attackers "
    "craft polyglot files for phar:// deserialization and code execution.",
    recommendation="Set phar.readonly = On except on build machines.",
)
def phar_readonly(ctx):
    setting = ctx.get("phar.readonly")
    if not setting.as_bool():
        yield Hit("phar.readonly is Off", (setting,), severity=MEDIUM if ctx.is_web else LOW)


@rule(
    "EXEC-010",
    "Unsigned Phar archives accepted",
    severity=LOW,
    directives=("phar.require_hash",),
    cwe="CWE-345",
    description="phar.require_hash = Off lets PHP open Phar archives without a signature.",
    recommendation="Set phar.require_hash = On.",
)
def phar_require_hash(ctx):
    setting = ctx.get("phar.require_hash")
    if not setting.as_bool():
        yield Hit("phar.require_hash is Off", (setting,))


@rule(
    "EXEC-011",
    "Query string exposed as $argv in web requests",
    severity=MEDIUM,
    directives=("register_argc_argv",),
    sapis=WEB_SAPIS,
    cwe="CWE-88",
    description="register_argc_argv = On fills $argv from the query string in web requests. Combined with a local "
    "file inclusion this enables the pearcmd.php remote-code-execution technique; it is On by default when no "
    "php.ini is loaded (e.g. official Docker images).",
    recommendation="Set register_argc_argv = Off for web SAPIs.",
)
def register_argc_argv(ctx):
    setting = ctx.get("register_argc_argv")
    if setting.as_bool():
        yield Hit("register_argc_argv is On for a web SAPI", (setting,))


@rule(
    "EXEC-012",
    "imap_open() may run rsh/ssh commands",
    severity=HIGH,
    directives=("imap.enable_insecure_rsh",),
    cwe="CWE-78",
    description="imap.enable_insecure_rsh lets imap_open() mailbox names inject arguments into rsh/ssh "
    "(CVE-2018-19518).",
    recommendation="Set imap.enable_insecure_rsh = Off.",
    references=("https://nvd.nist.gov/vuln/detail/CVE-2018-19518",),
)
def imap_rsh(ctx):
    setting = ctx.get("imap.enable_insecure_rsh")
    if setting.as_bool():
        yield Hit("imap.enable_insecure_rsh is On", (setting,))


@rule(
    "EXEC-013",
    "Dangerous sendmail options configured",
    severity=HIGH,
    directives=("sendmail_path", "mail.force_extra_parameters"),
    cwe="CWE-88",
    description="sendmail options such as -X (log file), -O/-C (alternate queue/config) or Exim's -be "
    "(expansion test) let mail() write attacker-influenced files or evaluate expressions.",
    recommendation="Keep sendmail_path to an absolute binary with -t -i, and do not force extra parameters.",
)
def sendmail_flags(ctx):
    for name in ("sendmail_path", "mail.force_extra_parameters"):
        setting = ctx.get(name)
        flags = sorted(set(_SENDMAIL_DANGER.findall(setting.text)))
        if flags:
            yield Hit(f"{setting.describe()} contains {names(flags)}", (setting,))
    path = ctx.get("sendmail_path")
    binary = path.text.split()[0] if path.text else ""
    if binary and not binary.startswith("/") and not re.match(r"^[A-Za-z]:[\\/]", binary):
        yield Hit(f"sendmail_path binary {binary!r} is resolved through $PATH", (path,), severity=LOW)


@rule(
    "EXEC-014",
    "Assertions compiled and executed in production",
    severity=LOW,
    directives=("zend.assertions", "assert.active"),
    production_only=True,
    cwe="CWE-489",
    description="zend.assertions = 1 executes assert() calls in production. Before PHP 8.0 string assertions "
    "were evaluated as code.",
    recommendation="Set zend.assertions = -1 in production.",
)
def assertions(ctx):
    setting = ctx.get("zend.assertions")
    if setting.as_int() != 1:
        return
    if ctx.version_below(8, 0) and ctx.on("assert.active"):
        yield Hit(
            "zend.assertions = 1 with assert.active on PHP < 8.0 (string assertions are eval'd)",
            (setting, ctx.get("assert.active")),
            severity=MEDIUM,
        )
    else:
        yield Hit("zend.assertions = 1", (setting,))


@rule(
    "EXEC-015",
    "Callback invoked when unserialize() meets an unknown class",
    severity=LOW,
    directives=("unserialize_callback_func",),
    cwe="CWE-502",
    description="unserialize_callback_func is called with attacker-chosen class names while unserializing "
    "untrusted data, which can trigger autoloading of unexpected files.",
    recommendation="Leave unserialize_callback_func empty unless the callback is strictly validated.",
)
def unserialize_callback(ctx):
    setting = ctx.get("unserialize_callback_func")
    if setting.text:
        yield Hit(setting.describe(), (setting,))


@rule(
    "EXEC-016",
    "include_path contains the current directory",
    severity=INFO,
    directives=("include_path",),
    cwe="CWE-427",
    description="A '.' entry makes relative include/require resolve against the working directory, which may "
    "be attacker-influenced (e.g. upload directories).",
    recommendation="Use absolute includes (__DIR__ . '/file.php') or remove '.' from include_path.",
)
def include_path_dot(ctx):
    setting = ctx.get("include_path")
    separator = ";" if re.search(r"(^|;)[A-Za-z]:[\\/]", setting.text) else ":"
    if "." in [entry.strip() for entry in setting.text.split(separator)]:
        yield Hit(f"{setting.describe()} includes '.'", (setting,))


@rule(
    "EXEC-017",
    "Session upload progress writes request data into session files",
    severity=LOW,
    directives=("session.upload_progress.enabled", "session.upload_progress.cleanup"),
    sapis=WEB_SAPIS,
    cwe="CWE-98",
    description="With upload progress enabled, any multipart request stores attacker-controlled data in a "
    "session file, which turns a local file inclusion into code execution even without a session.",
    recommendation="Set session.upload_progress.enabled = Off unless upload progress bars are used; never "
    "disable session.upload_progress.cleanup.",
)
def upload_progress(ctx):
    enabled = ctx.get("session.upload_progress.enabled")
    if not enabled.as_bool():
        return
    cleanup = ctx.get("session.upload_progress.cleanup")
    if not cleanup.as_bool():
        yield Hit(
            "upload progress is enabled and cleanup is Off, so the data persists in the session file",
            (enabled, cleanup),
            severity=MEDIUM,
        )
    else:
        yield Hit("session.upload_progress.enabled is On", (enabled,), confidence=Confidence.MEDIUM)
