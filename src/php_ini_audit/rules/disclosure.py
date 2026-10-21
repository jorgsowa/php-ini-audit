"""Error handling and information disclosure."""

from __future__ import annotations

from .. import values
from ..model import Confidence
from .base import INFO, LOW, MEDIUM, WEB_SAPIS, Hit, rule
from .execution import disabled_functions


@rule(
    "ERR-001",
    "Errors displayed to visitors",
    severity=MEDIUM,
    dev_severity=INFO,
    directives=("display_errors", "html_errors"),
    sapis=WEB_SAPIS,
    cwe="CWE-209",
    description="display_errors prints warnings and stack traces into responses, disclosing paths, queries, "
    "and sometimes credentials. PHP's built-in default is On when no php.ini is loaded.",
    recommendation="Set display_errors = Off and log_errors = On in production.",
    references=("https://www.php.net/manual/en/errorfunc.configuration.php#ini.display-errors",),
)
def display_errors(ctx):
    setting = ctx.get("display_errors")
    text = setting.text.lower()
    if text == "stderr":
        return
    if text == "stdout" or setting.as_bool():
        yield Hit("display_errors is On", (setting,))


@rule(
    "ERR-002",
    "Start-up errors displayed",
    severity=LOW,
    dev_severity=INFO,
    directives=("display_startup_errors",),
    sapis=WEB_SAPIS,
    cwe="CWE-209",
    description="display_startup_errors shows errors raised during PHP's start-up sequence in the output.",
    recommendation="Set display_startup_errors = Off in production.",
)
def display_startup_errors(ctx):
    setting = ctx.get("display_startup_errors")
    if setting.as_bool():
        yield Hit("display_startup_errors is On", (setting,))


@rule(
    "ERR-003",
    "Errors are not logged",
    severity=LOW,
    directives=("log_errors",),
    cwe="CWE-778",
    description="Without log_errors, probing and exploitation attempts that trigger warnings leave no trace.",
    recommendation="Set log_errors = On and configure error_log.",
)
def log_errors(ctx):
    setting = ctx.get("log_errors")
    if not setting.as_bool():
        yield Hit("log_errors is Off", (setting,))


@rule(
    "ERR-004",
    "PHP version disclosed in HTTP headers",
    severity=LOW,
    directives=("expose_php",),
    sapis=WEB_SAPIS,
    cwe="CWE-200",
    description="expose_php adds an X-Powered-By header with the exact PHP version, which helps attackers pick "
    "exploits.",
    recommendation="Set expose_php = Off.",
)
def expose_php(ctx):
    setting = ctx.get("expose_php")
    if setting.as_bool():
        yield Hit("expose_php is On", (setting,))


@rule(
    "ERR-005",
    "Function arguments included in stack traces",
    severity=LOW,
    directives=("zend.exception_ignore_args",),
    production_only=True,
    cwe="CWE-532",
    description="With zend.exception_ignore_args = Off, exception traces carry argument values such as "
    "passwords and tokens into logs and error pages.",
    recommendation="Set zend.exception_ignore_args = On in production.",
)
def exception_args(ctx):
    setting = ctx.get("zend.exception_ignore_args")
    if not setting.as_bool():
        yield Hit("zend.exception_ignore_args is Off", (setting,))


@rule(
    "ERR-006",
    "Error reporting disabled",
    severity=LOW,
    directives=("error_reporting",),
    cwe="CWE-778",
    description="error_reporting = 0 suppresses logging of every error, hiding attacks and bugs alike.",
    recommendation="Use error_reporting = E_ALL and control visibility with display_errors.",
)
def error_reporting(ctx):
    setting = ctx.get("error_reporting")
    level = values.eval_error_reporting(setting.value)
    if level == 0:
        yield Hit("error_reporting evaluates to 0", (setting,))


@rule(
    "ERR-007",
    "Script path added to outgoing mail headers",
    severity=LOW,
    directives=("mail.add_x_header",),
    cwe="CWE-200",
    description="mail.add_x_header adds X-PHP-Originating-Script with the script's UID and file name to every "
    "message.",
    recommendation="Set mail.add_x_header = Off.",
)
def mail_x_header(ctx):
    setting = ctx.get("mail.add_x_header")
    if setting.as_bool():
        yield Hit("mail.add_x_header is On", (setting,))


@rule(
    "ERR-008",
    "Environment variables copied into $_ENV",
    severity=LOW,
    directives=("variables_order",),
    sapis=WEB_SAPIS,
    cwe="CWE-526",
    description="An 'E' in variables_order copies the process environment, often holding secrets, into $_ENV "
    "where debug dumps and phpinfo() reveal it.",
    recommendation="Use variables_order = \"GPCS\" and read configuration with getenv().",
)
def variables_order(ctx):
    setting = ctx.get("variables_order")
    if "E" in setting.text.upper():
        yield Hit(f"{setting.describe()} populates $_ENV", (setting,), confidence=Confidence.MEDIUM)


@rule(
    "ERR-009",
    "Error log created world-writable",
    severity=LOW,
    directives=("error_log_mode",),
    cwe="CWE-732",
    description="error_log_mode controls the permissions of a newly created error log; a world-writable log "
    "can be forged or used for log poisoning.",
    recommendation="Use error_log_mode = 0640 or stricter.",
)
def error_log_mode(ctx):
    setting = ctx.get("error_log_mode")
    mode = values.parse_octal(setting.value)
    if mode is not None and mode & 0o002:
        yield Hit(f"{setting.describe()} grants write access to others", (setting,))


@rule(
    "ERR-010",
    "phpinfo() callable",
    severity=INFO,
    directives=("disable_functions",),
    sapis=WEB_SAPIS,
    production_only=True,
    cwe="CWE-200",
    description="A forgotten phpinfo() page reveals configuration, paths, environment variables and cookies.",
    recommendation="Add phpinfo to disable_functions in production.",
)
def phpinfo(ctx):
    if "phpinfo" not in disabled_functions(ctx):
        yield Hit("phpinfo() is not disabled", (ctx.get("disable_functions"),), confidence=Confidence.LOW)


@rule(
    "ERR-011",
    "Long string arguments kept in stack traces",
    severity=INFO,
    directives=("zend.exception_string_param_max_len",),
    cwe="CWE-532",
    description="Raising zend.exception_string_param_max_len stores more of each string argument in traces.",
    recommendation="Keep the default (15) or lower.",
)
def exception_string_len(ctx):
    setting = ctx.get("zend.exception_string_param_max_len")
    if setting.as_int() > 15:
        yield Hit(setting.describe(), (setting,))
