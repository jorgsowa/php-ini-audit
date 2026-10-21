"""Resource limits that bound denial-of-service impact."""

from __future__ import annotations

from .base import INFO, LOW, MEDIUM, WEB_SAPIS, Hit, rule
from .vulnerabilities import exposed_to

GIB = 1024**3


@rule(
    "RES-001",
    "Unlimited or very large memory_limit",
    severity=MEDIUM,
    directives=("memory_limit",),
    sapis=WEB_SAPIS,
    cwe="CWE-770",
    description="memory_limit = -1 lets one request exhaust server memory.",
    recommendation="Set memory_limit to what the application needs (typically 128M-512M).",
)
def memory_limit(ctx):
    setting = ctx.get("memory_limit")
    size = setting.as_bytes()
    if size is not None and size < 0:
        if exposed_to("CVE-2026-109618", ctx.php_version):
            yield Hit("memory_limit is unlimited (-1), the interim mitigation for CVE-2026-109618; restore a limit "
                      "after upgrading", (setting,), severity=INFO)
        else:
            yield Hit("memory_limit is unlimited (-1)", (setting,))
    elif size is not None and size > GIB:
        yield Hit(f"{setting.describe()} (> 1G)", (setting,), severity=LOW)


@rule(
    "RES-002",
    "Unlimited or long max_execution_time",
    severity=MEDIUM,
    directives=("max_execution_time",),
    sapis=WEB_SAPIS,
    cwe="CWE-400",
    description="max_execution_time = 0 lets slow or stuck requests occupy workers forever.",
    recommendation="Use 30-60 seconds for web requests (and request_terminate_timeout in FPM).",
)
def max_execution_time(ctx):
    setting = ctx.get("max_execution_time")
    seconds = setting.as_int()
    if seconds <= 0:
        yield Hit("max_execution_time is unlimited", (setting,))
    elif seconds > 300:
        yield Hit(f"{setting.describe()} seconds", (setting,), severity=LOW)


@rule(
    "RES-003",
    "Unlimited or very large POST bodies",
    severity=MEDIUM,
    directives=("post_max_size",),
    sapis=WEB_SAPIS,
    cwe="CWE-770",
    description="post_max_size = 0 removes the request body limit.",
    recommendation="Set post_max_size slightly above the largest legitimate upload.",
)
def post_max_size(ctx):
    setting = ctx.get("post_max_size")
    size = setting.as_bytes()
    if size == 0:
        yield Hit("post_max_size is unlimited (0)", (setting,))
    elif size is not None and size > GIB:
        yield Hit(f"{setting.describe()} (> 1G)", (setting,), severity=LOW)


@rule(
    "RES-004",
    "Very large uploads accepted",
    severity=LOW,
    directives=("upload_max_filesize", "post_max_size"),
    sapis=WEB_SAPIS,
    cwe="CWE-770",
    description="Large upload limits let clients fill the temp directory and disk.",
    recommendation="Keep upload_max_filesize to the real requirement and below post_max_size.",
)
def upload_max_filesize(ctx):
    setting = ctx.get("upload_max_filesize")
    size = setting.as_bytes()
    if size is not None and size > GIB:
        yield Hit(f"{setting.describe()} (> 1G)", (setting,))
    post = ctx.get("post_max_size").as_bytes()
    if size and post and post > 0 and size > post:
        yield Hit(
            "upload_max_filesize exceeds post_max_size; larger uploads fail silently",
            (setting, ctx.get("post_max_size")),
            severity=LOW,
        )


@rule(
    "RES-005",
    "max_input_vars raised or disabled",
    severity=LOW,
    directives=("max_input_vars",),
    sapis=WEB_SAPIS,
    cwe="CWE-407",
    description="max_input_vars caps request variables and protects against hash-collision DoS "
    "(CVE-2011-4885).",
    recommendation="Keep max_input_vars at 1000-5000.",
    references=("https://nvd.nist.gov/vuln/detail/CVE-2011-4885",),
)
def max_input_vars(ctx):
    setting = ctx.get("max_input_vars")
    count = setting.as_int()
    if count <= 0 or count > 10000:
        yield Hit(setting.describe(), (setting,))


@rule(
    "RES-006",
    "Deep input nesting allowed",
    severity=LOW,
    directives=("max_input_nesting_level",),
    sapis=WEB_SAPIS,
    cwe="CWE-674",
    description="Deeply nested request arrays cost CPU and memory to parse.",
    recommendation="Keep max_input_nesting_level at 64.",
)
def max_input_nesting_level(ctx):
    setting = ctx.get("max_input_nesting_level")
    if setting.as_int() > 256:
        yield Hit(setting.describe(), (setting,))


@rule(
    "RES-007",
    "Many files per request accepted",
    severity=LOW,
    directives=("max_file_uploads",),
    sapis=WEB_SAPIS,
    cwe="CWE-770",
    description="Each uploaded file costs a temp file and file descriptor.",
    recommendation="Keep max_file_uploads at 20 or the application's real need.",
)
def max_file_uploads(ctx):
    setting = ctx.get("max_file_uploads")
    if setting.as_int() > 100:
        yield Hit(setting.describe(), (setting,))


@rule(
    "RES-008",
    "Regular expression limits raised",
    severity=LOW,
    directives=("pcre.backtrack_limit", "pcre.recursion_limit"),
    cwe="CWE-1333",
    description="Higher PCRE limits make catastrophic backtracking (ReDoS) and stack exhaustion crashes easier.",
    recommendation="Keep pcre.backtrack_limit = 1000000 and pcre.recursion_limit = 100000.",
)
def pcre_limits(ctx):
    for name, limit in (("pcre.backtrack_limit", 1_000_000), ("pcre.recursion_limit", 100_000)):
        setting = ctx.get(name)
        if setting.as_int() > limit:
            yield Hit(f"{setting.describe()} (default {limit})", (setting,))


@rule(
    "RES-009",
    "unserialize() nesting depth unlimited",
    severity=LOW,
    directives=("unserialize_max_depth",),
    cwe="CWE-674",
    description="unserialize_max_depth = 0 lets deeply nested payloads exhaust the stack.",
    recommendation="Keep unserialize_max_depth = 4096 or lower.",
)
def unserialize_depth(ctx):
    setting = ctx.get("unserialize_max_depth")
    if setting.as_int() <= 0:
        yield Hit("unserialize_max_depth is unlimited", (setting,))


@rule(
    "RES-010",
    "Socket reads may block indefinitely",
    severity=LOW,
    directives=("default_socket_timeout",),
    sapis=WEB_SAPIS,
    cwe="CWE-400",
    description="A negative or very long default_socket_timeout lets slow remote peers hold workers.",
    recommendation="Use 60 seconds or less.",
)
def socket_timeout(ctx):
    setting = ctx.get("default_socket_timeout")
    seconds = setting.as_int()
    if seconds < 0 or seconds > 300:
        yield Hit(setting.describe(), (setting,))


@rule(
    "RES-011",
    "Unlimited multipart body parts",
    severity=LOW,
    directives=("max_multipart_body_parts", "max_input_vars", "max_file_uploads"),
    sapis=WEB_SAPIS,
    cwe="CWE-770",
    description="max_multipart_body_parts bounds multipart parsing (CVE-2023-0662); when it is -1 the bound "
    "is max_input_vars + max_file_uploads, so raising those raises it too.",
    recommendation="Keep max_input_vars and max_file_uploads modest, or set max_multipart_body_parts.",
    references=("https://nvd.nist.gov/vuln/detail/CVE-2023-0662",),
)
def multipart_parts(ctx):
    setting = ctx.get("max_multipart_body_parts")
    explicit = setting.as_int()
    if explicit > 10000:
        yield Hit(setting.describe(), (setting,))
    elif explicit < 0:
        derived = ctx.get("max_input_vars").as_int() + ctx.get("max_file_uploads").as_int()
        if derived > 10000:
            yield Hit(
                f"effective multipart part limit is {derived}",
                (setting, ctx.get("max_input_vars"), ctx.get("max_file_uploads")),
            )
