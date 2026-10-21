"""Session management."""

from __future__ import annotations

import stat

from .. import values
from ..model import Confidence
from .base import HIGH, INFO, LOW, MEDIUM, WEB_SAPIS, Hit, rule
from .filesystem import session_dir

_SHARED_TEMP = ("", "/tmp", "/var/tmp", "/dev/shm")


@rule(
    "SESS-001",
    "Uninitialised session IDs accepted",
    severity=MEDIUM,
    directives=("session.use_strict_mode",),
    sapis=WEB_SAPIS,
    cwe="CWE-384",
    description="Without strict mode PHP adopts any session ID a client presents, enabling session fixation.",
    recommendation="Set session.use_strict_mode = 1.",
    references=("https://www.php.net/manual/en/session.security.ini.php",),
)
def strict_mode(ctx):
    setting = ctx.get("session.use_strict_mode")
    if not setting.as_bool():
        yield Hit("session.use_strict_mode is Off", (setting,))


@rule(
    "SESS-002",
    "Session IDs accepted outside cookies",
    severity=HIGH,
    directives=("session.use_only_cookies",),
    sapis=WEB_SAPIS,
    cwe="CWE-598",
    description="session.use_only_cookies = 0 accepts session IDs from the URL, enabling fixation via links and "
    "leaking IDs through Referer headers and logs.",
    recommendation="Set session.use_only_cookies = 1.",
)
def only_cookies(ctx):
    setting = ctx.get("session.use_only_cookies")
    if not setting.as_bool():
        yield Hit("session.use_only_cookies is Off", (setting,))


@rule(
    "SESS-003",
    "Transparent session IDs in URLs",
    severity=HIGH,
    directives=("session.use_trans_sid",),
    sapis=WEB_SAPIS,
    cwe="CWE-598",
    description="session.use_trans_sid rewrites links to carry the session ID, which leaks through Referer, "
    "browser history, proxies and shared links.",
    recommendation="Set session.use_trans_sid = 0.",
)
def trans_sid(ctx):
    setting = ctx.get("session.use_trans_sid")
    if setting.as_bool():
        yield Hit("session.use_trans_sid is On", (setting,))


@rule(
    "SESS-004",
    "Session cookies disabled",
    severity=MEDIUM,
    directives=("session.use_cookies",),
    sapis=WEB_SAPIS,
    cwe="CWE-598",
    description="session.use_cookies = 0 forces session IDs into URLs or breaks sessions entirely.",
    recommendation="Set session.use_cookies = 1.",
)
def use_cookies(ctx):
    setting = ctx.get("session.use_cookies")
    if not setting.as_bool():
        yield Hit("session.use_cookies is Off", (setting,))


@rule(
    "SESS-005",
    "Session cookie readable from JavaScript",
    severity=MEDIUM,
    directives=("session.cookie_httponly",),
    sapis=WEB_SAPIS,
    cwe="CWE-1004",
    description="Without HttpOnly, any XSS can read document.cookie and steal the session.",
    recommendation="Set session.cookie_httponly = 1.",
)
def httponly(ctx):
    setting = ctx.get("session.cookie_httponly")
    if not setting.as_bool():
        yield Hit("session.cookie_httponly is Off", (setting,))


@rule(
    "SESS-006",
    "Session cookie sent over plain HTTP",
    severity=MEDIUM,
    directives=("session.cookie_secure",),
    sapis=WEB_SAPIS,
    cwe="CWE-614",
    description="Without the Secure flag the session cookie is sent over unencrypted connections and can be "
    "sniffed or injected.",
    recommendation="Set session.cookie_secure = 1 on sites served over HTTPS.",
)
def cookie_secure(ctx):
    setting = ctx.get("session.cookie_secure")
    if not setting.as_bool():
        yield Hit("session.cookie_secure is Off", (setting,), confidence=Confidence.MEDIUM)


@rule(
    "SESS-007",
    "Session cookie without SameSite protection",
    severity=LOW,
    directives=("session.cookie_samesite", "session.cookie_secure"),
    sapis=WEB_SAPIS,
    cwe="CWE-1275",
    description="Without SameSite=Lax or Strict the session cookie accompanies cross-site requests, which "
    "enables CSRF.",
    recommendation="Set session.cookie_samesite = \"Lax\" (or \"Strict\").",
)
def samesite(ctx):
    setting = ctx.get("session.cookie_samesite")
    value = setting.text.lower()
    if not value:
        if setting.directive is not None and setting.directive.raw.split(";")[0].strip().lower() == "none":
            yield Hit("unquoted None is parsed as an empty value; write \"None\" or (better) \"Lax\"", (setting,))
        else:
            yield Hit("session.cookie_samesite is not set", (setting,))
    elif value == "none":
        secure = ctx.get("session.cookie_secure")
        if secure.as_bool():
            yield Hit("SameSite=None sends the cookie on cross-site requests", (setting,))
        else:
            yield Hit(
                "SameSite=None without Secure: cookie sent cross-site and rejected by modern browsers",
                (setting, secure),
                severity=MEDIUM,
            )
    elif value not in ("lax", "strict"):
        yield Hit(f"unrecognised SameSite value {setting.text!r}", (setting,))


@rule(
    "SESS-008",
    "Weak session ID entropy",
    severity=HIGH,
    directives=("session.sid_length", "session.sid_bits_per_character"),
    sapis=WEB_SAPIS,
    cwe="CWE-331",
    description="Session IDs need at least 128 bits of entropy (sid_length x sid_bits_per_character) to resist "
    "brute force.",
    recommendation="Keep sid_length >= 32 with sid_bits_per_character = 4, or use 5/6 bits per character.",
)
def sid_entropy(ctx):
    length = ctx.get("session.sid_length")
    bits = ctx.get("session.sid_bits_per_character")
    entropy = max(length.as_int(), 22) * bits.as_int()
    if bits.as_int() not in (4, 5, 6):
        return
    if entropy < 64:
        yield Hit(f"session IDs carry ~{entropy} bits of entropy", (length, bits))
    elif entropy < 128:
        yield Hit(f"session IDs carry ~{entropy} bits of entropy", (length, bits), severity=LOW)


@rule(
    "SESS-009",
    "Session files stored in a shared or listable directory",
    severity=MEDIUM,
    directives=("session.save_path", "session.save_handler"),
    sapis=WEB_SAPIS,
    cwe="CWE-552",
    description="Session files are named after the session ID. In a directory other users can list (such as "
    "/tmp), they can harvest IDs and hijack sessions, or plant crafted session files.",
    recommendation="Use a dedicated session directory such as /var/lib/php/sessions with mode 1733 or 0700.",
)
def session_storage(ctx):
    handler = ctx.get("session.save_handler")
    if handler.text.lower() != "files":
        return
    setting = ctx.get("session.save_path")
    directory = session_dir(setting.text)
    if ctx.paths is not None and directory.startswith("/"):
        info = ctx.paths.fs.stat(directory)
        if info is not None and info.st_mode & stat.S_IROTH:
            yield Hit(f"{directory} can be listed by every local user", (setting,))
            return
        if info is not None:
            return
    if directory in _SHARED_TEMP:
        shown = directory or "the system temp directory"
        yield Hit(f"session files are written to {shown}", (setting,), confidence=Confidence.MEDIUM)


@rule(
    "SESS-010",
    "Session files created with permissive mode",
    severity=MEDIUM,
    directives=("session.save_path",),
    cwe="CWE-276",
    description="session.save_path = \"N;MODE;/path\" sets the file mode of session files; group or world access "
    "exposes session contents.",
    recommendation="Use mode 600 (the default).",
)
def session_file_mode(ctx):
    setting = ctx.get("session.save_path")
    parts = setting.text.split(";")
    if len(parts) != 3:
        return
    mode = values.parse_octal(parts[1].strip())
    if mode is None:
        return
    if mode & 0o007:
        yield Hit(f"session files are created with mode {parts[1].strip()}", (setting,))
    elif mode & 0o070:
        yield Hit(f"session files are created with mode {parts[1].strip()}", (setting,), severity=LOW)


@rule(
    "SESS-011",
    "Long-lived sessions",
    severity=LOW,
    directives=("session.gc_maxlifetime",),
    sapis=WEB_SAPIS,
    cwe="CWE-613",
    description="Session data is kept for gc_maxlifetime seconds of inactivity; long lifetimes widen the "
    "window for stolen session IDs.",
    recommendation="Keep session.gc_maxlifetime at a few hours or less and implement absolute timeouts in the "
    "application.",
)
def gc_maxlifetime(ctx):
    setting = ctx.get("session.gc_maxlifetime")
    if setting.as_int() > 86400:
        yield Hit(f"{setting.describe()} seconds (> 1 day)", (setting,))


@rule(
    "SESS-012",
    "Default session cookie name",
    severity=INFO,
    directives=("session.name",),
    sapis=WEB_SAPIS,
    cwe="CWE-200",
    description="PHPSESSID identifies the backend as PHP.",
    recommendation="Choose an application-specific session.name.",
)
def session_name(ctx):
    setting = ctx.get("session.name")
    if setting.text == "PHPSESSID":
        yield Hit("session.name is PHPSESSID", (setting,))


@rule(
    "SESS-013",
    "Persistent session cookie",
    severity=INFO,
    directives=("session.cookie_lifetime",),
    sapis=WEB_SAPIS,
    cwe="CWE-539",
    description="A non-zero cookie_lifetime stores the session cookie on disk in the browser.",
    recommendation="Use session.cookie_lifetime = 0 and handle \"remember me\" separately.",
)
def cookie_lifetime(ctx):
    setting = ctx.get("session.cookie_lifetime")
    if setting.as_int() > 0:
        yield Hit(f"{setting.describe()} seconds", (setting,))


@rule(
    "SESS-014",
    "Session cookie shared with other hosts",
    severity=INFO,
    directives=("session.cookie_domain",),
    sapis=WEB_SAPIS,
    cwe="CWE-565",
    description="A cookie_domain makes the session cookie visible to every subdomain, so one compromised "
    "subdomain can read or overwrite it.",
    recommendation="Leave session.cookie_domain empty unless sessions must span subdomains.",
)
def cookie_domain(ctx):
    setting = ctx.get("session.cookie_domain")
    if setting.text:
        yield Hit(setting.describe(), (setting,))
