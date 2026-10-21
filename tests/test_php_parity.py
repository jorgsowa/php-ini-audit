"""Differential tests: the scanner's effective configuration must match what real PHP resolves.

Runs against every php-cgi in $PHP_CGI (os.pathsep-separated) or on PATH; skipped when none is found.
"""

import tempfile
import unittest
from pathlib import Path

from php_ini_audit import directives, values
from php_ini_audit.discovery import Discoverer, Discovery
from php_ini_audit.engine import Auditor, Options
from php_ini_audit.fsutil import FileSystem

from . import php_oracle

BINARIES = php_oracle.cgi_binaries()

# Defaults that depend on how PHP was built rather than on PHP itself.
BUILD_DEPENDENT = {
    "curl.cainfo",
    "extension_dir",
    "include_path",
    "mysqli.default_socket",
    "openssl.cafile",
    "openssl.capath",
    "pdo_mysql.default_socket",
    "sendmail_path",
    # Debian patches the compiled-in default to /var/lib/php/sessions.
    "session.save_path",
}
# The table stores the effective value where PHP's INI entry is NULL.
EFFECTIVE_DEFAULTS = {"error_reporting"}
# (directive, first version, first version no longer affected or None, PHP's default there).
# The table models the current stable branches; these are the documented departures from it.
VERSIONED_DEFAULTS = (
    ("assert.exception", (0,), (8, 0), "0"),
    ("display_startup_errors", (0,), (8, 0), "0"),
    ("date.timezone", (8, 2), None, "UTC"),
    ("opcache.jit", (8, 0), (8, 4), "tracing"),
    ("opcache.jit", (8, 4), None, "disable"),
    ("opcache.jit_buffer_size", (8, 4), None, "64M"),
    ("opcache.jit_hot_loop", (8, 4), None, "61"),
    ("register_argc_argv", (8, 5), None, "0"),
    ("session.cookie_httponly", (8, 6), None, "1"),
    ("session.cookie_samesite", (8, 6), None, "Lax"),
    ("session.use_strict_mode", (8, 6), None, "1"),
)
PHP_INI_PERDIR = 2


def versioned_default(name, version):
    for directive, since, until, value in VERSIONED_DEFAULTS:
        if directive == name and since <= version and (until is None or version < until):
            return value
    return None


def scanner_targets(ini=None, scan_dir=None, user_ini=None, sapi="cgi"):
    fs = FileSystem()
    discoverer = Discoverer(fs)
    discovery = Discovery()
    if ini or scan_dir:
        directory = str(Path(ini).parent) if ini else str(scan_dir)
        discovery.installations.append(
            discoverer.build(str(ini) if ini else None, directory, scan_dirs=[str(scan_dir)] if scan_dir else [])
        )
    if user_ini:
        discovery.user_inis.append(str(user_ini))
    return Auditor(fs, Options(sapi=sapi, path_checks=False)).build_targets(discovery)


def comparable(name, value):
    if name == "error_reporting":
        return values.eval_error_reporting(value)
    return value


def write_files(root, files):
    for name, content in files.items():
        path = Path(root, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


# Each case is a php.ini and an optional scan dir; every directive the scanner resolves is compared.
LAYERING_CASES = {
    "quoting": {
        "php.ini": (
            'default_charset = "ISO-8859-1"\n'
            "arg_separator.output = '&amp;'\n"
            'error_prepend_string = "<b>quoted ; not a comment</b>"\n'
            'error_append_string = "say \\"hi\\""\n'
            'user_agent = "a" b "c"\n'
            "date.timezone = Europe/Warsaw ; trailing comment\n"
            "precision =   12   \n"
            'docref_root = ""\n'
        ),
    },
    "booleans": {
        "php.ini": (
            "display_errors = On\n"
            "log_errors = yes\n"
            "html_errors = true\n"
            "expose_php = Off\n"
            "allow_url_fopen = no\n"
            "file_uploads = false\n"
            "enable_dl = None\n"
            "short_open_tag = 0\n"
            "implicit_flush = 1\n"
            'auto_globals_jit = "Off"\n'
            "ignore_user_abort = TRUE\n"
            "session.use_strict_mode = on\n"
        ),
    },
    "sizes_and_lists": {
        "php.ini": (
            "memory_limit = 256M\n"
            "post_max_size = 1G\n"
            "upload_max_filesize = 512k\n"
            "disable_functions = exec, system,shell_exec\n"
            'variables_order = "GPCS"\n'
        ),
    },
    "error_reporting": {
        "php.ini": "error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT\n",
    },
    "error_reporting_numeric": {
        "php.ini": "error_reporting = 22519\n",
    },
    "error_reporting_grouping": {
        "php.ini": "error_reporting = (E_ERROR | E_WARNING) & ~E_NOTICE\n",
    },
    "multiline_quoted": {
        "php.ini": 'error_append_string = "line one\nline two"\nprecision = 10\n',
    },
    "duplicates_last_wins": {
        "php.ini": "memory_limit = 64M\n[Session]\nmemory_limit = 96M\n[PHP]\nmemory_limit = 128M\n",
    },
    "scan_dir_order": {
        "php.ini": "memory_limit = 64M\ndisplay_errors = On\nprecision = 10\n",
        "conf.d/20-b.ini": "memory_limit = 96M\nprecision = 11\n",
        "conf.d/10-a.ini": "memory_limit = 80M\ndisplay_errors = Off\n",
        "conf.d/99-z.ini": "precision = 13\n",
        "conf.d/notes.txt": "precision = 99\n",
    },
    "scan_dir_only": {
        "conf.d/00-base.ini": "memory_limit = 200M\nexpose_php = Off\n",
    },
    "unknown_and_removed": {
        # Fatal-on-startup removed directives such as safe_mode are left out: PHP refuses to run with them.
        "php.ini": "session.hash_function = 1\nmy_custom.setting = 5\nmemory_limit = 64M\n",
    },
}


@unittest.skipUnless(BINARIES, "php-cgi not found; set PHP_CGI to run parity tests")
class DirectiveTableParityTest(unittest.TestCase):
    maxDiff = None

    def test_defaults_and_per_dir_modes(self):
        for binary in BINARIES:
            with self.subTest(binary=binary):
                report = php_oracle.run(binary, all_entries=True)
                version = php_oracle.version_tuple(report["version"])
                problems = []
                for name, (default, mode) in sorted(directives.KNOWN.items()):
                    entry = report["all"].get(name)
                    if entry is None:
                        continue
                    php_default = entry["global_value"]
                    if bool(entry["access"] & PHP_INI_PERDIR) != bool(mode & directives.Mode.PERDIR):
                        problems.append(f"{name}: per-dir changeable is {bool(entry['access'] & PHP_INI_PERDIR)} in PHP")
                    if name in BUILD_DEPENDENT or name in EFFECTIVE_DEFAULTS:
                        continue
                    if php_default == default or (php_default is None and default == ""):
                        continue
                    if versioned_default(name, version) == php_default:
                        continue
                    problems.append(f"{name}: table {default!r}, PHP {report['version']} {php_default!r}")
                self.assertEqual(problems, [])

    def test_effective_error_reporting_default(self):
        for binary in BINARIES:
            with self.subTest(binary=binary):
                report = php_oracle.run(binary, names=["error_reporting"])
                if php_oracle.version_tuple(report["version"]) < (8, 0):
                    continue
                expected = values.eval_error_reporting(directives.default("error_reporting"))
                self.assertIn(report["values"]["error_reporting"], (None, "", str(expected)))


@unittest.skipUnless(BINARIES, "php-cgi not found; set PHP_CGI to run parity tests")
class LayeringParityTest(unittest.TestCase):
    maxDiff = None

    def assert_same_view(self, binary, files):
        with tempfile.TemporaryDirectory() as tmp:
            write_files(tmp, files)
            ini = Path(tmp, "php.ini") if "php.ini" in files else None
            scan_dir = Path(tmp, "conf.d") if any(n.startswith("conf.d/") for n in files) else None
            config = scanner_targets(ini, scan_dir)[0].config
            settings = [s for s in config.explicit() if not s.unresolved]
            self.assertTrue(settings)
            report = php_oracle.run(binary, ini=ini or Path(tmp, "missing.ini"), scan_dir=scan_dir,
                                    names=[s.name for s in settings])
            mismatches = {}
            for setting in settings:
                php_value = report["values"][setting.name]
                # Unknown to this build: removed directive, custom name or extension not loaded.
                if php_value is False:
                    continue
                if comparable(setting.name, setting.value) != comparable(setting.name, php_value):
                    mismatches[setting.name] = (setting.value, php_value)
            self.assertEqual(mismatches, {}, "scanner value vs PHP value")

    def test_cases(self):
        for binary in BINARIES:
            for case, files in LAYERING_CASES.items():
                with self.subTest(binary=binary, case=case):
                    self.assert_same_view(binary, files)


@unittest.skipUnless(BINARIES, "php-cgi not found; set PHP_CGI to run parity tests")
class OverlayParityTest(unittest.TestCase):
    def test_path_section_applies_to_requests_below_it(self):
        for binary in BINARIES:
            with self.subTest(binary=binary), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                docroot = root / "www"
                ini = root / "php.ini"
                ini.write_text(
                    "memory_limit = 64M\nprecision = 10\n"
                    f"[PATH={docroot}/legacy]\nmemory_limit = 99M\ndisplay_errors = On\n"
                    f"[PATH={docroot}/other]\nprecision = 3\n"
                )
                targets = scanner_targets(ini)
                legacy = next(t for t in targets if t.overlay and "legacy" in t.overlay)
                names = ["memory_limit", "precision", "display_errors"]
                report = php_oracle.run(binary, ini=ini, names=names, script_dir=docroot / "legacy" / "app",
                                        document_root=docroot)
                for name in names:
                    self.assertEqual(legacy.config.get(name).value, report["values"][name], name)

    def test_user_ini_applies_only_per_dir_directives(self):
        requested = {
            "memory_limit": "33M",
            "precision": "7",
            "upload_max_filesize": "64M",
            "session.upload_progress.enabled": "0",
            "disable_functions": "phpinfo",
            "allow_url_fopen": "0",
            "expose_php": "0",
            "user_ini.filename": "evil.ini",
        }
        for binary in BINARIES:
            with self.subTest(binary=binary), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                # open_basedir is per-dir changeable; it must still allow the dump script.
                overlay = dict(requested, open_basedir=str(root))
                docroot = root / "www"
                app = docroot / "app"
                app.mkdir(parents=True)
                ini = root / "php.ini"
                ini.write_text("memory_limit = 64M\ndisable_functions = exec\nallow_url_fopen = On\n")
                user_ini = app / ".user.ini"
                user_ini.write_text("".join(f"{name} = {value}\n" for name, value in overlay.items()))
                targets = scanner_targets(ini, user_ini=user_ini)
                target = next(t for t in targets if t.overlay)
                ineffective = {d.name for d in target.config.ineffective}
                report = php_oracle.run(binary, ini=ini, names=list(overlay), script_dir=app, document_root=docroot)
                for name, value in overlay.items():
                    php_value = report["values"][name]
                    if php_value is False:
                        continue
                    applied_by_php = php_value == value
                    self.assertEqual(name not in ineffective, applied_by_php, name)
                    self.assertEqual(target.config.get(name).value, php_value, name)


if __name__ == "__main__":
    unittest.main()
