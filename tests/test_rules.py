import unittest

from php_ini_audit.model import Confidence, Severity
from php_ini_audit.rules import REGISTRY

from .helpers import audit_ini, findings_for, rule_ids

HARDENED = (
    "expose_php = Off\ndisplay_errors = Off\ndisplay_startup_errors = Off\nlog_errors = On\n"
    "zend.exception_ignore_args = On\nzend.assertions = -1\nvariables_order = GPCS\nregister_argc_argv = Off\n"
    "enable_dl = Off\nallow_url_fopen = Off\nfile_uploads = Off\nopen_basedir = /srv/app/\n"
    "disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,putenv,mail,"
    "mb_send_mail,imap_mail,error_log,phpinfo\ninclude_path = /usr/share/php\nuser_ini.filename =\n"
    "session.save_path = /var/lib/php/sessions\nsession.use_strict_mode = 1\nsession.cookie_httponly = 1\n"
    "session.cookie_secure = 1\nsession.cookie_samesite = Lax\nsession.name = APP\n"
    "session.upload_progress.enabled = Off\ncgi.fix_pathinfo = 0\nopcache.restrict_api = /srv/app/admin/\n"
    "opcache.validate_permission = 1\nopcache.validate_root = 1\n"
)


class RegistryTest(unittest.TestCase):
    def test_every_rule_is_documented(self):
        for rule in REGISTRY.values():
            self.assertTrue(rule.description and rule.recommendation, rule.id)
            self.assertIn(rule.scope, ("config", "file", "pool"), rule.id)
            self.assertRegex(rule.id, r"^[A-Z]+-\d{3}$")


class DefaultsTest(unittest.TestCase):
    def test_empty_config_reports_insecure_builtin_defaults(self):
        result = audit_ini("")
        ids = rule_ids(result)
        for expected in ("ERR-001", "EXEC-011", "EXEC-005", "FS-001", "SESS-001", "SESS-005", "ERR-004"):
            self.assertIn(expected, ids)
        display = findings_for(result, "ERR-001")[0]
        self.assertTrue(display.from_default)
        self.assertIsNone(display.location)

    def test_hardened_config_is_quiet(self):
        result = audit_ini(HARDENED)
        self.assertEqual([f.rule_id for f in result.findings if f.severity >= Severity.LOW], [])

    def test_report_is_not_binary(self):
        result = audit_ini("allow_url_include = On\ndisplay_errors = On\n")
        severities = {f.severity for f in result.findings}
        self.assertGreaterEqual(len(severities), 3)
        self.assertGreater(len(result.findings), 10)


class ExecutionRulesTest(unittest.TestCase):
    def test_allow_url_include_depends_on_fopen(self):
        on = findings_for(audit_ini("allow_url_include = On\n"), "EXEC-001")[0]
        self.assertEqual(on.severity, Severity.CRITICAL)
        off = findings_for(audit_ini("allow_url_include = On\nallow_url_fopen = Off\n"), "EXEC-001")[0]
        self.assertEqual(off.severity, Severity.HIGH)

    def test_prepend_wrappers(self):
        result = audit_ini("auto_prepend_file = php://input\n")
        self.assertEqual(findings_for(result, "EXEC-003")[0].severity, Severity.CRITICAL)
        self.assertEqual(findings_for(result, "EXEC-004"), [])

    def test_partial_disable_functions(self):
        finding = findings_for(audit_ini("disable_functions = exec,system\n"), "EXEC-005")[0]
        self.assertIn("proc_open", finding.message)
        self.assertNotIn("system,", finding.message)

    def test_ld_preload_bypass_only_when_exec_family_disabled(self):
        sandboxed = "disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec\n"
        self.assertIn("EXEC-006", rule_ids(audit_ini(sandboxed)))
        self.assertNotIn("EXEC-006", rule_ids(audit_ini("disable_functions = exec\n")))

    def test_sendmail_flags(self):
        result = audit_ini('sendmail_path = "/usr/sbin/sendmail -t -i -X /var/www/log.php"\n')
        self.assertIn("-X", findings_for(result, "EXEC-013")[0].message)


class ScopeTest(unittest.TestCase):
    def test_web_rules_skip_cli(self):
        result = audit_ini("display_errors = On\nmemory_limit = -1\n", sapi="cli")
        self.assertNotIn("ERR-001", rule_ids(result))
        self.assertNotIn("RES-001", rule_ids(result))

    def test_development_profile_downgrades(self):
        result = audit_ini("display_errors = On\n", profile="development")
        self.assertEqual(findings_for(result, "ERR-001")[0].severity, Severity.INFO)
        self.assertNotIn("EXEC-014", rule_ids(result))

    def test_unresolved_values_lower_confidence(self):
        result = audit_ini("allow_url_include = 1${ALLOW}\n")
        finding = findings_for(result, "EXEC-001")[0]
        self.assertEqual(finding.confidence, Confidence.LOW)
        self.assertIn("CFG-007", rule_ids(result))

    def test_min_severity_and_selection(self):
        result = audit_ini("", min_severity=Severity.MEDIUM, only=["SESS"])
        self.assertTrue(result.findings)
        self.assertTrue(all(f.rule_id.startswith("SESS-") and f.severity >= Severity.MEDIUM for f in result.findings))


class SessionRulesTest(unittest.TestCase):
    def test_unquoted_samesite_none(self):
        finding = findings_for(audit_ini("session.cookie_samesite = None\n"), "SESS-007")[0]
        self.assertIn("unquoted", finding.message)

    def test_samesite_none_without_secure(self):
        finding = findings_for(audit_ini('session.cookie_samesite = "None"\n'), "SESS-007")[0]
        self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_sid_entropy(self):
        weak = findings_for(audit_ini("session.sid_length = 22\nsession.sid_bits_per_character = 4\n"), "SESS-008")
        self.assertEqual(weak[0].severity, Severity.LOW)

    def test_session_file_mode(self):
        self.assertIn("SESS-010", rule_ids(audit_ini('session.save_path = "N;0666;/var/lib/php"\n')))


class FilesystemRulesTest(unittest.TestCase):
    def test_open_basedir_entries(self):
        result = audit_ini("open_basedir = /var/www:.:/\n")
        self.assertIn("/var/www", findings_for(result, "FS-003")[0].message)
        self.assertIn(".", findings_for(result, "FS-004")[0].message)
        self.assertIn("FS-002", rule_ids(result))


class HygieneRulesTest(unittest.TestCase):
    def test_typo_of_security_directive(self):
        finding = findings_for(audit_ini("expose_phpp = Off\n"), "CFG-003")[0]
        self.assertIn("expose_php", finding.message)
        self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_case_sensitive_names(self):
        self.assertIn("CFG-003", rule_ids(audit_ini("Display_Errors = Off\n")))

    def test_obsolete_register_globals(self):
        unknown = findings_for(audit_ini("register_globals = On\n"), "CFG-002")[0]
        self.assertEqual(unknown.severity, Severity.HIGH)
        modern = findings_for(audit_ini("register_globals = On\n", php_version=(8, 2)), "CFG-002")[0]
        self.assertEqual(modern.severity, Severity.INFO)
        legacy = findings_for(audit_ini("register_globals = On\n", php_version=(5, 3)), "CFG-002")[0]
        self.assertEqual(legacy.severity, Severity.CRITICAL)

    def test_scan_dir_override_is_reported(self):
        result = audit_ini("display_errors = On\n", files={"conf.d/99-x.ini": "display_errors = Off\n"})
        self.assertNotIn("ERR-001", rule_ids(result))
        self.assertIn("CFG-004", rule_ids(result))


class ExtensionRulesTest(unittest.TestCase):
    def test_xdebug_connect_back(self):
        result = audit_ini("zend_extension = xdebug.so\nxdebug.mode = debug\nxdebug.discover_client_host = 1\n")
        self.assertEqual(findings_for(result, "EXT-001")[0].severity, Severity.CRITICAL)
        self.assertEqual(findings_for(result, "EXT-002")[0].severity, Severity.HIGH)

    def test_multibyte_charset(self):
        self.assertEqual(findings_for(audit_ini("default_charset = SJIS\n"), "ENC-001")[0].severity, Severity.MEDIUM)


if __name__ == "__main__":
    unittest.main()
