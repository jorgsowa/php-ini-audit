import unittest

from php_ini_audit.model import SourceKind
from php_ini_audit.parser import parse_fpm, parse_htaccess, parse_ini, scan_value


class ScanValueTest(unittest.TestCase):
    def test_bare_booleans_are_normalised(self):
        self.assertEqual(scan_value(" On ; comment")[0], "1")
        self.assertEqual(scan_value(" None")[0], "")
        self.assertEqual(scan_value(' "None"')[0], "None")

    def test_quotes_and_comments(self):
        self.assertEqual(scan_value(' "N;0700;/tmp" ; trailing')[0], "N;0700;/tmp")
        self.assertEqual(scan_value(" N;0700;/tmp")[0], "N")
        self.assertEqual(scan_value(" 'a;b'")[0], "a;b")
        self.assertEqual(scan_value(' "C:\\\\php\\\\ext"')[0], "C:\\php\\ext")

    def test_env_reference_is_flagged(self):
        value, unresolved, _ = scan_value(" ${MEMORY}")
        self.assertEqual(value, "${MEMORY}")
        self.assertTrue(unresolved)

    def test_unterminated_quote(self):
        self.assertTrue(scan_value(' "open')[2])


class ParseIniTest(unittest.TestCase):
    def test_directives_sections_and_issues(self):
        text = (
            "[PHP]\n"
            "display_errors = Off\n"
            "# hash comment\n"
            "garbage line\n"
            "include_path = \".:/a\n:/b\"\n"
            "[PATH=/var/www/x]\n"
            "allow_url_fopen = On\n"
        )
        parsed = parse_ini(text, "/etc/php.ini", SourceKind.PHP_INI)
        names = [d.name for d in parsed.directives]
        self.assertEqual(names, ["display_errors", "include_path", "allow_url_fopen"])
        self.assertEqual(parsed.directives[1].value, ".:/a\n:/b")
        self.assertEqual(len(parsed.issues), 2)
        self.assertEqual([d.name for d in parsed.base_directives], ["display_errors", "include_path"])
        self.assertEqual(parsed.conditional_sections[0][0], "PATH=/var/www/x")
        self.assertEqual(parsed.directives[0].location.line, 2)


class ParseFpmTest(unittest.TestCase):
    def test_pools(self):
        text = (
            "[global]\nerror_log = /var/log/fpm.log\n"
            "[www]\nlisten = /run/php.sock\n"
            "php_admin_value[disable_functions] = exec\n"
            "php_flag[display_errors] = off\n"
            "env[TOKEN] = abc\n"
        )
        parsed = parse_fpm(text, "/etc/php-fpm.d/www.conf")
        self.assertIn("error_log", parsed.global_settings)
        pool = parsed.pools[0]
        self.assertEqual(pool.name, "www")
        self.assertEqual(pool.settings["listen"].value, "/run/php.sock")
        self.assertEqual([(d.name, d.value, d.admin) for d in pool.php],
                         [("disable_functions", "exec", True), ("display_errors", "", False)])
        self.assertEqual(pool.env[0].name, "TOKEN")


class ParseHtaccessTest(unittest.TestCase):
    def test_php_directives_and_handlers(self):
        text = (
            "php_flag display_errors on\n"
            "php_value auto_prepend_file \"/tmp/x.php\"\n"
            "php_admin_flag engine off\n"
            "AddHandler application/x-httpd-php .php .png\n"
            "<FilesMatch \"\\.txt$\">\nSetHandler application/x-httpd-php\n</FilesMatch>\n"
        )
        parsed = parse_htaccess(text, "/var/www/.htaccess")
        self.assertEqual([(d.name, d.value) for d in parsed.directives],
                         [("display_errors", "1"), ("auto_prepend_file", "/tmp/x.php")])
        self.assertEqual(len(parsed.issues), 1)
        self.assertEqual(parsed.handlers[0].extensions, (".php", ".png"))
        self.assertEqual(parsed.handlers[1].files_pattern, "\\.txt$")


if __name__ == "__main__":
    unittest.main()
