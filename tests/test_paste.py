import unittest

from php_ini_audit import paste
from php_ini_audit.engine import Options

from .helpers import FIXTURES
from .test_phpinfo import CLI_OUTPUT, COPIED_OUTPUT, HTML_OUTPUT


def fixture(path):
    return (FIXTURES / path).read_text()


def rule_ids(result):
    return {f.rule_id for f in result.findings}


class DetectTest(unittest.TestCase):
    def test_kinds(self):
        cases = {
            "phpinfo": [CLI_OUTPUT, HTML_OUTPUT, COPIED_OUTPUT],
            "php.ini": [fixture("debian/etc/php/8.2/fpm/php.ini"), fixture("windows-xampp/php.ini"),
                        "display_errors = On\n"],
            "fpm": [fixture("debian/etc/php/8.2/fpm/pool.d/www.conf"),
                    fixture("docker/usr/local/etc/php-fpm.d/zz-docker.conf")],
            "htaccess": [fixture("webroot/uploads/.htaccess"), "php_flag display_errors on\n"],
        }
        for kind, texts in cases.items():
            for text in texts:
                with self.subTest(kind=kind, text=text[:40]):
                    self.assertEqual(paste.detect(text), kind)


class AuditTest(unittest.TestCase):
    def test_php_ini(self):
        kind, result = paste.audit("allow_url_include = On\n", options=Options(php_version=(8, 1, 0)))
        self.assertEqual(kind, "php.ini")
        include = next(f for f in result.findings if f.rule_id == "EXEC-001")
        self.assertEqual(str(include.location), "php.ini:1")
        self.assertIn("VULN-001", rule_ids(result))
        self.assertFalse(result.path_checks)

    def test_pool(self):
        kind, result = paste.audit(fixture("debian/etc/php/8.2/fpm/pool.d/www.conf"))
        self.assertEqual(kind, "fpm")
        self.assertTrue({"FPM-001", "FPM-004"} <= rule_ids(result))

    def test_htaccess(self):
        kind, result = paste.audit(fixture("webroot/uploads/.htaccess"))
        self.assertEqual(kind, "htaccess")
        self.assertIn("HTA-001", rule_ids(result))

    def test_user_ini_must_be_chosen(self):
        text = fixture("webroot/.user.ini")
        self.assertNotIn("CFG-005", rule_ids(paste.audit(text)[1]))
        kind, result = paste.audit(text, "user.ini")
        self.assertEqual(kind, "user.ini")
        self.assertIn("CFG-005", rule_ids(result))

    def test_phpinfo(self):
        kind, result = paste.audit(CLI_OUTPUT)
        self.assertEqual(kind, "phpinfo")
        self.assertEqual(result.targets[0].name, "phpinfo()")

    def test_rejects_empty_input(self):
        for text, kind in (("", None), ("just some words\n", None), ("display_errors = On\n", "phpinfo")):
            with self.subTest(text=text, kind=kind), self.assertRaises(ValueError):
                paste.audit(text, kind)

    def test_parse_version(self):
        self.assertEqual(paste.parse_version(" 8.3.12 "), (8, 3, 12))
        self.assertIsNone(paste.parse_version(""))
        with self.assertRaises(ValueError):
            paste.parse_version("8")


if __name__ == "__main__":
    unittest.main()
