import json
import tempfile
import unittest
from pathlib import Path

from php_ini_audit import phpinfo
from php_ini_audit.engine import Options

from .test_integration import run_cli

CLI_OUTPUT = """phpinfo()
PHP Version => 8.2.7-1~deb12u1

System => Linux web 6.1.0 x86_64
Server API => FPM/FastCGI
Loaded Configuration File => /etc/php/8.2/fpm/php.ini
Additional .ini files parsed => /etc/php/8.2/fpm/conf.d/10-opcache.ini,
/etc/php/8.2/fpm/conf.d/20-xdebug.ini

Core

Directive => Local Value => Master Value
allow_url_include => On => On
display_errors => STDOUT => STDOUT
open_basedir => no value => no value

session

Directive => Local Value => Master Value
session.use_strict_mode => Off => Off

xdebug

Directive => Local Value => Master Value
xdebug.mode => debug => debug
xdebug.discover_client_host => On => On
"""

HTML_OUTPUT = """<!DOCTYPE html><html><body><div class="center">
<table><tr class="h"><td><h1 class="p">PHP Version 8.3.12</h1></td></tr></table>
<table>
<tr><td class="e">System </td><td class="v">Windows NT WEB 10.0 build 20348 (Windows Server 2022) AMD64 </td></tr>
<tr><td class="e">Server API </td><td class="v">CGI/FastCGI </td></tr>
<tr><td class="e">Loaded Configuration File </td><td class="v">(none) </td></tr>
</table>
<h2><a name="module_core">Core</a></h2>
<table>
<tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">allow_url_fopen</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">error_log</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
<tr><td class="e">open_basedir</td><td class="v">C:\\inetpub &amp; data</td><td class="v"><i>no value</i></td></tr>
</table>
<h2><a name="module_zend+opcache">Zend OPcache</a></h2>
<table>
<tr><td class="e">opcache.restrict_api</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
</table>
</div></body></html>
"""

# Selecting the rendered page in a browser and copying it yields tab-separated cells.
COPIED_OUTPUT = (
    "PHP Version 8.3.12\n\nServer API\tApache 2.0 Handler\n\nCore\n\n"
    "Directive\tLocal Value\tMaster Value\nexpose_php\tOn\tOn\nmemory_limit\t-1\t128M\n"
)


def rule_ids(result):
    return {f.rule_id for f in result.findings}


class ParseTest(unittest.TestCase):
    def test_cli_output(self):
        info = phpinfo.parse(CLI_OUTPUT)
        target = phpinfo.build_target(info, Options())
        self.assertEqual(target.sapi, "fpm")
        self.assertEqual(target.php_version, (8, 2, 7))
        self.assertTrue(target.version_backports)
        self.assertEqual(target.files, ["/etc/php/8.2/fpm/php.ini", "/etc/php/8.2/fpm/conf.d/10-opcache.ini",
                                        "/etc/php/8.2/fpm/conf.d/20-xdebug.ini"])
        self.assertEqual(target.config.get("display_errors").value, "1")
        self.assertEqual(target.config.get("open_basedir").value, "")
        self.assertEqual(target.config.get("allow_url_include").location.line, 13)
        self.assertEqual({m for m, _ in info.modules}, {"core", "session", "xdebug"})

    def test_html_page(self):
        info = phpinfo.parse(HTML_OUTPUT)
        target = phpinfo.build_target(info, Options())
        self.assertEqual(target.php_version, (8, 3, 12))
        self.assertEqual(target.sapi, "cgi")
        self.assertEqual(target.platform, "windows")
        self.assertEqual(target.files, [])
        self.assertIsNotNone(target.defaults_reason)
        self.assertEqual(target.config.get("open_basedir").value, "C:\\inetpub & data")
        self.assertEqual(target.config.get("error_log").value, "")
        self.assertEqual({m for m, _ in info.modules}, {"core", "opcache"})

    def test_copied_page(self):
        target = phpinfo.build_target(phpinfo.parse(COPIED_OUTPUT), Options())
        self.assertEqual(target.sapi, "apache2")
        self.assertEqual(target.php_version, (8, 3, 12))
        self.assertEqual(target.config.get("memory_limit").value, "-1")

    def test_rejects_other_text(self):
        with self.assertRaises(ValueError):
            phpinfo.parse("<html><body><p>Hello</p></body></html>")


class AuditTest(unittest.TestCase):
    def test_findings(self):
        result = phpinfo.audit(CLI_OUTPUT)
        ids = rule_ids(result)
        self.assertTrue({"EXEC-001", "ERR-001", "SESS-001", "EXT-001", "EXT-002", "FS-001"} <= ids, ids)
        include = next(f for f in result.findings if f.rule_id == "EXEC-001")
        self.assertEqual(str(include.location), "phpinfo():13")
        self.assertFalse(result.path_checks)

    def test_directives_missing_from_phpinfo_are_not_reported(self):
        ids = rule_ids(phpinfo.audit(COPIED_OUTPUT))
        self.assertIn("RES-001", ids)
        self.assertIn("ERR-004", ids)
        # No session module in the dump, so session defaults must not produce findings.
        self.assertFalse({i for i in ids if i.startswith("SESS-")})

    def test_no_php_ini(self):
        self.assertIn("CFG-006", rule_ids(phpinfo.audit(HTML_OUTPUT)))

    def test_options_override(self):
        result = phpinfo.audit(CLI_OUTPUT, Options(sapi="cli", php_version=(8, 3, 0)))
        self.assertEqual(result.targets[0].sapi, "cli")
        self.assertEqual(result.targets[0].version_source, "--php-version")
        self.assertNotIn("FS-001", rule_ids(result))


class CliTest(unittest.TestCase):
    def test_phpinfo_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "info.html")
            path.write_text(HTML_OUTPUT)
            code, out, _ = run_cli("--phpinfo", str(path), "--format", "json", "--fail-on", "medium")
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out)["targets"][0]["name"], "phpinfo()")

    def test_not_phpinfo(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "php.ini")
            path.write_text("display_errors = On\n")
            code, _, err = run_cli("--phpinfo", str(path))
        self.assertEqual(code, 2)
        self.assertIn("no phpinfo()", err)


if __name__ == "__main__":
    unittest.main()
