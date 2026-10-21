import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from php_ini_audit.cli import main
from php_ini_audit.fsutil import FileSystem, ReadError

from .helpers import FIXTURES

SRC = Path(__file__).resolve().parent.parent / "src"


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class DebianFixtureTest(unittest.TestCase):
    def setUp(self):
        code, out, _ = run_cli("--root", str(FIXTURES / "debian"), "--format", "json")
        self.assertEqual(code, 0)
        self.report = json.loads(out)
        self.ids = {(f["rule_id"], f["target"]) for f in self.report["findings"]}

    def test_targets(self):
        names = [t["name"] for t in self.report["targets"]]
        self.assertIn("/etc/php/8.2/cli/php.ini", names)
        self.assertIn("/etc/php/8.2/fpm/php.ini", names)
        self.assertTrue(any("pool [www]" in n for n in names))
        self.assertTrue(any("[PATH=/var/www/legacy]" in n for n in names))
        fpm = next(t for t in self.report["targets"] if t["name"] == "/etc/php/8.2/fpm/php.ini")
        self.assertEqual(fpm["php_version"], "8.2.7")
        self.assertEqual(fpm["sapi"], "fpm")

    def test_pool_findings_belong_to_pool(self):
        pool_rules = {rid for rid, target in self.ids if "pool [www]" in target}
        self.assertTrue({"FPM-001", "FPM-002", "FPM-003", "FPM-004", "FPM-007", "FS-002", "ERR-001"} <= pool_rules)
        self.assertNotIn("SESS-001", pool_rules)

    def test_scan_dir_override_wins(self):
        fpm_rules = {rid for rid, target in self.ids if target == "/etc/php/8.2/fpm/php.ini"}
        self.assertNotIn("ERR-001", fpm_rules)
        self.assertIn("EXT-001", fpm_rules)

    def test_summary_counts_every_severity(self):
        self.assertEqual(set(self.report["summary"]["by_severity"]), {"critical", "high", "medium", "low", "info"})


class DockerFixtureTest(unittest.TestCase):
    def test_missing_php_ini(self):
        code, out, _ = run_cli("--root", str(FIXTURES / "docker"), "--format", "json")
        report = json.loads(out)
        ids = {f["rule_id"] for f in report["findings"]}
        self.assertIn("CFG-006", ids)
        self.assertIn("EXEC-011", ids)
        self.assertIn("FPM-001", ids)


class WebrootFixtureTest(unittest.TestCase):
    def test_overlays(self):
        code, out, _ = run_cli(str(FIXTURES / "webroot"), "--format", "json")
        report = json.loads(out)
        ids = {f["rule_id"] for f in report["findings"]}
        self.assertTrue({"HTA-001", "CFG-005", "EXEC-004"} <= ids)
        self.assertNotIn("FS-001", ids)


class CliTest(unittest.TestCase):
    def test_fail_on(self):
        code, _, _ = run_cli("--root", str(FIXTURES / "debian"), "--fail-on", "critical")
        self.assertEqual(code, 1)
        code, _, _ = run_cli(str(FIXTURES / "hardened" / "php.ini"), "--fail-on", "low")
        self.assertEqual(code, 0)

    def test_sarif(self):
        code, out, _ = run_cli("--root", str(FIXTURES / "debian"), "--format", "sarif")
        sarif = json.loads(out)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])

    def test_rules_command(self):
        code, out, _ = run_cli("rules", "--format", "json")
        self.assertEqual(code, 0)
        self.assertGreater(len(json.loads(out)), 50)
        code, _, err = run_cli("rules", "NOPE-001")
        self.assertEqual(code, 2)

    def test_unknown_selector(self):
        code, _, err = run_cli(str(FIXTURES / "hardened"), "--only", "BOGUS")
        self.assertEqual(code, 2)

    def test_discover(self):
        code, out, _ = run_cli("discover", "--root", str(FIXTURES / "debian"))
        self.assertIn("/etc/php/8.2/fpm/pool.d/www.conf", out)


class ProcessTest(unittest.TestCase):
    """The installed entry point, run as a separate process."""

    def run_module(self, *argv):
        env = dict(os.environ, PYTHONPATH=str(SRC), NO_COLOR="1")
        return subprocess.run([sys.executable, "-m", "php_ini_audit", *argv], capture_output=True, text=True,
                              env=env, timeout=60)

    def test_exit_codes(self):
        debian = str(FIXTURES / "debian")
        self.assertEqual(self.run_module("--root", debian).returncode, 0)
        self.assertEqual(self.run_module("--root", debian, "--fail-on", "high").returncode, 1)
        self.assertEqual(self.run_module("--root", debian, "--fail-on", "bogus").returncode, 2)
        self.assertEqual(self.run_module("--root", str(FIXTURES / "missing")).returncode, 2)

    def test_output_file_keeps_stdout_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp, "report.sarif")
            done = self.run_module("--root", str(FIXTURES / "debian"), "--format", "sarif", "-o", str(report))
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(done.stdout, "")
            self.assertTrue(json.loads(report.read_text())["runs"][0]["results"])

    def test_missing_path_is_a_warning(self):
        done = self.run_module(str(FIXTURES / "hardened" / "php.ini"), str(FIXTURES / "nope.ini"), "--format", "json")
        self.assertEqual(done.returncode, 0)
        warnings = json.loads(done.stdout)["warnings"]
        self.assertTrue(any("nope.ini" in w for w in warnings), warnings)

    def test_text_report_is_plain_when_piped(self):
        done = self.run_module("--root", str(FIXTURES / "debian"))
        self.assertNotIn("\033[", done.stdout)
        self.assertIn("Summary", done.stdout)


@unittest.skipIf(os.name == "nt", "POSIX permissions and symlinks")
class FilesystemSafetyTest(unittest.TestCase):
    def test_symlinks_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as root:
            secret = Path(outside, "secret.ini")
            secret.write_text("x = 1\n")
            os.makedirs(Path(root, "etc"))
            os.symlink(str(secret), Path(root, "etc", "php.ini"))
            fs = FileSystem(root)
            self.assertEqual(fs.resolve("/etc/php.ini"), str(secret))
            with self.assertRaises(ReadError):
                fs.read_text("/etc/php.ini")

    def test_fifo_is_not_read(self):
        with tempfile.TemporaryDirectory() as root:
            fifo = Path(root, "php.ini")
            os.mkfifo(fifo)
            with self.assertRaises(ReadError):
                FileSystem().read_text(str(fifo))

    def test_world_writable_config_and_paths(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "etc").mkdir()
            shared = Path(root, "srv", "shared")
            shared.mkdir(parents=True)
            os.chmod(shared, 0o777)
            ini = Path(root, "etc", "php.ini")
            ini.write_text("opcache.file_cache = /srv/shared\nerror_log = /srv/www/public/php.log\n")
            os.chmod(ini, 0o666)
            os.chmod(Path(root, "etc"), 0o755)
            code, out, _ = run_cli("--root", root, "--ini", "/etc/php.ini", "--path-checks", "on", "--format", "json")
            report = json.loads(out)
            ids = {f["rule_id"] for f in report["findings"]}
            self.assertIn("FS-011", ids)
            self.assertIn("FS-005", ids)
            self.assertIn("FS-006", ids)
            ww = next(f for f in report["findings"] if f["rule_id"] == "FS-005")
            self.assertIn("/srv/shared", ww["message"])
            os.chmod(shared, 0o755)


if __name__ == "__main__":
    unittest.main()
