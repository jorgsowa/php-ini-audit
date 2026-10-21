import datetime
import json
import os
import tempfile
import unittest
from pathlib import Path

from php_ini_audit.fsutil import FileSystem
from php_ini_audit.model import Confidence, Severity
from php_ini_audit.rules.base import Context
from php_ini_audit.rules.vulnerabilities import ADVISORIES, end_of_life
from php_ini_audit.versions import VersionEvidence, VersionFinder, pick

from .helpers import FIXTURES, audit_ini, findings_for
from .test_integration import run_cli

ADVISORY = {a.cve: a for a in ADVISORIES}


class AdvisoryStatusTest(unittest.TestCase):
    def test_patch_levels(self):
        cgi = ADVISORY["CVE-2024-4577"]
        self.assertEqual(cgi.status((8, 3, 7)), "affected")
        self.assertEqual(cgi.status((8, 3, 8)), "fixed")
        self.assertEqual(cgi.status((8, 3)), "possible")
        self.assertEqual(cgi.status((8, 4, 0)), "fixed")
        self.assertEqual(cgi.status((8, 0, 30)), "untracked")

    def test_end_of_life_branch_between_fixes_is_affected(self):
        wrapper = ADVISORY["CVE-2026-91766"]
        self.assertEqual(wrapper.status((8, 2, 33)), "affected")
        multipart = ADVISORY["CVE-2023-0662"]
        self.assertEqual(multipart.status((8, 1, 15)), "affected")
        self.assertEqual(multipart.fixed_for((8, 1, 15)), "8.1.16")

    def test_every_advisory_is_registered(self):
        from php_ini_audit.rules import REGISTRY

        for cve in ADVISORY:
            self.assertIn(cve, REGISTRY)


class EndOfLifeTest(unittest.TestCase):
    def hits(self, version, today):
        ctx = Context(config=None, sapi="fpm", profile="production", php_version=version)
        return list(end_of_life(ctx, today=today))

    def test_dates(self):
        self.assertIn("ended on 2023-11-26", self.hits((8, 0, 30), datetime.date(2026, 1, 1))[0].message)
        warning = self.hits((8, 2), datetime.date(2026, 10, 21))[0]
        self.assertEqual(warning.severity, Severity.LOW)
        self.assertEqual(self.hits((8, 4), datetime.date(2026, 10, 21)), [])
        self.assertEqual(self.hits((5, 4, 45), datetime.date(2026, 1, 1))[0].severity, Severity.CRITICAL)


class ConfigurationGatingTest(unittest.TestCase):
    def test_cve_requires_feature(self):
        exposed = audit_ini("allow_url_fopen = On\n", php_version=(8, 3, 6))
        self.assertTrue(findings_for(exposed, "CVE-2025-1861"))
        closed = audit_ini("allow_url_fopen = Off\n", php_version=(8, 3, 6))
        self.assertFalse(findings_for(closed, "CVE-2025-1861"))
        patched = audit_ini("allow_url_fopen = On\n", php_version=(8, 3, 19))
        self.assertFalse(findings_for(patched, "CVE-2025-1861"))

    def test_pool_cves(self):
        result = audit_ini("", files={"pool.d/www.conf": "[www]\nlisten = 127.0.0.1:9000\n"
                                      "listen.allowed_clients = 127.0.0.1\npm.status_path = /status\n"
                                      "catch_workers_output = yes\n"}, php_version=(8, 3, 10))
        for cve in ("CVE-2026-91768", "CVE-2026-6735", "CVE-2024-9026"):
            self.assertTrue(findings_for(result, cve), cve)

    def test_unknown_patch_is_summarised(self):
        result = audit_ini("allow_url_fopen = On\n", php_version=(8, 3))
        self.assertFalse(findings_for(result, "CVE-2025-1861"))
        summary = findings_for(result, "VULN-002")[0]
        self.assertIn("CVE-2025-1861 (fixed in 8.3.19)", summary.message)

    def test_cookie_prefix(self):
        result = audit_ini("session.name = __Host-SID\n", php_version=(8, 2, 17))
        self.assertTrue(findings_for(result, "CVE-2024-2756"))


class VersionFinderTest(unittest.TestCase):
    def test_sources(self):
        with tempfile.TemporaryDirectory() as root:
            header = Path(root, "usr/include/php/20230831/main")
            header.mkdir(parents=True)
            (header / "php_version.h").write_text('#define PHP_VERSION "8.3.12"\n')
            apk = Path(root, "lib/apk/db")
            apk.mkdir(parents=True)
            (apk / "installed").write_text("P:php82\nV:8.2.20-r0\n\nP:musl\nV:1.2.4-r2\n")
            cellar = Path(root, "opt/homebrew/Cellar/php/8.4.3")
            cellar.mkdir(parents=True)
            Path(root, "opt/homebrew/opt").mkdir(parents=True)
            os.symlink("../Cellar/php/8.4.3", Path(root, "opt/homebrew/opt/php"))
            found = {(e.version, e.backports) for e in VersionFinder(FileSystem(root)).collect()}
            self.assertEqual(found, {((8, 3, 12), False), ((8, 2, 20), False), ((8, 4, 3), False)})

    def test_dpkg_marks_backports(self):
        found = VersionFinder(FileSystem(str(FIXTURES / "debian"))).collect()
        self.assertEqual({(e.version, e.backports) for e in found}, {((8, 2, 7), True)})

    def test_ambiguous_branch(self):
        evidence = [VersionEvidence((8, 2, 1), "/opt/a/x.h"), VersionEvidence((8, 2, 9), "/opt/b/x.h")]
        self.assertIsNone(pick(evidence, (8, 2)))
        self.assertEqual(pick(evidence, (8, 2), near="/opt/b/etc/php.ini").version, (8, 2, 9))


class FixtureTest(unittest.TestCase):
    def report(self, *argv):
        code, out, _ = run_cli(*argv, "--format", "json")
        self.assertEqual(code, 0)
        return json.loads(out)

    def test_docker_header_version(self):
        report = self.report("--root", str(FIXTURES / "docker"))
        self.assertEqual(report["targets"][0]["php_version"], "8.3.6")
        ids = {f["rule_id"] for f in report["findings"]}
        self.assertTrue({"CVE-2025-1861", "CVE-2024-8925"} <= ids)
        self.assertNotIn("CVE-2024-8927", ids)

    def test_debian_backports_lower_confidence(self):
        report = self.report("--root", str(FIXTURES / "debian"))
        cves = [f for f in report["findings"] if f["rule_id"].startswith("CVE-")]
        self.assertTrue(cves)
        self.assertTrue(all(f["confidence"] == str(Confidence.LOW) for f in cves))

    def test_windows_cgi(self):
        report = self.report(str(FIXTURES / "windows-xampp" / "php.ini"), "--php-version", "8.3.7")
        finding = next(f for f in report["findings"] if f["rule_id"] == "CVE-2024-4577")
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["confidence"], "medium")


if __name__ == "__main__":
    unittest.main()
