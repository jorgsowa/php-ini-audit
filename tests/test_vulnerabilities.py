import datetime
import json
import os
import tempfile
import unittest
from pathlib import Path

from php_ini_audit.discovery import Discoverer
from php_ini_audit.engine import Auditor, Options
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

    def test_oom_path_reported_even_when_mitigated(self):
        finite = findings_for(audit_ini("post_max_size = 512M\n", php_version=(8, 4, 26)), "CVE-2026-109618")[0]
        self.assertEqual(finite.confidence, Confidence.HIGH)
        self.assertIn("post_max_size = 512M", finite.message)
        unlimited = audit_ini("memory_limit = -1\n", php_version=(8, 4, 26))
        self.assertEqual(findings_for(unlimited, "CVE-2026-109618")[0].confidence, Confidence.MEDIUM)
        self.assertEqual(findings_for(unlimited, "RES-001")[0].severity, Severity.INFO)
        self.assertFalse(findings_for(audit_ini("", php_version=(8, 4, 27)), "CVE-2026-109618"))
        self.assertFalse(findings_for(audit_ini("", php_version=(8, 4, 26), sapi="cli"), "CVE-2026-109618"))

    def test_stale_state_paths(self):
        default = findings_for(audit_ini("", php_version=(8, 5, 11)), "CVE-2026-109619")[0]
        self.assertIn("session.upload_progress.enabled is On", default.message)
        self.assertIn("fatal_error_backtraces is On", default.message)
        older = findings_for(audit_ini("", php_version=(8, 4, 26)), "CVE-2026-109619")[0]
        self.assertNotIn("fatal_error_backtraces", older.message)
        closed = audit_ini("session.upload_progress.enabled = 0\nfatal_error_backtraces = 0\n",
                           php_version=(8, 5, 11))
        self.assertEqual(findings_for(closed, "CVE-2026-109619")[0].confidence, Confidence.MEDIUM)

    def test_user_ini_cannot_disable_upload_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "php.ini").write_text("session.upload_progress.enabled = On\n")
            Path(tmp, ".user.ini").write_text("session.upload_progress.enabled = 0\nsession.sid_length = 48\n")
            fs = FileSystem()
            discovery = Discoverer(fs).paths([str(Path(tmp, "php.ini")), str(Path(tmp, ".user.ini"))])
            result = Auditor(fs, Options(sapi="fpm", php_version=(8, 4, 26), path_checks=False)).run(discovery)
        late = [f for f in findings_for(result, "CVE-2026-109619") if ".user.ini" in f.target]
        self.assertIn("applies after request parsing", late[0].message)
        self.assertEqual(findings_for(result, "CFG-010")[0].severity, Severity.MEDIUM)

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
