"""End-to-end snapshots of full scans over the fixtures.

Regenerate after an intended change with: UPDATE_GOLDEN=1 python -m unittest tests.test_golden
"""

import json
import os
import unittest

from .helpers import FIXTURES
from .test_integration import run_cli

GOLDEN = FIXTURES.parent / "golden"
# Path checks depend on the checkout's permissions, so snapshots leave them off.
SCENARIOS = {
    "debian": ("--root", "debian"),
    "debian-development": ("--root", "debian", "--profile", "development"),
    "debian-old-patch": ("--root", "debian", "--php-version", "8.2.0"),
    "docker": ("--root", "docker"),
    "hardened": ("hardened/php.ini",),
    "webroot": ("webroot",),
    "windows-xampp": ("windows-xampp/php.ini",),
}


def cli_args(scenario):
    args = []
    for arg in SCENARIOS[scenario]:
        args.append(str(FIXTURES / arg) if (FIXTURES / arg).exists() else arg)
    return args + ["--path-checks", "off", "--format", "json"]


def snapshot(report):
    def clean(text):
        return str(text).replace(str(FIXTURES), "<fixtures>").replace(os.sep, "/") if text is not None else "-"

    lines = ["[targets]"]
    for target in report["targets"]:
        version = target["php_version"] or "unknown"
        if target["php_version_source"]:
            version += f" from {target['php_version_source']}"
        flags = " defaults-only" if target["defaults_only"] else ""
        lines.append(f"{clean(target['name'])}  sapi={target['sapi']} php={clean(version)}{flags}")
        lines += [f"  file {clean(path)}" for path in target["files"]]
    lines.append("[warnings]")
    lines += [clean(w) for w in report["warnings"]]
    lines.append("[findings]")
    for f in report["findings"]:
        where = f"{clean(f['file'])}:{f['line']}" if f["line"] else clean(f["file"])
        if f["from_default"]:
            where = "default"
        lines.append(
            f"{f['severity']:8} {f['confidence']:6} {f['rule_id']:14} {clean(f['directive'])}={clean(f['value'])}"
            f"  at {where}  in {clean(f['target'])}"
        )
    lines.append("[summary]")
    lines.append(json.dumps(report["summary"]["by_severity"]))
    return "\n".join(lines) + "\n"


class GoldenReportTest(unittest.TestCase):
    maxDiff = None

    def test_scenarios(self):
        update = bool(os.environ.get("UPDATE_GOLDEN"))
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                code, out, err = run_cli(*cli_args(scenario))
                self.assertEqual(code, 0, err)
                actual = snapshot(json.loads(out))
                path = GOLDEN / f"{scenario}.txt"
                if update:
                    GOLDEN.mkdir(exist_ok=True)
                    path.write_text(actual)
                    continue
                self.assertTrue(path.exists(), f"missing {path}; run with UPDATE_GOLDEN=1")
                self.assertEqual(actual, path.read_text(), f"{scenario} report changed")

    def test_no_stale_snapshots(self):
        stale = {p.stem for p in GOLDEN.glob("*.txt")} - set(SCENARIOS)
        self.assertEqual(stale, set())

    def test_formats_agree(self):
        args = cli_args("debian")[:-2]
        _, out, _ = run_cli(*args, "--format", "json")
        findings = json.loads(out)["findings"]
        _, out, _ = run_cli(*args, "--format", "sarif")
        results = json.loads(out)["runs"][0]["results"]
        self.assertEqual([r["ruleId"] for r in results], [f["rule_id"] for f in findings])
        _, out, _ = run_cli(*args, "--format", "markdown")
        for rule_id in {f["rule_id"] for f in findings}:
            self.assertIn(f"| {rule_id} |", out)
        _, out, _ = run_cli(*args, "--format", "text", "--no-color")
        self.assertNotIn("\033[", out)
        for rule_id in {f["rule_id"] for f in findings}:
            self.assertIn(rule_id, out)


if __name__ == "__main__":
    unittest.main()
