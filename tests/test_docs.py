import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_builder():
    spec = importlib.util.spec_from_file_location("build_docs", ROOT / "scripts" / "build_docs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DocsTest(unittest.TestCase):
    def test_generated_regions_are_current(self):
        self.assertEqual(load_builder().main(["--check"]), 0, "run python3 scripts/build_docs.py")

    def test_every_rule_is_documented(self):
        from php_ini_audit.rules import REGISTRY

        page = (ROOT / "docs" / "rules.html").read_text(encoding="utf-8")
        missing = [rule_id for rule_id in REGISTRY if f'id="{rule_id}"' not in page]
        self.assertEqual(missing, [])

    def test_internal_rule_links_resolve(self):
        import re

        from php_ini_audit.rules import REGISTRY

        for page in (ROOT / "docs").glob("*.html"):
            for rule_id in re.findall(r'rules\.html#([A-Z]+-\d{3})', page.read_text(encoding="utf-8")):
                self.assertIn(rule_id, REGISTRY, f"{page.name} links to unknown rule {rule_id}")


if __name__ == "__main__":
    unittest.main()
