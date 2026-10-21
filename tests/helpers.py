import os
import tempfile
from pathlib import Path

from php_ini_audit.discovery import Discoverer
from php_ini_audit.engine import Auditor, Options
from php_ini_audit.fsutil import FileSystem

FIXTURES = Path(__file__).parent / "fixtures"


def audit_ini(text, files=None, **options):
    """Audit a php.ini given as text, plus optional extra files relative to its directory."""
    with tempfile.TemporaryDirectory() as tmp:
        ini = os.path.join(tmp, "php.ini")
        Path(ini).write_text(text)
        for name, content in (files or {}).items():
            target = Path(tmp, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        fs = FileSystem()
        discovery = Discoverer(fs).paths([ini])
        options.setdefault("path_checks", False)
        options.setdefault("sapi", "fpm")
        return Auditor(fs, Options(**options)).run(discovery)


def rule_ids(result):
    return {f.rule_id for f in result.findings}


def findings_for(result, rule_id):
    return [f for f in result.findings if f.rule_id == rule_id]
