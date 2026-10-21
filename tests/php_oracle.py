"""Ask a real php-cgi binary what it makes of a configuration, as ground truth for the scanner."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

# CLI SAPI overrides several defaults (display_errors, html_errors, ...), php-cgi does not.
ENV_VAR = "PHP_CGI"

DUMP_SCRIPT = """<?php
$names = json_decode(getenv('PIA_NAMES') ?: '[]', true);
$values = [];
foreach ($names as $name) {
    $values[$name] = ini_get($name);
}
echo json_encode([
    'version' => PHP_VERSION,
    'values' => $values,
    'all' => getenv('PIA_ALL') ? ini_get_all(null, true) : null,
]);
"""


def cgi_binaries():
    """php-cgi binaries from $PHP_CGI (os.pathsep-separated), else the one on PATH."""
    configured = os.environ.get(ENV_VAR)
    candidates = configured.split(os.pathsep) if configured else [shutil.which("php-cgi")]
    return [c for c in candidates if c]


def version_tuple(text):
    return tuple(int(part) for part in text.split("-")[0].split(".")[:3])


def run(binary, ini=None, scan_dir=None, names=(), all_entries=False, script_dir=None, document_root=None):
    """Run php-cgi with only the given configuration and return its view of the directives.

    With document_root the request is a real CGI request, so [PATH=] sections and .user.ini apply.
    """
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(script_dir or tmp)
        directory.mkdir(parents=True, exist_ok=True)
        script = directory / "pia_dump.php"
        script.write_text(DUMP_SCRIPT)
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PIA_NAMES": json.dumps(list(names)),
            "PHP_INI_SCAN_DIR": str(scan_dir or ""),
        }
        if all_entries:
            env["PIA_ALL"] = "1"
        args = [binary, "-n" if ini is None else "-c", *([] if ini is None else [str(ini)])]
        if document_root:
            env.update(
                REDIRECT_STATUS="200",
                GATEWAY_INTERFACE="CGI/1.1",
                REQUEST_METHOD="GET",
                SCRIPT_FILENAME=str(script),
                DOCUMENT_ROOT=str(document_root),
            )
        else:
            args += ["-q", str(script)]
        try:
            completed = subprocess.run(args, env=env, capture_output=True, text=True, timeout=30, check=True)
            body = completed.stdout.split("\n\n", 1)[-1] if document_root else completed.stdout
        finally:
            script.unlink()
    return json.loads(body)
