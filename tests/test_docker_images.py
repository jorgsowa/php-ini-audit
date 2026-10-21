"""Scan the exported filesystem of real PHP images and compare with what php-fpm inside reports.

Opt-in because it pulls images: PHP_INI_AUDIT_DOCKER=1 python -m unittest tests.test_docker_images
"""

import json
import os
import posixpath
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import uuid
from pathlib import Path

from php_ini_audit import directives, values
from php_ini_audit.discovery import Discoverer
from php_ini_audit.engine import Auditor, Options
from php_ini_audit.fsutil import FileSystem

from .test_integration import run_cli
from .test_php_parity import BUILD_DEPENDENT, EFFECTIVE_DEFAULTS, versioned_default

ENABLED = bool(os.environ.get("PHP_INI_AUDIT_DOCKER")) and shutil.which("docker") is not None
EXTRACT = ("etc/", "usr/local/etc/", "usr/local/include/php/main/", "usr/include/php", "var/lib/dpkg/status",
           "lib/apk/db/installed")
APT = "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends"

# name -> (image, setup command, php-fpm binary, target that php-fpm loads)
IMAGES = {
    "official-defaults": ("php:8.3-fpm-alpine", "true", "php-fpm", "/usr/local/etc/php (no php.ini)"),
    "official-production": (
        "php:8.3-fpm-alpine",
        "cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini",
        "php-fpm",
        "/usr/local/etc/php/php.ini",
    ),
    "alpine-packages": (
        "alpine:3.20",
        "apk add --no-cache php83 php83-fpm php83-opcache php83-session",
        "php-fpm83",
        "/etc/php83/php.ini",
    ),
    "debian-packages": ("debian:bookworm-slim", f"{APT} php8.2-fpm", "php-fpm8.2", "/etc/php/8.2/fpm/php.ini"),
}


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=600, check=True, **kwargs)


def parse_phpinfo(text):
    """Return (header fields, {directive: local value}) from `php-fpm -i` text output."""
    fields, ini = {}, {}
    lines = iter(text.splitlines())
    for line in lines:
        parts = line.split(" => ")
        if len(parts) == 2 and parts[0] not in fields:
            value = parts[1]
            # Long lists continue on the following lines, each ending with a comma but the last.
            while value.endswith(","):
                value += next(lines, "")
            fields[parts[0]] = value
        elif len(parts) == 3:
            ini.setdefault(parts[0], parts[1])
    return fields, ini


def extract(stream, root):
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            name = posixpath.normpath(member.name.lstrip("./"))
            if name.startswith("..") or not name.startswith(EXTRACT):
                continue
            target = Path(root, name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                # Kept verbatim: the scanner itself must confine absolute targets to the root.
                os.symlink(member.linkname, target)
            elif member.islnk():
                source = Path(root, posixpath.normpath(member.linkname.lstrip("./")))
                if source.is_file():
                    shutil.copyfile(source, target)
            elif member.isfile() and member.size <= 4 * 1024 * 1024:
                target.write_bytes(archive.extractfile(member).read())


def same(name, scanner_value, displayed):
    if displayed == "no value":
        return scanner_value in (None, "")
    if displayed in ("On", "Off"):
        return values.to_bool(scanner_value) == (displayed == "On")
    if name == "error_reporting":
        return values.eval_error_reporting(scanner_value) == int(displayed)
    return scanner_value == displayed


@unittest.skipUnless(ENABLED, "set PHP_INI_AUDIT_DOCKER=1 (needs docker) to scan real images")
class DockerImageTest(unittest.TestCase):
    maxDiff = None

    def scan_image(self, image, setup, fpm):
        name = f"php-ini-audit-test-{uuid.uuid4().hex[:12]}"
        try:
            run = docker("run", "--name", name, image, "sh", "-c", f"({setup}) >/dev/null 2>&1 && {fpm} -i")
            root = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, root)
            with subprocess.Popen(["docker", "export", name], stdout=subprocess.PIPE) as export:
                extract(export.stdout, root)
            self.assertEqual(export.returncode, 0)
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)
        code, out, err = run_cli("--root", root, "--path-checks", "off", "--format", "json")
        self.assertEqual(code, 0, err)
        self.assertTrue(json.loads(out)["findings"])
        fs = FileSystem(root)
        discovery = Discoverer(fs).system()
        discovery.resolve_versions(fs)
        targets = Auditor(fs, Options(path_checks=False)).build_targets(discovery)
        return parse_phpinfo(run.stdout), {t.name: t for t in targets}

    def test_images(self):
        for case, (image, setup, fpm, expected_target) in IMAGES.items():
            with self.subTest(case=case):
                (fields, php_ini), targets = self.scan_image(image, setup, fpm)
                self.assertIn(expected_target, targets)
                target = targets[expected_target]

                version = tuple(int(p) for p in fields["PHP Version"].split(".")[:3])
                self.assertEqual(target.php_version, version)
                loaded = fields["Loaded Configuration File"]
                self.assertEqual(target.defaults_reason is not None, loaded == "(none)")
                scanned = [p.strip() for p in fields["Additional .ini files parsed"].split(",") if p.strip()]
                expected_files = ([] if loaded == "(none)" else [loaded]) + [p for p in scanned if p != "(none)"]
                self.assertEqual(target.files, expected_files)

                config = target.config
                mismatches = {}
                for directive, displayed in php_ini.items():
                    setting = config.get(directive)
                    if setting.unresolved:
                        continue
                    if not setting.is_set:
                        if not directives.is_known(directive) or directive in BUILD_DEPENDENT | EFFECTIVE_DEFAULTS:
                            continue
                        if versioned_default(directive, version) is not None:
                            continue
                    if not same(directive, setting.value, displayed):
                        mismatches[directive] = (setting.value, displayed)
                self.assertEqual(mismatches, {}, "scanner value vs php-fpm -i")


if __name__ == "__main__":
    unittest.main()
