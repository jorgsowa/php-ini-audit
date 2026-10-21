"""Discovery and version detection over the on-disk layouts of real distributions and bundles, via --root."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from .test_integration import run_cli

DPKG = "Package: {package}\nStatus: install ok installed\nVersion: {version}\n\n"
APK = "P:{package}\nV:{version}\nA:x86_64\n\n"
HEADER = '#define PHP_VERSION "{version}"\n'

# name -> (files, symlinks {link: target}, expected {target name: (sapi, version, version source, files)})
LAYOUTS = {
    "rhel": (
        {
            "etc/php.ini": "expose_php = On\n",
            "etc/php.d/10-opcache.ini": "zend_extension=opcache\n",
            "etc/php.d/20-sodium.ini": "extension=sodium\n",
            "etc/php-fpm.conf": "[global]\ninclude=/etc/php-fpm.d/*.conf\n",
            "etc/php-fpm.d/www.conf": "[www]\nlisten = /run/php-fpm/www.sock\n",
            "usr/include/php/main/php_version.h": HEADER.format(version="8.1.27"),
        },
        {},
        {
            "/etc/php.ini": ("unknown", "8.1.27", "/usr/include/php/main/php_version.h",
                             ["/etc/php.ini", "/etc/php.d/10-opcache.ini", "/etc/php.d/20-sodium.ini"]),
            "/etc/php.ini + pool [www] (/etc/php-fpm.d/www.conf)": ("fpm", "8.1.27", None, None),
        },
    ),
    "remi": (
        {
            "etc/opt/remi/php83/php.ini": "expose_php = On\n",
            "etc/opt/remi/php83/php.d/10-opcache.ini": "zend_extension=opcache\n",
            "opt/remi/php83/root/usr/include/php/main/php_version.h": HEADER.format(version="8.3.4"),
            "etc/opt/remi/php82/php.ini": "expose_php = On\n",
            "opt/remi/php82/root/usr/include/php/main/php_version.h": HEADER.format(version="8.2.18"),
        },
        {},
        {
            "/etc/opt/remi/php83/php.ini": ("unknown", "8.3.4", "/opt/remi/php83/root/usr/include/php/main/php_version.h",
                                            ["/etc/opt/remi/php83/php.ini", "/etc/opt/remi/php83/php.d/10-opcache.ini"]),
            "/etc/opt/remi/php82/php.ini": ("unknown", "8.2.18", "/opt/remi/php82/root/usr/include/php/main/php_version.h",
                                            ["/etc/opt/remi/php82/php.ini"]),
        },
    ),
    "alpine": (
        {
            "etc/php83/php.ini": "expose_php = On\n",
            "etc/php83/conf.d/00_opcache.ini": "zend_extension=opcache\n",
            "etc/php83/php-fpm.conf": "[global]\nerror_log = /var/log/php83/error.log\n",
            "etc/php83/php-fpm.d/www.conf": "[www]\nlisten = 127.0.0.1:9000\n",
            "lib/apk/db/installed": APK.format(package="musl", version="1.2.5-r0")
            + APK.format(package="php83", version="8.3.12-r0")
            + APK.format(package="php83-fpm", version="8.3.12-r0"),
        },
        {},
        {
            "/etc/php83/php.ini": ("unknown", "8.3.12", "/lib/apk/db/installed (php83 8.3.12-r0)",
                                   ["/etc/php83/php.ini", "/etc/php83/conf.d/00_opcache.ini"]),
            "/etc/php83/php.ini + pool [www] (/etc/php83/php-fpm.d/www.conf)": ("fpm", "8.3.12", None, None),
        },
    ),
    "homebrew": (
        {
            "opt/homebrew/etc/php/8.3/php.ini": "expose_php = On\n",
            "opt/homebrew/etc/php/8.3/conf.d/ext-opcache.ini": "zend_extension=opcache\n",
            "opt/homebrew/etc/php/8.3/php-fpm.d/www.conf": "[www]\nlisten = 127.0.0.1:9000\n",
            "opt/homebrew/Cellar/php@8.3/8.3.12/bin/.keep": "",
            "opt/homebrew/Cellar/php@8.3/8.3.9/bin/.keep": "",
        },
        {"opt/homebrew/opt/php@8.3": "../Cellar/php@8.3/8.3.12"},
        {
            "/opt/homebrew/etc/php/8.3/php.ini": ("unknown", "8.3.12", "/opt/homebrew/opt/php@8.3",
                                                  ["/opt/homebrew/etc/php/8.3/php.ini",
                                                   "/opt/homebrew/etc/php/8.3/conf.d/ext-opcache.ini"]),
            "/opt/homebrew/etc/php/8.3/php.ini + pool [www] (/opt/homebrew/etc/php/8.3/php-fpm.d/www.conf)":
                ("fpm", "8.3.12", None, None),
        },
    ),
    "cpanel": (
        {
            "opt/cpanel/ea-php81/root/etc/php.ini": "expose_php = On\n",
            "opt/cpanel/ea-php81/root/etc/php.d/20-curl.ini": "extension=curl.so\n",
            "opt/cpanel/ea-php81/root/usr/include/php/main/php_version.h": HEADER.format(version="8.1.29"),
        },
        {},
        {
            "/opt/cpanel/ea-php81/root/etc/php.ini": (
                "unknown", "8.1.29", "/opt/cpanel/ea-php81/root/usr/include/php/main/php_version.h",
                ["/opt/cpanel/ea-php81/root/etc/php.ini", "/opt/cpanel/ea-php81/root/etc/php.d/20-curl.ini"]),
        },
    ),
    "debian-symlinked-mods": (
        {
            "etc/php/8.3/fpm/php.ini": "expose_php = On\n",
            "etc/php/8.3/cli/php.ini": "expose_php = On\n",
            "etc/php/8.3/mods-available/opcache.ini": "zend_extension=opcache.so\n",
            "etc/php/8.3/mods-available/xdebug.ini": "zend_extension=xdebug.so\n",
            "etc/php/8.3/fpm/pool.d/www.conf": "[www]\nlisten = /run/php/php8.3-fpm.sock\n",
            "var/lib/dpkg/status": DPKG.format(package="php8.3-common", version="8.3.6-0ubuntu0.24.04.3")
            + DPKG.format(package="php8.3-fpm", version="8.3.6-0ubuntu0.24.04.3"),
        },
        {
            # Debian links enabled modules with absolute targets; they must resolve inside the root.
            "etc/php/8.3/fpm/conf.d/10-opcache.ini": "/etc/php/8.3/mods-available/opcache.ini",
            "etc/php/8.3/cli/conf.d/20-xdebug.ini": "/etc/php/8.3/mods-available/xdebug.ini",
        },
        {
            "/etc/php/8.3/fpm/php.ini": ("fpm", "8.3.6", "/var/lib/dpkg/status (php8.3-common 8.3.6-0ubuntu0.24.04.3)",
                                         ["/etc/php/8.3/fpm/php.ini", "/etc/php/8.3/fpm/conf.d/10-opcache.ini"]),
            "/etc/php/8.3/cli/php.ini": ("cli", "8.3.6", "/var/lib/dpkg/status (php8.3-common 8.3.6-0ubuntu0.24.04.3)",
                                         ["/etc/php/8.3/cli/php.ini", "/etc/php/8.3/cli/conf.d/20-xdebug.ini"]),
            "/etc/php/8.3/fpm/php.ini + pool [www] (/etc/php/8.3/fpm/pool.d/www.conf)": ("fpm", "8.3.6", None, None),
        },
    ),
    "bundles": (
        {
            "opt/lampp/etc/php.ini": "expose_php = On\n",
            "opt/bitnami/php/etc/php.ini": "expose_php = On\n",
            "opt/plesk/php/8.2/etc/php.ini": "expose_php = On\n",
            "opt/plesk/php/8.2/etc/php.d/opcache.ini": "zend_extension=opcache.so\n",
            "Applications/MAMP/bin/php/php8.2.0/conf/php.ini": "expose_php = On\n",
        },
        {},
        {
            "/opt/lampp/etc/php.ini": ("unknown", None, None, ["/opt/lampp/etc/php.ini"]),
            "/opt/bitnami/php/etc/php.ini": ("unknown", None, None, ["/opt/bitnami/php/etc/php.ini"]),
            "/opt/plesk/php/8.2/etc/php.ini": ("unknown", "8.2", "path",
                                               ["/opt/plesk/php/8.2/etc/php.ini",
                                                "/opt/plesk/php/8.2/etc/php.d/opcache.ini"]),
            "/Applications/MAMP/bin/php/php8.2.0/conf/php.ini": ("unknown", "8.2", "path",
                                                                 ["/Applications/MAMP/bin/php/php8.2.0/conf/php.ini"]),
        },
    ),
}


def build_root(root, files, links):
    for name, content in files.items():
        path = Path(root, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    for name, target in links.items():
        path = Path(root, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, path)


@unittest.skipIf(os.name == "nt", "layouts use POSIX symlinks")
class LayoutDiscoveryTest(unittest.TestCase):
    maxDiff = None

    def test_layouts(self):
        for layout, (files, links, expected) in LAYOUTS.items():
            with self.subTest(layout=layout), tempfile.TemporaryDirectory() as root:
                build_root(root, files, links)
                code, out, err = run_cli("--root", root, "--path-checks", "off", "--format", "json")
                self.assertEqual(code, 0, err)
                report = json.loads(out)
                self.assertEqual(report["warnings"], [])
                targets = {t["name"]: t for t in report["targets"]}
                self.assertEqual(set(targets), set(expected))
                for name, (sapi, version, source, scanned) in expected.items():
                    target = targets[name]
                    self.assertEqual(target["sapi"], sapi, name)
                    self.assertEqual(target["php_version"], version, name)
                    if source is not None:
                        self.assertEqual(target["php_version_source"], source, name)
                    if scanned is not None:
                        self.assertEqual(target["files"], scanned, name)

    def test_symlink_outside_root_is_reanchored(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            Path(outside, "evil.ini").write_text("allow_url_include = On\n")
            build_root(root, {"etc/php/8.3/fpm/php.ini": "expose_php = Off\n"},
                       {"etc/php/8.3/fpm/conf.d/99-evil.ini": str(Path(outside, "evil.ini"))})
            code, out, _ = run_cli("--root", root, "--path-checks", "off", "--format", "json")
            report = json.loads(out)
            self.assertNotIn("EXEC-001", {f["rule_id"] for f in report["findings"]})
            self.assertEqual(report["targets"][0]["files"], ["/etc/php/8.3/fpm/php.ini"])

    def test_discover_lists_layout(self):
        files, links, expected = LAYOUTS["alpine"]
        with tempfile.TemporaryDirectory() as root:
            build_root(root, files, links)
            code, out, _ = run_cli("discover", "--root", root)
            self.assertEqual(code, 0)
            self.assertIn("/etc/php83/php.ini  [sapi unknown, php 8.3.12 from /lib/apk/db/installed", out)
            self.assertIn("  scan  /etc/php83/conf.d/00_opcache.ini", out)
            self.assertIn("  fpm   /etc/php83/php-fpm.conf", out)
            self.assertIn("  fpm   /etc/php83/php-fpm.d/www.conf", out)


if __name__ == "__main__":
    unittest.main()
