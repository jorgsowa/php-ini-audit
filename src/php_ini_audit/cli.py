"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import re
import sys
from typing import List, Optional

from . import __version__
from .discovery import Discoverer, Discovery
from .engine import PROFILES, Auditor, Options
from .fsutil import FileSystem
from .model import Severity
from .report import render_json, render_markdown, render_rule, render_rules, render_sarif, render_text
from .rules import REGISTRY
from .versions import format_version, parse_version

COMMANDS = ("scan", "rules", "discover")
SAPIS = ("cli", "fpm", "apache2", "cgi", "litespeed", "embed", "unknown")
EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2


def _severity(text: str) -> Severity:
    try:
        return Severity.parse(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _version(text: str):
    if not re.fullmatch(r"\d+\.\d+(\.\d+)?", text):
        raise argparse.ArgumentTypeError("expected MAJOR.MINOR or MAJOR.MINOR.PATCH, e.g. 8.3.12")
    return parse_version(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="php-ini-audit",
        description="Statically audit PHP INI configuration. Files are only read; nothing is executed.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    def add_source_options(p: argparse.ArgumentParser) -> None:
        p.add_argument("paths", nargs="*", help="php.ini / *.ini / pool *.conf / .user.ini / .htaccess files or "
                       "directories to walk; omit to discover system installations")
        p.add_argument("--root", help="audit a mounted filesystem or container image extracted at this path")
        p.add_argument("--ini", help="explicit php.ini (like php -c)")
        p.add_argument("--scan-dir", action="append", default=[], help="extra INI scan directory (like "
                       "PHP_INI_SCAN_DIR); repeatable")
        p.add_argument("--pool", action="append", default=[], help="php-fpm pool or php-fpm.conf; repeatable")
        p.add_argument("--webroot", action="append", default=[], help="document root: its .user.ini/.htaccess "
                       "files are audited and paths inside it are treated as web-served; repeatable")
        p.add_argument("--max-depth", type=int, default=12, help="directory walk depth (default 12)")

    scan = sub.add_parser("scan", help="audit configuration (default command)")
    add_source_options(scan)
    scan.add_argument("--profile", choices=PROFILES, default="production",
                      help="severity profile (default production)")
    scan.add_argument("--sapi", choices=SAPIS, help="override the SAPI inferred from paths")
    scan.add_argument("--php-version", type=_version, help="exact PHP version (X.Y or X.Y.Z); otherwise read from paths, headers and package databases")
    scan.add_argument("--path-checks", choices=("auto", "on", "off"), default="auto",
                      help="inspect permissions of referenced paths; auto = on for system/--root scans")
    scan.add_argument("--min-severity", type=_severity, default=Severity.INFO, help="hide findings below this")
    scan.add_argument("--only", action="append", default=[], help="rule id or category (e.g. SESS); repeatable")
    scan.add_argument("--skip", action="append", default=[], help="rule id or category to skip; repeatable")
    scan.add_argument("--format", choices=("text", "json", "sarif", "markdown"), default="text")
    scan.add_argument("-o", "--output", help="write the report to this file")
    scan.add_argument("--fail-on", type=_severity, help="exit 1 when a finding at or above this severity exists")
    scan.add_argument("--no-color", action="store_true")

    rules = sub.add_parser("rules", help="list the rule catalogue or explain one rule")
    rules.add_argument("rule_id", nargs="?")
    rules.add_argument("--format", choices=("text", "json", "markdown"), default="text")

    discover = sub.add_parser("discover", help="list the configuration files that would be audited")
    add_source_options(discover)
    return parser


def _display_path(fs: FileSystem, path: str) -> str:
    """With --root, accept both host paths below the root and paths as seen inside it."""
    if fs.root is None:
        return os.path.abspath(path)
    absolute = os.path.abspath(path)
    if absolute == fs.root or absolute.startswith(fs.root.rstrip(os.sep) + os.sep):
        return fs.to_display(absolute)
    return "/" + path.replace(os.sep, "/").lstrip("/")


def _discover(args, fs: FileSystem) -> Discovery:
    discoverer = Discoverer(fs)

    def display(path: str) -> str:
        return _display_path(fs, path)

    paths = [display(p) for p in args.paths]
    explicit = bool(paths or args.ini or args.scan_dir or args.pool)
    discovery = discoverer.paths(paths, max_depth=args.max_depth) if paths else Discovery()
    if args.ini or args.scan_dir:
        ini = display(args.ini) if args.ini else None
        directory = os.path.dirname(ini) if ini else display(args.scan_dir[0])
        installation = discoverer.build(ini, directory, scan_dirs=[display(d) for d in args.scan_dir])
        installation.fpm_files = [display(p) for p in args.pool]
        discovery.installations.append(installation)
    elif args.pool:
        extra = discoverer.paths([display(p) for p in args.pool])
        discovery.installations.extend(extra.installations)
    if not explicit:
        discovery = discoverer.system()
    if not explicit or fs.root:
        discovery.resolve_versions(fs)
    for webroot in args.webroot:
        found = discoverer.paths([display(webroot)], max_depth=args.max_depth)
        discovery.user_inis.extend(p for p in found.user_inis if p not in discovery.user_inis)
        discovery.htaccess.extend(p for p in found.htaccess if p not in discovery.htaccess)
        discovery.warnings.extend(found.warnings)
    return discovery


def _cmd_rules(args) -> int:
    if args.rule_id:
        rule_id = args.rule_id.upper()
        if rule_id not in REGISTRY:
            print(f"unknown rule: {args.rule_id}", file=sys.stderr)
            return EXIT_USAGE
        sys.stdout.write(render_rule(rule_id))
    else:
        sys.stdout.write(render_rules(args.format))
    return EXIT_OK


def _cmd_discover(args, fs: FileSystem) -> int:
    discovery = _discover(args, fs)
    for installation in discovery.installations:
        version = format_version(installation.php_version)
        if installation.version_source:
            version += f" from {installation.version_source}"
        print(f"{installation.label}  [sapi {installation.sapi}, php {version}]")
        if installation.defaults_reason:
            print(f"  ! {installation.defaults_reason}")
        for path in installation.scan_files:
            print(f"  scan  {path}")
        for path in installation.fpm_files:
            print(f"  fpm   {path}")
    for path in discovery.user_inis:
        print(f".user.ini  {path}")
    for path in discovery.htaccess:
        print(f".htaccess  {path}")
    for warning in discovery.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if not (discovery.installations or discovery.user_inis or discovery.htaccess):
        print("No PHP configuration found.", file=sys.stderr)
    return EXIT_OK


def _cmd_scan(args, fs: FileSystem) -> int:
    for selector in args.only + args.skip:
        upper = selector.upper()
        if upper not in REGISTRY and upper not in {r.category for r in REGISTRY.values()}:
            print(f"unknown rule or category: {selector}", file=sys.stderr)
            return EXIT_USAGE
    discovery = _discover(args, fs)
    system_scan = not (args.paths or args.ini or args.scan_dir or args.pool)
    path_checks = args.path_checks == "on" or (args.path_checks == "auto" and (system_scan or bool(args.root)))
    webroots = [_display_path(fs, w) for w in args.webroot]
    options = Options(
        profile=args.profile,
        sapi=args.sapi,
        php_version=args.php_version,
        path_checks=path_checks,
        webroots=webroots,
        min_severity=args.min_severity,
        only=args.only,
        skip=args.skip,
    )
    result = Auditor(fs, options).run(discovery)

    if args.format == "json":
        output = render_json(result, args.profile)
    elif args.format == "sarif":
        output = render_sarif(result, args.profile)
    elif args.format == "markdown":
        output = render_markdown(result, args.profile)
    else:
        color = not args.no_color and not args.output and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        output = render_text(result, args.profile, color=color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
    else:
        sys.stdout.write(output)

    if args.fail_on is not None and any(f.severity >= args.fail_on for f in result.findings):
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "scan")
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "rules":
        return _cmd_rules(args)
    if args.root and not os.path.isdir(args.root):
        print(f"--root {args.root} is not a directory", file=sys.stderr)
        return EXIT_USAGE
    fs = FileSystem(args.root)
    try:
        if args.command == "discover":
            return _cmd_discover(args, fs)
        return _cmd_scan(args, fs)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
