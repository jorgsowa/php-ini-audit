"""Fill the generated regions of docs/*.html from the rule registry.

Usage: python3 scripts/build_docs.py [--check]
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from php_ini_audit import __version__  # noqa: E402
from php_ini_audit.model import Severity  # noqa: E402
from php_ini_audit.rules import CATEGORIES, REGISTRY  # noqa: E402

DOCS = ROOT / "docs"
REGION = re.compile(r"(<!-- generated:(?P<name>[a-z-]+) -->)(.*?)(<!-- /generated:(?P=name) -->)", re.DOTALL)


def _esc(text: str) -> str:
    return html.escape(text, quote=True)


def _rule_html(rule) -> str:
    meta = [f"<span><b>Category</b> {_esc(rule.category_name)}</span>", f"<span><b>Scope</b> {rule.scope}</span>"]
    if rule.sapis:
        meta.append(f"<span><b>SAPIs</b> {_esc(', '.join(sorted(rule.sapis)))}</span>")
    if rule.production_only:
        meta.append("<span><b>Profile</b> production only</span>")
    if rule.dev_severity is not None:
        meta.append(f"<span><b>Development</b> {rule.dev_severity}</span>")
    if rule.cwe:
        number = rule.cwe.split("-", 1)[1]
        meta.append(
            f'<span><b>Weakness</b> <a href="https://cwe.mitre.org/data/definitions/{number}.html">{rule.cwe}</a></span>'
        )
    directives = ""
    if rule.directives:
        directives = "<p><b>Directives</b> " + ", ".join(f"<code>{_esc(d)}</code>" for d in rule.directives) + "</p>"
    references = ""
    if rule.references:
        links = "".join(f'<li><a href="{_esc(r)}">{_esc(r)}</a></li>' for r in rule.references)
        references = f"<ul>{links}</ul>"
    search = " ".join([rule.id, rule.title, rule.description, " ".join(rule.directives), rule.cwe or ""]).lower()
    return (
        f'<details class="rule" id="{rule.id}" data-severity="{rule.severity}" data-category="{rule.category}" '
        f'data-search="{_esc(search)}">\n'
        f'  <summary><span class="id">{rule.id}</span><span class="title">{_esc(rule.title)}</span>'
        f'<span class="sev sev-{rule.severity}">{rule.severity}</span></summary>\n'
        f'  <div class="body">\n'
        f'    <div class="meta">{"".join(meta)}</div>\n'
        f"    <p>{_esc(rule.description)}</p>\n"
        f"    {directives}\n"
        f'    <p class="fix"><b>Fix:</b> {_esc(rule.recommendation)}</p>\n'
        f"    {references}\n"
        f"  </div>\n"
        f"</details>"
    )


def render_rules() -> str:
    parts = []
    for category, name in CATEGORIES.items():
        rules = sorted((r for r in REGISTRY.values() if r.category == category), key=lambda r: r.id)
        if not rules:
            continue
        parts.append(
            f'<section class="category" data-category="{category}">\n'
            f'<h2 class="category-heading" id="cat-{category}">{_esc(name)} '
            f'<a class="anchor" href="#cat-{category}">#</a></h2>\n'
            + "\n".join(_rule_html(r) for r in rules)
            + "\n</section>"
        )
    return "\n" + "\n".join(parts) + "\n"


def render_severity_options() -> str:
    options = "".join(f'<option value="{s}">{str(s).capitalize()}</option>' for s in sorted(Severity, reverse=True))
    return f'<option value="">All severities</option>{options}'


def render_category_options() -> str:
    used = {r.category for r in REGISTRY.values()}
    options = "".join(f'<option value="{c}">{_esc(n)}</option>' for c, n in CATEGORIES.items() if c in used)
    return f'<option value="">All categories</option>{options}'


def render_category_table() -> str:
    rows = []
    for category, name in CATEGORIES.items():
        rules = [r for r in REGISTRY.values() if r.category == category]
        if rules:
            rows.append(
                f'<tr><td><a href="rules.html#cat-{category}"><code>{category}</code></a></td>'
                f"<td>{_esc(name)}</td><td>{len(rules)}</td></tr>"
            )
    return "\n" + "\n".join(rows) + "\n"


GENERATORS = {
    "rules": render_rules,
    "rule-count": lambda: str(len(REGISTRY)),
    "version": lambda: __version__,
    "severity-options": render_severity_options,
    "category-options": render_category_options,
    "category-table": render_category_table,
}


def build(text: str) -> str:
    def replace(match: re.Match) -> str:
        generator = GENERATORS.get(match.group("name"))
        if generator is None:
            raise KeyError(f"unknown generated region: {match.group('name')}")
        return f"{match.group(1)}{generator()}{match.group(4)}"

    return REGION.sub(replace, text)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if any page is out of date")
    args = parser.parse_args(argv)
    stale = []
    for page in sorted(DOCS.glob("*.html")):
        current = page.read_text(encoding="utf-8")
        updated = build(current)
        if updated != current:
            stale.append(page.name)
            if not args.check:
                page.write_text(updated, encoding="utf-8")
    if args.check and stale:
        print(f"out of date: {', '.join(stale)} (run python3 scripts/build_docs.py)", file=sys.stderr)
        return 1
    if stale and not args.check:
        print(f"updated: {', '.join(stale)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
