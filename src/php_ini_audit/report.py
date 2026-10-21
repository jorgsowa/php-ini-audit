"""Render audit results as text, JSON, SARIF or Markdown."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Dict, Iterable, List

from . import __version__
from .engine import AuditResult
from .model import Finding, Severity
from .rules import REGISTRY
from .versions import format_version

_COLORS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def severity_counts(findings: Iterable[Finding]) -> Dict[str, int]:
    counts = Counter(f.severity for f in findings)
    return {str(s): counts.get(s, 0) for s in sorted(Severity, reverse=True)}


def summary(result: AuditResult) -> dict:
    by_category = Counter(f.category for f in result.findings)
    by_target: Dict[str, Counter] = defaultdict(Counter)
    for finding in result.findings:
        by_target[finding.target][str(finding.severity)] += 1
    return {
        "by_severity": severity_counts(result.findings),
        "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        "by_target": {name: dict(counts) for name, counts in by_target.items()},
        "rules_evaluated": result.rules_evaluated,
        "configurations": len([t for t in result.targets if not t.overlay]),
        "overlays": len([t for t in result.targets if t.overlay]),
        "files": len(result.files),
        "path_checks": result.path_checks,
    }


def _where(finding: Finding) -> str:
    if finding.location:
        return str(finding.location)
    return "built-in default" if finding.from_default else ""


def render_text(result: AuditResult, profile: str, color: bool = False) -> str:
    def paint(severity: Severity, text: str) -> str:
        return f"{_COLORS[severity]}{text}{_RESET}" if color else text

    lines: List[str] = [f"php-ini-audit {__version__}  profile={profile}  path-checks={'on' if result.path_checks else 'off'}"]
    if not result.targets:
        lines.append("No PHP configuration found. Pass paths, --ini or --root.")
    for warning in result.warnings:
        lines.append(f"warning: {warning}")

    grouped: Dict[str, List[Finding]] = defaultdict(list)
    for finding in result.findings:
        grouped[finding.target].append(finding)

    target_names = [t.name for t in result.targets] + sorted(set(grouped) - {t.name for t in result.targets})
    describe = {t.name: t for t in result.targets}
    for name in target_names:
        findings = grouped.get(name, [])
        target = describe.get(name)
        lines.append("")
        header = f"== {name}"
        if target is not None:
            version = format_version(target.php_version)
            if target.version_source and target.version_source != "path":
                version += f" from {target.version_source}"
            header += f"  [sapi {target.sapi}, php {version}]"
        else:
            header += "  [file checks]"
        lines.append(header)
        if target is not None and target.files and not target.overlay:
            lines.append(f"   files: {', '.join(target.files)}")
        if findings:
            counts = severity_counts(findings)
            lines.append("   " + ", ".join(f"{n} {s}" for s, n in counts.items()))
        else:
            lines.append("   no findings")
        for finding in findings:
            label = paint(finding.severity, f"{str(finding.severity).upper():8}")
            lines.append(f"  {label} {finding.rule_id:14} {finding.title}  (confidence {finding.confidence})")
            lines.append(f"           {finding.message}")
            where = _where(finding)
            if where:
                lines.append(f"           at {where}")
            lines.append(f"           fix: {finding.recommendation}")

    data = summary(result)
    lines.append("")
    lines.append("Summary")
    lines.append(
        f"  {data['configurations']} configuration(s), {data['overlays']} overlay(s), {data['files']} file(s), "
        f"{data['rules_evaluated']} rules"
    )
    lines.append("  severity: " + "  ".join(f"{s} {n}" for s, n in data["by_severity"].items()))
    if data["by_category"]:
        lines.append("  category: " + "  ".join(f"{c} {n}" for c, n in data["by_category"].items()))
    return "\n".join(lines) + "\n"


def render_json(result: AuditResult, profile: str) -> str:
    payload = {
        "tool": {"name": "php-ini-audit", "version": __version__},
        "profile": profile,
        "summary": summary(result),
        "targets": [t.to_dict() for t in result.targets],
        "files": result.files,
        "warnings": result.warnings,
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, indent=2) + "\n"


def render_sarif(result: AuditResult, profile: str) -> str:
    used = sorted({f.rule_id for f in result.findings})
    rules = []
    for rule_id in used:
        rule = REGISTRY[rule_id]
        descriptor = {
            "id": rule.id,
            "name": rule.title,
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "help": {"text": rule.recommendation},
            "properties": {
                "category": rule.category_name,
                "tags": ["security", rule.category_name] + ([rule.cwe] if rule.cwe else []),
                "security-severity": _SECURITY_SEVERITY[rule.severity],
            },
        }
        if rule.references:
            descriptor["helpUri"] = rule.references[0]
        rules.append(descriptor)
    results = []
    for finding in result.findings:
        item = {
            "ruleId": finding.rule_id,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": f"{finding.message} [{finding.target}]"},
            "properties": {
                "severity": str(finding.severity),
                "confidence": str(finding.confidence),
                "target": finding.target,
                "security-severity": _SECURITY_SEVERITY[finding.severity],
                "fromDefault": finding.from_default,
            },
        }
        if finding.location:
            physical = {"artifactLocation": {"uri": finding.location.path}}
            if finding.location.line:
                physical["region"] = {"startLine": finding.location.line}
            item["locations"] = [{"physicalLocation": physical}]
        results.append(item)
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "php-ini-audit",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "properties": {"profile": profile},
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: AuditResult, profile: str) -> str:
    data = summary(result)
    lines = [
        "# PHP configuration audit",
        "",
        f"Profile: **{profile}** · path checks: **{'on' if result.path_checks else 'off'}** · "
        f"{data['configurations']} configuration(s), {data['overlays']} overlay(s), {data['files']} file(s)",
        "",
        "| Severity | Findings |",
        "| --- | ---: |",
    ]
    lines += [f"| {s} | {n} |" for s, n in data["by_severity"].items()]
    lines.append("")
    for severity in sorted(Severity, reverse=True):
        findings = [f for f in result.findings if f.severity == severity]
        if not findings:
            continue
        lines += [f"## {str(severity).capitalize()}", "", "| Rule | Finding | Location | Target | Confidence |",
                  "| --- | --- | --- | --- | --- |"]
        for f in findings:
            lines.append(
                f"| {f.rule_id} | **{_md_escape(f.title)}** — {_md_escape(f.message)} | {_md_escape(_where(f))} | "
                f"{_md_escape(f.target)} | {f.confidence} |"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def render_rules(fmt: str) -> str:
    rules = sorted(REGISTRY.values(), key=lambda r: r.id)
    if fmt == "json":
        return json.dumps(
            [
                {
                    "id": r.id,
                    "title": r.title,
                    "category": r.category_name,
                    "severity": str(r.severity),
                    "scope": r.scope,
                    "sapis": sorted(r.sapis) if r.sapis else None,
                    "production_only": r.production_only,
                    "directives": list(r.directives),
                    "description": r.description,
                    "recommendation": r.recommendation,
                    "cwe": r.cwe,
                    "references": list(r.references),
                }
                for r in rules
            ],
            indent=2,
        ) + "\n"
    if fmt == "markdown":
        lines = ["| Rule | Severity | Category | Title |", "| --- | --- | --- | --- |"]
        lines += [f"| {r.id} | {r.severity} | {r.category_name} | {_md_escape(r.title)} |" for r in rules]
        return "\n".join(lines) + "\n"
    return "".join(f"{r.id:14} {str(r.severity):8} {r.category_name:30} {r.title}\n" for r in rules)


def render_rule(rule_id: str) -> str:
    rule = REGISTRY[rule_id]
    lines = [
        f"{rule.id}  {rule.title}",
        f"severity:   {rule.severity}" + (f" (development: {rule.dev_severity})" if rule.dev_severity is not None else ""),
        f"category:   {rule.category_name}",
        f"scope:      {rule.scope}" + (f", SAPIs: {', '.join(sorted(rule.sapis))}" if rule.sapis else ""),
    ]
    if rule.directives:
        lines.append(f"directives: {', '.join(rule.directives)}")
    if rule.cwe:
        lines.append(f"weakness:   {rule.cwe}")
    lines += ["", rule.description, "", f"Fix: {rule.recommendation}"]
    lines += [f"See: {ref}" for ref in rule.references]
    return "\n".join(lines) + "\n"
