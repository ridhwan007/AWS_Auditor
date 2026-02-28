"""
Report Generator
================
Produces structured JSON (and optional summary) output from audit findings.

Output structure:
{
  "metadata": { ... },
  "summary": { ... },
  "findings": [ ... ],
  "errors": [ ... ]
}
"""

from __future__ import annotations

import csv
import io
import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core import Finding, sort_findings
from .config import SEVERITY_ORDER

log = logging.getLogger("aws_audit.report")


def generate_report(
    findings: list[Finding],
    errors: list[dict[str, str]],
    account_id: str,
    regions: list[str],
    duration_seconds: float,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """
    Build the full JSON report and optionally write it to disk.

    Returns the report dict.
    """
    sorted_findings = sort_findings(findings)
    now = datetime.now(timezone.utc)

    # ── Summary statistics ─────────────────────
    severity_counts = Counter(f.severity for f in sorted_findings)
    service_counts = Counter(f.service for f in sorted_findings)
    category_counts = Counter(f.category for f in sorted_findings)

    # Risk score: weighted sum
    weight = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    risk_score = sum(weight.get(f.severity, 0) for f in sorted_findings)

    # Risk rating
    if risk_score == 0:
        risk_rating = "EXCELLENT"
    elif risk_score <= 10:
        risk_rating = "GOOD"
    elif risk_score <= 50:
        risk_rating = "MODERATE"
    elif risk_score <= 150:
        risk_rating = "HIGH"
    else:
        risk_rating = "CRITICAL"

    # Privilege escalation summary
    privesc_findings = [f for f in sorted_findings if f.category == "Privilege Escalation"]
    privesc_techniques = set()
    for f in privesc_findings:
        tech = f.metadata.get("technique", "")
        if tech:
            privesc_techniques.add(tech)

    report: dict[str, Any] = {
        "metadata": {
            "tool": "AWS Security Audit Tool",
            "version": "1.0.0",
            "timestamp": now.isoformat(),
            "account_id": account_id,
            "regions_scanned": regions,
            "scan_duration_seconds": round(duration_seconds, 2),
        },
        "summary": {
            "total_findings": len(sorted_findings),
            "risk_score": risk_score,
            "risk_rating": risk_rating,
            "severity_breakdown": {
                sev: severity_counts.get(sev, 0)
                for sev in SEVERITY_ORDER
            },
            "service_breakdown": dict(service_counts.most_common()),
            "category_breakdown": dict(category_counts.most_common()),
            "privilege_escalation": {
                "total_paths": len(privesc_findings),
                "unique_techniques": len(privesc_techniques),
                "techniques": sorted(privesc_techniques),
            },
            "top_affected_resources": _top_resources(sorted_findings, n=10),
        },
        "findings": [f.to_dict() for f in sorted_findings],
        "errors": errors,
    }

    # ── Write to file ──────────────────────────
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        log.info("Report written to %s", output_path)

    return report


def _top_resources(findings: list[Finding], n: int = 10) -> list[dict[str, Any]]:
    """Return the top N resources with the most / highest-severity findings."""
    resource_data: dict[str, dict] = {}
    for f in findings:
        key = f.resource_id
        if key not in resource_data:
            resource_data[key] = {
                "resource_id": key,
                "service": f.service,
                "finding_count": 0,
                "highest_severity": "INFO",
                "severities": [],
            }
        resource_data[key]["finding_count"] += 1
        resource_data[key]["severities"].append(f.severity)
        if SEVERITY_ORDER.get(f.severity, 99) < SEVERITY_ORDER.get(
            resource_data[key]["highest_severity"], 99
        ):
            resource_data[key]["highest_severity"] = f.severity

    ranked = sorted(
        resource_data.values(),
        key=lambda r: (
            SEVERITY_ORDER.get(r["highest_severity"], 99),
            -r["finding_count"],
        ),
    )
    # Clean up
    for r in ranked:
        r["severity_breakdown"] = dict(Counter(r.pop("severities")))
    return ranked[:n]


def print_summary(report: dict[str, Any]) -> None:
    """Print a coloured summary to the terminal (using rich if available)."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel

        console = Console()
        meta = report["metadata"]
        summary = report["summary"]

        # Header
        console.print(Panel(
            f"[bold]AWS Security Audit Report[/bold]\n"
            f"Account: [cyan]{meta['account_id']}[/cyan]  |  "
            f"Regions: {', '.join(meta['regions_scanned'])}  |  "
            f"Duration: {meta['scan_duration_seconds']}s\n"
            f"Timestamp: {meta['timestamp']}",
            title="[bold blue]AWS Security Audit Tool v{0}[/bold blue]".format(meta['version']),
        ))

        # Risk
        rating = summary["risk_rating"]
        colour = {"EXCELLENT": "green", "GOOD": "green", "MODERATE": "yellow",
                  "HIGH": "red", "CRITICAL": "bold red"}.get(rating, "white")
        console.print(f"\n  Risk Score: [bold]{summary['risk_score']}[/bold]  "
                       f"Rating: [{colour}]{rating}[/{colour}]\n")

        # Severity table
        sev_table = Table(title="Findings by Severity")
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="right")
        colours = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                   "LOW": "cyan", "INFO": "dim"}
        for sev, count in summary["severity_breakdown"].items():
            sev_table.add_row(f"[{colours.get(sev, 'white')}]{sev}[/]", str(count))
        console.print(sev_table)

        # Privesc
        pe = summary["privilege_escalation"]
        if pe["total_paths"] > 0:
            console.print(f"\n  [bold red]⚠  Privilege Escalation Paths: {pe['total_paths']}[/bold red]  "
                           f"(Techniques: {pe['unique_techniques']})")
            for t in pe["techniques"]:
                console.print(f"     • {t}")

        # Service table
        svc_table = Table(title="\nFindings by Service")
        svc_table.add_column("Service")
        svc_table.add_column("Count", justify="right")
        for svc, cnt in summary["service_breakdown"].items():
            svc_table.add_row(svc, str(cnt))
        console.print(svc_table)

        # Errors
        if report["errors"]:
            console.print(f"\n  [yellow]Errors during scan: {len(report['errors'])}[/yellow]")

    except ImportError:
        # Fallback plain text
        summary = report["summary"]
        print("\n" + "=" * 60)
        print("  AWS SECURITY AUDIT REPORT")
        print("=" * 60)
        print(f"  Account:  {report['metadata']['account_id']}")
        print(f"  Regions:  {', '.join(report['metadata']['regions_scanned'])}")
        print(f"  Duration: {report['metadata']['scan_duration_seconds']}s")
        print(f"  Risk Score: {summary['risk_score']}  Rating: {summary['risk_rating']}")
        print()
        print("  Severity Breakdown:")
        for sev, cnt in summary["severity_breakdown"].items():
            print(f"    {sev:<10} {cnt}")
        print()
        pe = summary["privilege_escalation"]
        if pe["total_paths"] > 0:
            print(f"  ⚠  Privilege Escalation Paths: {pe['total_paths']}")
        print("=" * 60)


# ══════════════════════════════════════════════
# CSV Output
# ══════════════════════════════════════════════
def generate_csv(report: dict[str, Any], output_path: str | Path) -> None:
    """Write a CSV with one row per finding: title, severity, service, category, resource, region, remediation."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "finding_id", "severity", "service", "category",
        "title", "resource_id", "region", "description",
        "remediation", "compliance",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for f in report.get("findings", []):
            row = {
                "finding_id": f.get("finding_id", ""),
                "severity": f.get("severity", ""),
                "service": f.get("service", ""),
                "category": f.get("category", ""),
                "title": f.get("title", ""),
                "resource_id": f.get("resource_id", ""),
                "region": f.get("region", ""),
                "description": f.get("description", ""),
                "remediation": f.get("remediation", ""),
                "compliance": "; ".join(f.get("compliance", [])),
            }
            writer.writerow(row)

    log.info("CSV report written to %s", output_path)


# ══════════════════════════════════════════════
# Text Summary Output
# ══════════════════════════════════════════════
def generate_summary_txt(report: dict[str, Any], output_path: str | Path) -> None:
    """Write a human-readable summary.txt with full audit details."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    meta = report["metadata"]
    summary = report["summary"]
    findings = report.get("findings", [])
    errors = report.get("errors", [])

    lines: list[str] = []
    w = lines.append  # shorthand

    w("=" * 72)
    w("  AWS SECURITY AUDIT REPORT")
    w("=" * 72)
    w(f"  Tool:      {meta['tool']} v{meta['version']}")
    w(f"  Account:   {meta['account_id']}")
    w(f"  Timestamp: {meta['timestamp']}")
    w(f"  Regions:   {', '.join(meta['regions_scanned'])}")
    w(f"  Duration:  {meta['scan_duration_seconds']}s")
    w("")
    w("-" * 72)
    w("  RISK ASSESSMENT")
    w("-" * 72)
    w(f"  Total Findings:  {summary['total_findings']}")
    w(f"  Risk Score:      {summary['risk_score']}")
    w(f"  Risk Rating:     {summary['risk_rating']}")
    w("")
    w("  Severity Breakdown:")
    for sev, cnt in summary["severity_breakdown"].items():
        bar = "#" * cnt
        w(f"    {sev:<10} {cnt:>4}  {bar}")
    w("")

    # Privilege escalation
    pe = summary.get("privilege_escalation", {})
    if pe.get("total_paths", 0) > 0:
        w("-" * 72)
        w("  PRIVILEGE ESCALATION PATHS")
        w("-" * 72)
        w(f"  Total Paths:        {pe['total_paths']}")
        w(f"  Unique Techniques:  {pe['unique_techniques']}")
        for t in pe.get("techniques", []):
            w(f"    - {t}")
        w("")

    # Service breakdown
    w("-" * 72)
    w("  FINDINGS BY SERVICE")
    w("-" * 72)
    for svc, cnt in summary.get("service_breakdown", {}).items():
        w(f"    {svc:<25} {cnt}")
    w("")

    # Category breakdown
    w("-" * 72)
    w("  FINDINGS BY CATEGORY")
    w("-" * 72)
    for cat, cnt in summary.get("category_breakdown", {}).items():
        w(f"    {cat:<35} {cnt}")
    w("")

    # Top affected resources
    top = summary.get("top_affected_resources", [])
    if top:
        w("-" * 72)
        w("  TOP AFFECTED RESOURCES")
        w("-" * 72)
        for i, res in enumerate(top, 1):
            w(f"  {i:>2}. [{res['highest_severity']}] {res['resource_id']}")
            w(f"      Service: {res['service']}  |  Findings: {res['finding_count']}")
        w("")

    # Detailed findings grouped by severity
    w("=" * 72)
    w("  DETAILED FINDINGS")
    w("=" * 72)

    current_severity = None
    for idx, f in enumerate(findings, 1):
        sev = f.get("severity", "")
        if sev != current_severity:
            current_severity = sev
            w("")
            w(f"  ── {sev} " + "─" * (60 - len(sev)))

        w(f"")
        w(f"  [{idx}] {f.get('title', '')}")
        w(f"      Severity:  {sev}")
        w(f"      Service:   {f.get('service', '')}")
        w(f"      Category:  {f.get('category', '')}")
        w(f"      Region:    {f.get('region', '')}")
        w(f"      Resource:  {f.get('resource_id', '')}")
        w(f"      Description:")
        # Wrap description lines
        desc = f.get("description", "")
        for desc_line in _wrap_text(desc, 62):
            w(f"        {desc_line}")
        remediation = f.get("remediation", "")
        if remediation:
            w(f"      Remediation:")
            for rem_line in _wrap_text(remediation, 62):
                w(f"        {rem_line}")
        compliance = f.get("compliance", [])
        if compliance:
            w(f"      Compliance: {'; '.join(compliance)}")

    # Errors
    if errors:
        w("")
        w("-" * 72)
        w(f"  ERRORS ({len(errors)})")
        w("-" * 72)
        for err in errors:
            w(f"    [{err.get('service', '?')}] {err.get('error', '')}")

    w("")
    w("=" * 72)
    w(f"  End of report — {summary['total_findings']} findings")
    w("=" * 72)

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    log.info("Text summary written to %s", output_path)


def _wrap_text(text: str, width: int = 62) -> list[str]:
    """Simple word-wrap for plain text output."""
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    length = 0
    for word in words:
        if length + len(word) + 1 > width and current:
            lines.append(" ".join(current))
            current = [word]
            length = len(word)
        else:
            current.append(word)
            length += len(word) + 1
    if current:
        lines.append(" ".join(current))
    return lines or [""]
