#!/usr/bin/env python3
"""
AWS Security Audit Tool
========================
A comprehensive AWS security scanner that identifies vulnerabilities,
risky permissions, misconfigurations, and privilege escalation attack
vectors across your AWS account.

Usage:
    python -m Cloud_AWS_ASM.scanner --profile myprofile --regions us-east-1,eu-west-1
    python -m Cloud_AWS_ASM.scanner --all-regions --output report.json
    python -m Cloud_AWS_ASM.scanner --services iam,s3,ec2 --quiet

Author : ASM Security Team
Version: 1.0.0
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3
import botocore.exceptions

from .core import Finding, sort_findings
from .report import generate_report, generate_csv, generate_summary_txt, print_summary

# ── Auditor registry ──────────────────────────
from .auditors.iam_auditor import IAMAuditor
from .auditors.s3_auditor import S3Auditor
from .auditors.ec2_vpc_auditor import EC2VPCAuditor
from .auditors.rds_auditor import RDSAuditor
from .auditors.logging_auditor import LoggingAuditor
from .auditors.lambda_kms_auditor import LambdaAuditor, KMSAuditor
from .auditors.privesc_auditor import PrivilegeEscalationAuditor
from .auditors.ecs_auditor import ECSAuditor

SERVICE_AUDITORS = {
    "iam":       IAMAuditor,
    "s3":        S3Auditor,
    "ec2":       EC2VPCAuditor,
    "rds":       RDSAuditor,
    "logging":   LoggingAuditor,
    "lambda":    LambdaAuditor,
    "kms":       KMSAuditor,
    "ecs":       ECSAuditor,
    "privesc":   PrivilegeEscalationAuditor,
}

ALL_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "eu-south-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
    "ap-northeast-3", "ap-south-1", "ap-east-1",
    "sa-east-1", "ca-central-1", "me-south-1", "af-south-1",
]

log = logging.getLogger("aws_audit")


# ══════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aws-security-audit",
        description="AWS Security Audit Tool — identify vulnerabilities, misconfigurations & privilege escalation paths",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s --profile prod --regions us-east-1,eu-west-1 --output audit.json
  %(prog)s --all-regions --services iam,s3,privesc
  %(prog)s --severity CRITICAL,HIGH --json-only
""",
    )
    parser.add_argument(
        "--profile", "-p",
        help="AWS CLI profile name (default: default/env credentials)",
    )
    parser.add_argument(
        "--regions", "-r",
        default="us-east-1",
        help="Comma-separated AWS regions (default: us-east-1)",
    )
    parser.add_argument(
        "--all-regions", action="store_true",
        help="Scan all commercial AWS regions",
    )
    parser.add_argument(
        "--services", "-s",
        default=",".join(SERVICE_AUDITORS.keys()),
        help=f"Comma-separated services to audit (available: {', '.join(SERVICE_AUDITORS.keys())})",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output JSON file path (default: aws_audit_<account>_<timestamp>.json)",
    )
    parser.add_argument(
        "--severity",
        default=None,
        help="Only report findings at or above this severity (e.g. HIGH or CRITICAL,HIGH)",
    )
    parser.add_argument(
        "--json-only", action="store_true",
        help="Print raw JSON to stdout instead of the summary table",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress progress output (logging)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args(argv)


# ══════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════
def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # Logging setup
    level = logging.WARNING if args.quiet else (logging.DEBUG if args.verbose else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )

    # Regions
    regions = ALL_REGIONS if args.all_regions else [r.strip() for r in args.regions.split(",")]

    # Services
    requested = [s.strip().lower() for s in args.services.split(",")]
    for s in requested:
        if s not in SERVICE_AUDITORS:
            log.error("Unknown service '%s' — available: %s", s, ", ".join(SERVICE_AUDITORS.keys()))
            return 1

    # Severity filter
    severity_filter: set[str] | None = None
    if args.severity:
        severity_filter = {s.strip().upper() for s in args.severity.split(",")}

    # Session
    try:
        session_kwargs = {}
        if args.profile:
            session_kwargs["profile_name"] = args.profile
        session = boto3.Session(**session_kwargs)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        caller_arn = identity["Arn"]
        log.info("Authenticated as %s (account %s)", caller_arn, account_id)
    except botocore.exceptions.NoCredentialsError:
        log.error("No AWS credentials found. Configure via 'aws configure', env vars, or --profile.")
        return 1
    except botocore.exceptions.ClientError as exc:
        log.error("Failed to authenticate with AWS: %s", exc)
        return 1

    # ── Run auditors ──────────────────────────
    all_findings: list[Finding] = []
    all_errors: list[dict[str, str]] = []
    start_time = time.time()

    log.info("=" * 60)
    log.info("  AWS Security Audit — Account %s", account_id)
    log.info("  Regions: %s", ", ".join(regions))
    log.info("  Services: %s", ", ".join(requested))
    log.info("=" * 60)

    for svc_key in requested:
        auditor_cls = SERVICE_AUDITORS[svc_key]
        auditor = auditor_cls(session=session, regions=regions)
        try:
            auditor.run()
        except Exception as exc:
            log.error("[%s] Auditor crashed: %s", svc_key, exc, exc_info=args.verbose)
            all_errors.append({"service": svc_key, "error": f"Auditor exception: {exc}"})
        all_findings.extend(auditor.findings)
        all_errors.extend(auditor.errors)

    elapsed = time.time() - start_time

    # Severity filter
    if severity_filter:
        all_findings = [f for f in all_findings if f.severity in severity_filter]

    # ── Report ─────────────────────────────────
    if not args.output:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        args.output = f"aws_audit_{account_id}_{ts}.json"

    report = generate_report(
        findings=all_findings,
        errors=all_errors,
        account_id=account_id,
        regions=regions,
        duration_seconds=elapsed,
        output_path=args.output,
    )

    # Derive CSV and TXT paths from JSON output path
    json_path = Path(args.output)
    csv_path = json_path.with_suffix(".csv")
    txt_path = json_path.with_name(json_path.stem.replace("aws_audit", "summary", 1) + ".txt")
    if txt_path == json_path.with_suffix(".txt"):
        txt_path = json_path.with_suffix(".txt")  # fallback
    txt_path = json_path.with_suffix(".txt")

    generate_csv(report, csv_path)
    generate_summary_txt(report, txt_path)

    if args.json_only:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_summary(report)
        print(f"\n  Reports saved:")
        print(f"    JSON:    {args.output}")
        print(f"    CSV:     {csv_path}")
        print(f"    Summary: {txt_path}\n")

    # Exit code: 2 if CRITICAL, 1 if HIGH, 0 otherwise
    severities = {f.severity for f in all_findings}
    if "CRITICAL" in severities:
        return 2
    if "HIGH" in severities:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
