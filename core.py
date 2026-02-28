"""
AWS Security Audit Tool — Core Models & Base Classes

Provides the data-model for findings and the abstract base every auditor extends.
"""

from __future__ import annotations

import abc
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

import boto3
import botocore.exceptions

from .config import SEVERITY_ORDER

log = logging.getLogger("aws_audit")


# ──────────────────────────────────────────────
# Finding data-model
# ──────────────────────────────────────────────
@dataclass
class Finding:
    """A single security finding produced by an auditor."""

    title: str
    severity: str                       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    service: str                        # e.g. "IAM", "S3", "EC2"
    category: str                       # e.g. "Privilege Escalation", "Misconfiguration"
    description: str
    resource_id: str                    # ARN or identifier
    region: str = "global"
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    compliance: list[str] = field(default_factory=list)  # e.g. ["CIS 1.1", "SOC2"]

    def to_dict(self) -> dict:
        return asdict(self)


# ──────────────────────────────────────────────
# Abstract Auditor
# ──────────────────────────────────────────────
class BaseAuditor(abc.ABC):
    """
    Every service auditor inherits from this class.

    Sub-classes must implement:
        • service_name  — property returning e.g. "IAM"
        • run()         — executes checks, populates self.findings
    """

    def __init__(self, session: boto3.Session, regions: list[str] | None = None):
        self.session = session
        self.regions = regions or ["us-east-1"]
        self.findings: list[Finding] = []
        self.errors: list[dict[str, str]] = []
        self.account_id: str = self._resolve_account_id()

    # ── helpers ────────────────────────────────
    def _resolve_account_id(self) -> str:
        try:
            sts = self.session.client("sts")
            return sts.get_caller_identity()["Account"]
        except Exception:
            return "unknown"

    def client(self, service: str, region: str | None = None):
        """Return a boto3 client, honouring region."""
        return self.session.client(service, region_name=region or self.regions[0])

    def add_finding(self, **kwargs) -> None:
        self.findings.append(Finding(**kwargs))

    def _safe_api_call(self, func, *args, **kwargs) -> Any | None:
        """Wrap AWS API calls so a single failure doesn't crash the whole audit."""
        try:
            return func(*args, **kwargs)
        except botocore.exceptions.ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            error_msg = exc.response["Error"]["Message"]
            log.warning("[%s] API error %s: %s", self.service_name, error_code, error_msg)
            self.errors.append({"service": self.service_name, "error": f"{error_code}: {error_msg}"})
            return None
        except botocore.exceptions.EndpointConnectionError as exc:
            log.warning("[%s] Endpoint connection error: %s", self.service_name, exc)
            self.errors.append({"service": self.service_name, "error": str(exc)})
            return None
        except Exception as exc:
            log.warning("[%s] Unexpected error: %s", self.service_name, exc)
            self.errors.append({"service": self.service_name, "error": str(exc)})
            return None

    def _paginate(self, service: str, method: str, key: str,
                  region: str | None = None, **kwargs) -> list:
        """Generic paginator wrapper — returns the aggregated list for *key*."""
        client = self.client(service, region)
        paginator = client.get_paginator(method)
        items: list = []
        try:
            for page in paginator.paginate(**kwargs):
                items.extend(page.get(key, []))
        except botocore.exceptions.ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            error_msg = exc.response["Error"]["Message"]
            log.warning("[%s] Paginate %s error %s: %s",
                        self.service_name, method, error_code, error_msg)
            self.errors.append({"service": self.service_name,
                                "error": f"{method} → {error_code}: {error_msg}"})
        except Exception as exc:
            log.warning("[%s] Paginate %s unexpected error: %s",
                        self.service_name, method, exc)
            self.errors.append({"service": self.service_name, "error": str(exc)})
        return items

    # ── contract ───────────────────────────────
    @property
    @abc.abstractmethod
    def service_name(self) -> str: ...

    @abc.abstractmethod
    def run(self) -> None: ...


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity (CRITICAL first) then by service."""
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.service, f.title),
    )
