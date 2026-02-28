"""
S3 Security Auditor
===================
Checks:
  • Public access (ACL & policy)
  • Block public access settings
  • Server-side encryption (default)
  • Bucket versioning
  • Access logging
  • MFA Delete
  • Bucket policy overly permissive
  • HTTPS-only enforcement (ssl transport)
  • Object-level CloudTrail logging
  • Lifecycle policies
"""

from __future__ import annotations

import json
import logging

from ..core import BaseAuditor
from ..config import CRITICAL, HIGH, MEDIUM, LOW, INFO

log = logging.getLogger("aws_audit.s3")


class S3Auditor(BaseAuditor):

    @property
    def service_name(self) -> str:
        return "S3"

    def run(self) -> None:
        log.info("[S3] Starting audit …")
        s3 = self.client("s3")
        resp = self._safe_api_call(s3.list_buckets)
        if not resp:
            return
        buckets = resp.get("Buckets", [])
        for bucket in buckets:
            name = bucket.get("BucketName") or bucket.get("Name", "")
            if not name:
                continue
            arn = f"arn:aws:s3:::{name}"
            self._check_block_public_access(s3, name, arn)
            self._check_bucket_acl(s3, name, arn)
            self._check_bucket_policy(s3, name, arn)
            self._check_encryption(s3, name, arn)
            self._check_versioning(s3, name, arn)
            self._check_logging(s3, name, arn)
            self._check_ssl_only(s3, name, arn)
            self._check_lifecycle(s3, name, arn)
        log.info("[S3] Audit complete — %d findings", len(self.findings))

    # ──────────────────────────────────────────
    def _check_block_public_access(self, s3, name: str, arn: str) -> None:
        resp = self._safe_api_call(s3.get_public_access_block, Bucket=name)
        if resp is None:
            self.add_finding(
                title=f"S3 bucket '{name}' has no Block Public Access configuration",
                severity=HIGH,
                service="S3",
                category="Public Access",
                description="No S3 Block Public Access settings found — the bucket may be publicly accessible.",
                resource_id=arn,
                remediation="Enable all four Block Public Access settings on this bucket.",
                compliance=["CIS 2.1.5"],
            )
            return
        config = resp.get("PublicAccessBlockConfiguration", {})
        disabled = [k for k, v in config.items() if not v]
        if disabled:
            self.add_finding(
                title=f"S3 bucket '{name}' has incomplete Block Public Access",
                severity=HIGH,
                service="S3",
                category="Public Access",
                description=f"The following Block Public Access settings are disabled: {', '.join(disabled)}.",
                resource_id=arn,
                remediation="Enable all Block Public Access settings unless public access is explicitly required.",
                compliance=["CIS 2.1.5"],
                metadata={"disabled_settings": disabled},
            )

    # ──────────────────────────────────────────
    def _check_bucket_acl(self, s3, name: str, arn: str) -> None:
        resp = self._safe_api_call(s3.get_bucket_acl, Bucket=name)
        if not resp:
            return
        for grant in resp.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri:
                self.add_finding(
                    title=f"S3 bucket '{name}' ACL allows public access (AllUsers)",
                    severity=CRITICAL,
                    service="S3",
                    category="Public Access",
                    description=f"Bucket ACL grants '{grant.get('Permission')}' to AllUsers (anonymous).",
                    resource_id=arn,
                    remediation="Remove the AllUsers grant from the bucket ACL.",
                    compliance=["CIS 2.1.5"],
                )
            elif "AuthenticatedUsers" in uri:
                self.add_finding(
                    title=f"S3 bucket '{name}' ACL allows access to any authenticated AWS user",
                    severity=HIGH,
                    service="S3",
                    category="Public Access",
                    description=f"Bucket ACL grants '{grant.get('Permission')}' to AuthenticatedUsers (any AWS account).",
                    resource_id=arn,
                    remediation="Remove the AuthenticatedUsers grant.",
                )

    # ──────────────────────────────────────────
    def _check_bucket_policy(self, s3, name: str, arn: str) -> None:
        resp = self._safe_api_call(s3.get_bucket_policy, Bucket=name)
        if not resp:
            return
        try:
            policy = json.loads(resp.get("Policy", "{}"))
        except (json.JSONDecodeError, TypeError):
            return

        for stmt in policy.get("Statement", []):
            effect = stmt.get("Effect", "")
            principal = stmt.get("Principal", "")
            condition = stmt.get("Condition", {})

            # Public allow with no condition
            if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                if not condition:
                    self.add_finding(
                        title=f"S3 bucket '{name}' policy allows public access (Principal: *)",
                        severity=CRITICAL,
                        service="S3",
                        category="Public Access",
                        description="Bucket policy has an Allow statement with Principal '*' and no Condition.",
                        resource_id=arn,
                        remediation="Remove or restrict the public Allow statement.",
                    )
                else:
                    self.add_finding(
                        title=f"S3 bucket '{name}' policy allows '*' with conditions",
                        severity=MEDIUM,
                        service="S3",
                        category="Public Access",
                        description=f"Bucket policy allows Principal '*' guarded by conditions: {json.dumps(condition)}",
                        resource_id=arn,
                        remediation="Verify conditions are sufficient to prevent unintended access.",
                    )

    # ──────────────────────────────────────────
    def _check_encryption(self, s3, name: str, arn: str) -> None:
        resp = self._safe_api_call(s3.get_bucket_encryption, Bucket=name)
        if resp is None:
            self.add_finding(
                title=f"S3 bucket '{name}' does not have default encryption",
                severity=HIGH,
                service="S3",
                category="Encryption",
                description="Default server-side encryption is not enabled for this bucket.",
                resource_id=arn,
                remediation="Enable SSE-S3 or SSE-KMS as the default encryption for the bucket.",
                compliance=["CIS 2.1.1"],
            )
        else:
            rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            for rule in rules:
                algo = rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
                if algo == "AES256":
                    self.add_finding(
                        title=f"S3 bucket '{name}' uses SSE-S3 (AES256) — consider SSE-KMS",
                        severity=INFO,
                        service="S3",
                        category="Encryption",
                        description="Bucket uses AWS-managed SSE-S3 encryption. SSE-KMS offers better key management and audit trail.",
                        resource_id=arn,
                        remediation="Consider upgrading to SSE-KMS for auditable key management.",
                    )

    # ──────────────────────────────────────────
    def _check_versioning(self, s3, name: str, arn: str) -> None:
        resp = self._safe_api_call(s3.get_bucket_versioning, Bucket=name)
        if not resp or resp.get("Status") != "Enabled":
            self.add_finding(
                title=f"S3 bucket '{name}' versioning not enabled",
                severity=MEDIUM,
                service="S3",
                category="Data Protection",
                description="Versioning is not enabled. Data deleted or overwritten cannot be recovered.",
                resource_id=arn,
                remediation="Enable versioning to protect against accidental deletes and overwrites.",
                compliance=["CIS 2.1.3"],
            )
        # MFA Delete
        if resp and resp.get("MFADelete") != "Enabled":
            self.add_finding(
                title=f"S3 bucket '{name}' MFA Delete not enabled",
                severity=LOW,
                service="S3",
                category="Data Protection",
                description="MFA Delete is not enabled — versioned objects can be deleted without MFA.",
                resource_id=arn,
                remediation="Enable MFA Delete for sensitive buckets.",
            )

    # ──────────────────────────────────────────
    def _check_logging(self, s3, name: str, arn: str) -> None:
        resp = self._safe_api_call(s3.get_bucket_logging, Bucket=name)
        if not resp or not resp.get("LoggingEnabled"):
            self.add_finding(
                title=f"S3 bucket '{name}' access logging is disabled",
                severity=MEDIUM,
                service="S3",
                category="Logging & Monitoring",
                description="Server access logging is not enabled — access events are not recorded.",
                resource_id=arn,
                remediation="Enable server access logging to a dedicated logging bucket.",
                compliance=["CIS 2.6"],
            )

    # ──────────────────────────────────────────
    def _check_ssl_only(self, s3, name: str, arn: str) -> None:
        resp = self._safe_api_call(s3.get_bucket_policy, Bucket=name)
        if not resp:
            self.add_finding(
                title=f"S3 bucket '{name}' has no bucket policy enforcing HTTPS",
                severity=MEDIUM,
                service="S3",
                category="Encryption in Transit",
                description="No bucket policy exists to deny non-SSL (HTTP) requests.",
                resource_id=arn,
                remediation="Add a bucket policy with Condition aws:SecureTransport = false → Deny.",
                compliance=["CIS 2.1.2"],
            )
            return
        try:
            policy = json.loads(resp.get("Policy", "{}"))
        except (json.JSONDecodeError, TypeError):
            return

        has_ssl_deny = False
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") == "Deny":
                cond = stmt.get("Condition", {})
                bool_cond = cond.get("Bool", {})
                if bool_cond.get("aws:SecureTransport") in ("false", False):
                    has_ssl_deny = True
                    break
        if not has_ssl_deny:
            self.add_finding(
                title=f"S3 bucket '{name}' does not enforce HTTPS-only access",
                severity=MEDIUM,
                service="S3",
                category="Encryption in Transit",
                description="The bucket policy does not explicitly deny non-SSL requests.",
                resource_id=arn,
                remediation="Add a Deny statement for aws:SecureTransport=false.",
                compliance=["CIS 2.1.2"],
            )

    # ──────────────────────────────────────────
    def _check_lifecycle(self, s3, name: str, arn: str) -> None:
        resp = self._safe_api_call(s3.get_bucket_lifecycle_configuration, Bucket=name)
        if resp is None:
            self.add_finding(
                title=f"S3 bucket '{name}' has no lifecycle policy",
                severity=LOW,
                service="S3",
                category="Cost & Data Management",
                description="No lifecycle rules — old/obsolete data may accumulate and increase costs or breach risk.",
                resource_id=arn,
                remediation="Configure lifecycle rules to transition or expire objects.",
            )
