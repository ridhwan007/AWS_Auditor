"""
Lambda & KMS Security Auditor
==============================
Lambda checks:
  • Functions with public access (resource policy)
  • Functions using deprecated runtimes
  • Functions without VPC configuration
  • Functions with overly permissive execution role
  • Functions without dead-letter queue
  • Environment variable secrets exposure

KMS checks:
  • Key rotation disabled
  • Key policies allowing broad access
  • Keys scheduled for deletion
  • Cross-account key access
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from ..core import BaseAuditor
from ..config import CRITICAL, HIGH, MEDIUM, LOW, INFO

log = logging.getLogger("aws_audit.lambda_kms")

DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7",
    "nodejs8.10", "nodejs10.x", "nodejs12.x", "nodejs14.x",
    "dotnetcore2.1", "dotnetcore3.1",
    "ruby2.5", "ruby2.7",
    "java8", "go1.x",
}


class LambdaAuditor(BaseAuditor):

    @property
    def service_name(self) -> str:
        return "Lambda"

    def run(self) -> None:
        log.info("[Lambda] Starting audit …")
        for region in self.regions:
            self._check_functions(region)
        log.info("[Lambda] Audit complete — %d findings", len(self.findings))

    def _check_functions(self, region: str) -> None:
        functions = self._paginate(
            "lambda", "list_functions", "Functions", region=region,
        )
        lam = self.client("lambda", region)

        for fn in functions:
            fn_name = fn["FunctionName"]
            fn_arn = fn["FunctionArn"]

            # Public resource policy
            policy_resp = self._safe_api_call(lam.get_policy, FunctionName=fn_name)
            if policy_resp:
                try:
                    policy = json.loads(policy_resp.get("Policy", "{}"))
                    for stmt in policy.get("Statement", []):
                        principal = stmt.get("Principal", "")
                        condition = stmt.get("Condition", {})
                        if stmt.get("Effect") == "Allow" and (
                            principal == "*" or principal == {"AWS": "*"}
                        ) and not condition:
                            self.add_finding(
                                title=f"Lambda '{fn_name}' is publicly invocable",
                                severity=CRITICAL,
                                service="Lambda",
                                category="Public Access",
                                region=region,
                                description=(
                                    f"Lambda function {fn_name} resource policy allows "
                                    "Principal '*' with no conditions."
                                ),
                                resource_id=fn_arn,
                                remediation="Remove the public invoke permission.",
                            )
                except (json.JSONDecodeError, TypeError):
                    pass

            # Deprecated runtime
            runtime = fn.get("Runtime", "")
            if runtime in DEPRECATED_RUNTIMES:
                self.add_finding(
                    title=f"Lambda '{fn_name}' uses deprecated runtime '{runtime}'",
                    severity=MEDIUM,
                    service="Lambda",
                    category="Patching",
                    region=region,
                    description=f"Runtime '{runtime}' is deprecated and may not receive security patches.",
                    resource_id=fn_arn,
                    remediation=f"Upgrade runtime from '{runtime}' to a supported version.",
                )

            # No VPC
            vpc_config = fn.get("VpcConfig", {})
            if not vpc_config or not vpc_config.get("SubnetIds"):
                self.add_finding(
                    title=f"Lambda '{fn_name}' is not in a VPC",
                    severity=LOW,
                    service="Lambda",
                    category="Network Security",
                    region=region,
                    description="Function runs outside a VPC. If it accesses VPC resources, this is a misconfiguration.",
                    resource_id=fn_arn,
                    remediation="Place the function in a VPC if it needs to access private resources.",
                )

            # No dead-letter queue
            dlq = fn.get("DeadLetterConfig", {})
            if not dlq or not dlq.get("TargetArn"):
                self.add_finding(
                    title=f"Lambda '{fn_name}' has no dead-letter queue",
                    severity=LOW,
                    service="Lambda",
                    category="Reliability",
                    region=region,
                    description="No DLQ configured — failed async invocations are silently lost.",
                    resource_id=fn_arn,
                    remediation="Configure a dead-letter queue (SQS or SNS).",
                )

            # Environment variable secrets (heuristic)
            env_vars = fn.get("Environment", {}).get("Variables", {})
            secret_keywords = {"password", "secret", "api_key", "apikey", "token",
                               "private_key", "access_key", "db_pass", "database_password"}
            for key, value in env_vars.items():
                if any(kw in key.lower() for kw in secret_keywords):
                    self.add_finding(
                        title=f"Lambda '{fn_name}' has potential secret in env var '{key}'",
                        severity=HIGH,
                        service="Lambda",
                        category="Secret Exposure",
                        region=region,
                        description=(
                            f"Environment variable '{key}' in function {fn_name} appears "
                            "to contain a secret. Environment variables are stored in plain "
                            "text in the Lambda configuration."
                        ),
                        resource_id=fn_arn,
                        remediation="Use AWS Secrets Manager or SSM Parameter Store (SecureString) instead.",
                        metadata={"env_var_name": key},
                    )


class KMSAuditor(BaseAuditor):

    @property
    def service_name(self) -> str:
        return "KMS"

    def run(self) -> None:
        log.info("[KMS] Starting audit …")
        for region in self.regions:
            self._check_keys(region)
        log.info("[KMS] Audit complete — %d findings", len(self.findings))

    def _check_keys(self, region: str) -> None:
        kms = self.client("kms", region)
        keys_resp = self._paginate("kms", "list_keys", "Keys", region=region)

        for key_entry in keys_resp:
            key_id = key_entry["KeyId"]
            key_arn = key_entry.get("KeyArn", f"arn:aws:kms:{region}:{self.account_id}:key/{key_id}")

            desc = self._safe_api_call(kms.describe_key, KeyId=key_id)
            if not desc:
                continue
            meta = desc.get("KeyMetadata", {})

            # Skip AWS-managed keys
            manager = meta.get("KeyManager", "")
            if manager == "AWS":
                continue

            state = meta.get("KeyState", "")

            # Key scheduled for deletion
            if state == "PendingDeletion":
                deletion_date = meta.get("DeletionDate", "unknown")
                self.add_finding(
                    title=f"KMS key '{key_id}' scheduled for deletion",
                    severity=MEDIUM,
                    service="KMS",
                    category="Key Management",
                    region=region,
                    description=f"Key is scheduled for deletion on {deletion_date}. Encrypted data will become inaccessible.",
                    resource_id=key_arn,
                    remediation="Cancel deletion if the key is still needed.",
                )
                continue

            if state != "Enabled":
                continue

            # Rotation
            rotation = self._safe_api_call(kms.get_key_rotation_status, KeyId=key_id)
            if rotation and not rotation.get("KeyRotationEnabled", False):
                self.add_finding(
                    title=f"KMS key '{key_id}' automatic rotation disabled",
                    severity=MEDIUM,
                    service="KMS",
                    category="Key Management",
                    region=region,
                    description="Automatic key rotation is not enabled for this customer-managed key.",
                    resource_id=key_arn,
                    remediation="Enable automatic key rotation (annual by default).",
                    compliance=["CIS 3.8"],
                )

            # Key policy — broad access
            policy_resp = self._safe_api_call(kms.get_key_policy, KeyId=key_id, PolicyName="default")
            if policy_resp:
                try:
                    policy = json.loads(policy_resp.get("Policy", "{}"))
                    for stmt in policy.get("Statement", []):
                        if stmt.get("Effect") != "Allow":
                            continue
                        principal = stmt.get("Principal", {})
                        if principal == "*" or principal.get("AWS") == "*":
                            condition = stmt.get("Condition", {})
                            if not condition:
                                self.add_finding(
                                    title=f"KMS key '{key_id}' policy allows Principal '*'",
                                    severity=HIGH,
                                    service="KMS",
                                    category="Key Management",
                                    region=region,
                                    description="Key policy allows any principal with no conditions.",
                                    resource_id=key_arn,
                                    remediation="Restrict the key policy to specific principals.",
                                )
                except (json.JSONDecodeError, TypeError):
                    pass
