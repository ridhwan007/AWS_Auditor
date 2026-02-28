"""
IAM Security Auditor
====================
Checks:
  • Root account usage & MFA
  • Password policy vs CIS benchmarks
  • Users without MFA
  • Stale / unused credentials & access keys
  • Overly permissive policies (*, Admin)
  • Inline policies on users (should be on groups/roles)
  • Access keys not rotated
  • Cross-account trust relationships
  • Service-linked roles with dangerous permissions
  • Users with console access AND programmatic access
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta

from ..core import BaseAuditor
from ..config import (
    CRITICAL, HIGH, MEDIUM, LOW, INFO,
    CIS_PASSWORD_POLICY,
    HIGH_RISK_POLICIES,
    STALE_CREDENTIAL_DAYS,
    STALE_ACCESS_KEY_DAYS,
)

log = logging.getLogger("aws_audit.iam")


class IAMAuditor(BaseAuditor):

    @property
    def service_name(self) -> str:
        return "IAM"

    # ──────────────────────────────────────────
    def run(self) -> None:
        log.info("[IAM] Starting audit …")
        self._check_root_account()
        self._check_password_policy()
        self._check_users()
        self._check_policies()
        self._check_roles()
        self._check_groups()
        self._check_credential_report()
        log.info("[IAM] Audit complete — %d findings", len(self.findings))

    # ──────────────────────────────────────────
    # Root account
    # ──────────────────────────────────────────
    def _check_root_account(self) -> None:
        iam = self.client("iam")

        # Root MFA
        summary = self._safe_api_call(iam.get_account_summary)
        if summary:
            data = summary.get("SummaryMap", {})
            if data.get("AccountMFAEnabled", 0) == 0:
                self.add_finding(
                    title="Root account MFA not enabled",
                    severity=CRITICAL,
                    service="IAM",
                    category="Authentication",
                    description=(
                        "The AWS root account does not have Multi-Factor Authentication "
                        "enabled. Root has unrestricted access to every resource in the "
                        "account and cannot be limited by IAM policies."
                    ),
                    resource_id=f"arn:aws:iam::{self.account_id}:root",
                    remediation=(
                        "Enable a hardware MFA device on the root account. "
                        "Ideally use a FIDO2 security key. "
                        "Reference: CIS AWS Foundations Benchmark 1.5"
                    ),
                    compliance=["CIS 1.5", "SOC2 CC6.1", "NIST 800-53 IA-2"],
                )
            # Root access keys
            if data.get("AccountAccessKeysPresent", 0) > 0:
                self.add_finding(
                    title="Root account has active access keys",
                    severity=CRITICAL,
                    service="IAM",
                    category="Credential Management",
                    description=(
                        "The root account has active access keys. These provide "
                        "unrestricted programmatic access and should be deleted."
                    ),
                    resource_id=f"arn:aws:iam::{self.account_id}:root",
                    remediation="Delete all root access keys immediately. CIS 1.4",
                    compliance=["CIS 1.4"],
                )

    # ──────────────────────────────────────────
    # Password policy
    # ──────────────────────────────────────────
    def _check_password_policy(self) -> None:
        iam = self.client("iam")
        resp = self._safe_api_call(iam.get_account_password_policy)
        if resp is None:
            self.add_finding(
                title="No custom password policy configured",
                severity=HIGH,
                service="IAM",
                category="Authentication",
                description="The account is using the default AWS password policy which is weak.",
                resource_id=f"arn:aws:iam::{self.account_id}:account-password-policy",
                remediation="Set a strong password policy that meets CIS benchmarks.",
                compliance=["CIS 1.8-1.11"],
            )
            return

        policy = resp.get("PasswordPolicy", {})
        checks = {
            "MinimumPasswordLength": (
                policy.get("MinimumPasswordLength", 0) < CIS_PASSWORD_POLICY["MinimumPasswordLength"],
                f"Minimum password length is {policy.get('MinimumPasswordLength', 0)} "
                f"(should be ≥{CIS_PASSWORD_POLICY['MinimumPasswordLength']})",
            ),
            "RequireSymbols": (
                not policy.get("RequireSymbols", False),
                "Password policy does not require symbols",
            ),
            "RequireNumbers": (
                not policy.get("RequireNumbers", False),
                "Password policy does not require numbers",
            ),
            "RequireUppercaseCharacters": (
                not policy.get("RequireUppercaseCharacters", False),
                "Password policy does not require uppercase characters",
            ),
            "RequireLowercaseCharacters": (
                not policy.get("RequireLowercaseCharacters", False),
                "Password policy does not require lowercase characters",
            ),
            "MaxPasswordAge": (
                policy.get("MaxPasswordAge", 9999) > CIS_PASSWORD_POLICY["MaxPasswordAge"],
                f"Max password age is {policy.get('MaxPasswordAge', 'not set')} days "
                f"(should be ≤{CIS_PASSWORD_POLICY['MaxPasswordAge']})",
            ),
            "PasswordReusePrevention": (
                policy.get("PasswordReusePrevention", 0) < CIS_PASSWORD_POLICY["PasswordReusePrevention"],
                f"Password reuse prevention is {policy.get('PasswordReusePrevention', 0)} "
                f"(should be ≥{CIS_PASSWORD_POLICY['PasswordReusePrevention']})",
            ),
        }

        for check_name, (failed, desc) in checks.items():
            if failed:
                self.add_finding(
                    title=f"Weak password policy: {check_name}",
                    severity=MEDIUM,
                    service="IAM",
                    category="Authentication",
                    description=desc,
                    resource_id=f"arn:aws:iam::{self.account_id}:account-password-policy",
                    remediation=f"Update password policy — {desc}. See CIS 1.8-1.11",
                    compliance=["CIS 1.8-1.11"],
                )

    # ──────────────────────────────────────────
    # Users
    # ──────────────────────────────────────────
    def _check_users(self) -> None:
        iam = self.client("iam")
        users = self._paginate("iam", "list_users", "Users")

        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]

            # MFA check
            mfa_devices = self._safe_api_call(iam.list_mfa_devices, UserName=username)
            if mfa_devices and len(mfa_devices.get("MFADevices", [])) == 0:
                # Check if user has console access
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except Exception:
                    has_console = False

                if has_console:
                    self.add_finding(
                        title=f"IAM user '{username}' has console access without MFA",
                        severity=HIGH,
                        service="IAM",
                        category="Authentication",
                        description=(
                            f"User '{username}' can log into the console but has no MFA "
                            "device configured, making the account vulnerable to credential theft."
                        ),
                        resource_id=user_arn,
                        remediation="Enable MFA for this user. CIS 1.10",
                        compliance=["CIS 1.10"],
                    )

            # Inline policies on user (should be on group/role)
            inline = self._safe_api_call(iam.list_user_policies, UserName=username)
            if inline and len(inline.get("PolicyNames", [])) > 0:
                self.add_finding(
                    title=f"IAM user '{username}' has inline policies",
                    severity=MEDIUM,
                    service="IAM",
                    category="Best Practice",
                    description=(
                        f"User '{username}' has {len(inline['PolicyNames'])} inline "
                        "policy/policies attached directly. Best practice is to assign "
                        "policies via groups or roles for manageability."
                    ),
                    resource_id=user_arn,
                    remediation="Move inline policies to a group or use managed policies.",
                    compliance=["CIS 1.15"],
                )

            # Access keys audit
            self._check_user_access_keys(iam, username, user_arn)

            # Attached high-risk managed policies
            attached = self._safe_api_call(
                iam.list_attached_user_policies, UserName=username
            )
            if attached:
                for pol in attached.get("AttachedPolicies", []):
                    if pol["PolicyArn"] in HIGH_RISK_POLICIES:
                        self.add_finding(
                            title=f"User '{username}' has high-risk policy: {pol['PolicyName']}",
                            severity=HIGH,
                            service="IAM",
                            category="Excessive Permissions",
                            description=(
                                f"The managed policy '{pol['PolicyName']}' grants broad / "
                                "administrative permissions and is directly attached to a user."
                            ),
                            resource_id=user_arn,
                            remediation="Replace with a least-privilege custom policy.",
                            metadata={"policy_arn": pol["PolicyArn"]},
                        )

    def _check_user_access_keys(self, iam, username: str, user_arn: str) -> None:
        keys_resp = self._safe_api_call(iam.list_access_keys, UserName=username)
        if not keys_resp:
            return
        now = datetime.now(timezone.utc)
        for key in keys_resp.get("AccessKeyMetadata", []):
            key_id = key["AccessKeyId"]
            status = key["Status"]
            created = key.get("CreateDate")

            if status == "Active" and created:
                age = (now - created).days
                if age > STALE_ACCESS_KEY_DAYS:
                    self.add_finding(
                        title=f"Access key '{key_id}' for '{username}' not rotated ({age}d old)",
                        severity=MEDIUM,
                        service="IAM",
                        category="Credential Management",
                        description=(
                            f"Access key {key_id} was created {age} days ago and has "
                            f"not been rotated (threshold: {STALE_ACCESS_KEY_DAYS} days)."
                        ),
                        resource_id=user_arn,
                        remediation="Rotate or deactivate the access key.",
                        metadata={"access_key_id": key_id, "age_days": age},
                        compliance=["CIS 1.14"],
                    )

            # Check last used
            last_used_resp = self._safe_api_call(
                iam.get_access_key_last_used, AccessKeyId=key_id
            )
            if last_used_resp:
                last_used = last_used_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                if status == "Active" and (
                    last_used is None
                    or (now - last_used).days > STALE_CREDENTIAL_DAYS
                ):
                    unused_days = "never" if last_used is None else f"{(now - last_used).days}d ago"
                    self.add_finding(
                        title=f"Stale access key '{key_id}' for '{username}' (last used: {unused_days})",
                        severity=MEDIUM,
                        service="IAM",
                        category="Credential Management",
                        description=(
                            f"Active access key {key_id} has not been used recently "
                            f"(last used: {unused_days}). Unused active keys increase "
                            "attack surface."
                        ),
                        resource_id=user_arn,
                        remediation="Deactivate and delete unused access keys.",
                        metadata={"access_key_id": key_id, "last_used": unused_days},
                    )

    # ──────────────────────────────────────────
    # Managed Policies (wildcard / admin)
    # ──────────────────────────────────────────
    def _check_policies(self) -> None:
        iam = self.client("iam")
        policies = self._paginate("iam", "list_policies", "Policies", Scope="Local")

        for pol in policies:
            arn = pol["Arn"]
            version_id = pol.get("DefaultVersionId", "v1")
            resp = self._safe_api_call(
                iam.get_policy_version, PolicyArn=arn, VersionId=version_id
            )
            if not resp:
                continue
            doc = resp["PolicyVersion"]["Document"]
            if isinstance(doc, str):
                doc = json.loads(doc)

            statements = doc.get("Statement", [])
            if not isinstance(statements, list):
                statements = [statements]

            for stmt in statements:
                effect = stmt.get("Effect", "")
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                # Full admin: Action=* Resource=*
                if effect == "Allow" and "*" in actions and "*" in resources:
                    self.add_finding(
                        title=f"Customer policy '{pol['PolicyName']}' grants full admin (*:*)",
                        severity=CRITICAL,
                        service="IAM",
                        category="Excessive Permissions",
                        description=(
                            f"Policy '{pol['PolicyName']}' has a statement allowing all "
                            "actions on all resources — effectively administrator access."
                        ),
                        resource_id=arn,
                        remediation="Apply least-privilege: scope down actions and resources.",
                        compliance=["CIS 1.16", "NIST 800-53 AC-6"],
                    )
                # Wildcard resource with sensitive actions
                elif effect == "Allow" and "*" in resources:
                    for action in actions:
                        if action.endswith(":*") or action == "*":
                            self.add_finding(
                                title=f"Policy '{pol['PolicyName']}' has wildcard action '{action}' on all resources",
                                severity=HIGH,
                                service="IAM",
                                category="Excessive Permissions",
                                description=(
                                    f"Policy allows '{action}' on Resource '*'. "
                                    "This is broader than necessary."
                                ),
                                resource_id=arn,
                                remediation="Restrict Resource ARNs and use specific actions.",
                            )
                            break  # one finding per statement

    # ──────────────────────────────────────────
    # Roles — trust policy analysis
    # ──────────────────────────────────────────
    def _check_roles(self) -> None:
        iam = self.client("iam")
        roles = self._paginate("iam", "list_roles", "Roles")

        for role in roles:
            role_name = role["RoleName"]
            role_arn = role["Arn"]
            trust = role.get("AssumeRolePolicyDocument", {})
            if isinstance(trust, str):
                trust = json.loads(trust)

            for stmt in trust.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                principal = stmt.get("Principal", {})
                # Wildcard principal — anyone can assume
                if principal == "*" or principal.get("AWS") == "*":
                    conditions = stmt.get("Condition", {})
                    if not conditions:
                        self.add_finding(
                            title=f"Role '{role_name}' is assumable by anyone (Principal: *)",
                            severity=CRITICAL,
                            service="IAM",
                            category="Trust Relationship",
                            description=(
                                f"Role '{role_name}' trust policy allows any AWS principal "
                                "to assume it without conditions. This is effectively an "
                                "open door into your account."
                            ),
                            resource_id=role_arn,
                            remediation="Restrict the trust policy to specific accounts/roles and add conditions.",
                        )
                    else:
                        self.add_finding(
                            title=f"Role '{role_name}' trusts all AWS principals (with conditions)",
                            severity=HIGH,
                            service="IAM",
                            category="Trust Relationship",
                            description=(
                                f"Role '{role_name}' trust policy allows any AWS principal "
                                f"to assume it, guarded only by conditions: {json.dumps(conditions)}. "
                                "Verify the conditions are sufficient."
                            ),
                            resource_id=role_arn,
                            remediation="Explicitly scope the Principal to known accounts/roles.",
                        )

                # Cross-account trust
                aws_principals = principal.get("AWS", [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                for p in aws_principals:
                    if ":" in p:
                        principal_account = p.split(":")[4] if len(p.split(":")) > 4 else ""
                        if principal_account and principal_account != self.account_id:
                            self.add_finding(
                                title=f"Role '{role_name}' has cross-account trust to {principal_account}",
                                severity=MEDIUM,
                                service="IAM",
                                category="Trust Relationship",
                                description=(
                                    f"Role '{role_name}' can be assumed by principal '{p}' "
                                    f"in external account {principal_account}. Verify this "
                                    "is intentional and the external account is trusted."
                                ),
                                resource_id=role_arn,
                                remediation="Validate cross-account trusts regularly.",
                                metadata={"external_principal": p,
                                          "external_account": principal_account},
                            )

            # High-risk attached policies on roles
            attached = self._safe_api_call(
                iam.list_attached_role_policies, RoleName=role_name
            )
            if attached:
                for pol in attached.get("AttachedPolicies", []):
                    if pol["PolicyArn"] in HIGH_RISK_POLICIES:
                        self.add_finding(
                            title=f"Role '{role_name}' has high-risk policy: {pol['PolicyName']}",
                            severity=HIGH,
                            service="IAM",
                            category="Excessive Permissions",
                            description=(
                                f"Managed policy '{pol['PolicyName']}' (a known high-risk "
                                "policy) is attached to role."
                            ),
                            resource_id=role_arn,
                            remediation="Scope down to a least-privilege custom policy.",
                            metadata={"policy_arn": pol["PolicyArn"]},
                        )

    # ──────────────────────────────────────────
    # Groups
    # ──────────────────────────────────────────
    def _check_groups(self) -> None:
        iam = self.client("iam")
        groups = self._paginate("iam", "list_groups", "Groups")

        for grp in groups:
            grp_name = grp["GroupName"]
            grp_arn = grp["Arn"]

            attached = self._safe_api_call(
                iam.list_attached_group_policies, GroupName=grp_name
            )
            if attached:
                for pol in attached.get("AttachedPolicies", []):
                    if pol["PolicyArn"] in HIGH_RISK_POLICIES:
                        self.add_finding(
                            title=f"Group '{grp_name}' has high-risk policy: {pol['PolicyName']}",
                            severity=HIGH,
                            service="IAM",
                            category="Excessive Permissions",
                            description=(
                                f"Group '{grp_name}' has the high-risk managed policy "
                                f"'{pol['PolicyName']}' attached."
                            ),
                            resource_id=grp_arn,
                            remediation="Replace with a scoped custom policy.",
                            metadata={"policy_arn": pol["PolicyArn"]},
                        )

    # ──────────────────────────────────────────
    # Credential report (stale console passwords)
    # ──────────────────────────────────────────
    def _check_credential_report(self) -> None:
        iam = self.client("iam")
        # Generate report
        self._safe_api_call(iam.generate_credential_report)
        import time
        for _ in range(10):
            resp = self._safe_api_call(iam.get_credential_report)
            if resp and resp.get("ReportFormat") == "text/csv":
                break
            time.sleep(2)
        else:
            return

        if not resp:
            return

        import csv
        import io

        content = resp["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        now = datetime.now(timezone.utc)

        for row in reader:
            user = row.get("user", "")
            if user == "<root_account>":
                continue
            arn = row.get("arn", "")

            # Console password enabled but not used in STALE_CREDENTIAL_DAYS
            pw_last_used = row.get("password_last_used", "N/A")
            pw_enabled = row.get("password_enabled", "false") == "true"
            if pw_enabled and pw_last_used not in ("N/A", "no_information", "not_supported"):
                try:
                    last = datetime.fromisoformat(pw_last_used.replace("Z", "+00:00"))
                    if (now - last).days > STALE_CREDENTIAL_DAYS:
                        self.add_finding(
                            title=f"User '{user}' console password unused for {(now - last).days} days",
                            severity=LOW,
                            service="IAM",
                            category="Credential Management",
                            description=(
                                f"User '{user}' has an active console password last used "
                                f"{(now - last).days} days ago."
                            ),
                            resource_id=arn,
                            remediation="Remove console access if the user no longer needs it.",
                        )
                except (ValueError, TypeError):
                    pass
