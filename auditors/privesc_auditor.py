"""
IAM Privilege Escalation Detector
==================================
Enumerates all IAM users and roles, resolves their effective permissions,
and checks for known privilege-escalation attack paths.

Based on research from:
  • Rhino Security Labs — "AWS IAM Privilege Escalation — Methods and Mitigations"
  • Bishop Fox — "Breaking AWS IAM"
  • AWS documentation
  • DataDog / Lightspin privesc paths

Attack paths detected:
  1.  Create new policy version (iam:CreatePolicyVersion)
  2.  Set existing policy version as default (iam:SetDefaultPolicyVersion)
  3.  Create access key for another user (iam:CreateAccessKey)
  4.  Create login profile (iam:CreateLoginProfile)
  5.  Update login profile (iam:UpdateLoginProfile)
  6.  Attach user/group/role policy
  7.  Put inline user/group/role policy
  8.  Add user to group
  9.  Update assume-role policy (iam:UpdateAssumeRolePolicy)
  10. PassRole + EC2 RunInstances
  11. PassRole + Lambda CreateFunction + InvokeFunction
  12. PassRole + CloudFormation
  13. PassRole + Glue Dev Endpoint
  14. PassRole + SageMaker
  15. PassRole + DataPipeline
  16. Lambda UpdateFunctionCode
  17. Lambda UpdateFunctionConfiguration (layer injection)
  18. Glue UpdateDevEndpoint
  19. STS AssumeRole to high-priv role
  20. SSM StartSession / SendCommand on EC2 with high-priv role
  21. EC2 Instance Connect
  22. CodeStar CreateProject / AssociateTeamMember
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ..core import BaseAuditor
from ..config import CRITICAL, HIGH, MEDIUM, LOW, PRIVESC_ACTIONS

log = logging.getLogger("aws_audit.privesc")


class PrivilegeEscalationAuditor(BaseAuditor):
    """
    Detects privilege escalation paths in IAM by analysing effective
    permissions of each user and role against known attack techniques.
    """

    @property
    def service_name(self) -> str:
        return "PrivEsc"

    def run(self) -> None:
        log.info("[PrivEsc] Starting privilege-escalation analysis …")
        self._analyse_users()
        self._analyse_roles()
        self._check_dangerous_role_chains()
        log.info("[PrivEsc] Analysis complete — %d findings", len(self.findings))

    # ══════════════════════════════════════════
    # Users
    # ══════════════════════════════════════════
    def _analyse_users(self) -> None:
        iam = self.client("iam")
        users = self._paginate("iam", "list_users", "Users")

        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]
            effective_actions = self._get_user_effective_actions(iam, username)
            self._check_privesc_paths(
                principal_type="user",
                principal_name=username,
                principal_arn=user_arn,
                effective_actions=effective_actions,
            )

    # ══════════════════════════════════════════
    # Roles
    # ══════════════════════════════════════════
    def _analyse_roles(self) -> None:
        iam = self.client("iam")
        roles = self._paginate("iam", "list_roles", "Roles")

        for role in roles:
            role_name = role["RoleName"]
            role_arn = role["Arn"]
            # Skip service-linked & AWS-managed
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            effective_actions = self._get_role_effective_actions(iam, role_name)
            self._check_privesc_paths(
                principal_type="role",
                principal_name=role_name,
                principal_arn=role_arn,
                effective_actions=effective_actions,
            )

    # ══════════════════════════════════════════
    # Dangerous role chains (role A can assume role B which is admin)
    # ══════════════════════════════════════════
    def _check_dangerous_role_chains(self) -> None:
        iam = self.client("iam")
        roles = self._paginate("iam", "list_roles", "Roles")

        # Build a mapping: role_arn → is_admin
        admin_roles: dict[str, str] = {}  # arn → role_name
        role_map: dict[str, dict] = {}    # arn → role dict

        for role in roles:
            role_arn = role["Arn"]
            role_name = role["RoleName"]
            role_map[role_arn] = role
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            effective = self._get_role_effective_actions(iam, role_name)
            if self._is_admin(effective):
                admin_roles[role_arn] = role_name

        # Now check which principals can assume admin roles
        for admin_arn, admin_name in admin_roles.items():
            admin_role = role_map.get(admin_arn, {})
            trust = admin_role.get("AssumeRolePolicyDocument", {})
            if isinstance(trust, str):
                trust = json.loads(trust)

            for stmt in trust.get("Statement", []):
                if stmt.get("Effect") != "Allow":
                    continue
                principals = self._extract_principals(stmt.get("Principal", {}))
                for p in principals:
                    if p == "*":
                        # Already caught by IAM auditor
                        continue
                    # If the trusted principal is a user or a non-admin role, flag
                    if ":user/" in p or (":role/" in p and p not in admin_roles):
                        # Determine the trusted entity name
                        entity_name = p.rsplit("/", 1)[-1] if "/" in p else p
                        self.add_finding(
                            title=f"Privilege escalation chain: '{entity_name}' → admin role '{admin_name}'",
                            severity=HIGH,
                            service="IAM",
                            category="Privilege Escalation",
                            description=(
                                f"Principal '{p}' can assume role '{admin_name}' "
                                f"({admin_arn}) which has administrative permissions. "
                                "This creates a privilege escalation path."
                            ),
                            resource_id=admin_arn,
                            remediation=(
                                "Restrict the trust policy of the admin role or remove "
                                "sts:AssumeRole permissions from the lower-privilege principal."
                            ),
                            metadata={
                                "source_principal": p,
                                "target_admin_role": admin_arn,
                                "attack_path": f"{p} → sts:AssumeRole → {admin_arn}",
                            },
                            references=[
                                "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
                            ],
                        )

    # ══════════════════════════════════════════
    # Core detection logic
    # ══════════════════════════════════════════
    def _check_privesc_paths(
        self,
        principal_type: str,
        principal_name: str,
        principal_arn: str,
        effective_actions: set[str],
    ) -> None:
        """Check a set of effective actions against known privesc techniques."""

        for technique_id, required_actions in PRIVESC_ACTIONS.items():
            if self._has_all_actions(effective_actions, required_actions):
                severity = CRITICAL if self._technique_is_critical(technique_id) else HIGH
                friendly_name = technique_id.replace("_", " ").title()

                self.add_finding(
                    title=f"PrivEsc: {principal_type} '{principal_name}' — {friendly_name}",
                    severity=severity,
                    service="IAM",
                    category="Privilege Escalation",
                    description=(
                        f"The {principal_type} '{principal_name}' has permissions "
                        f"enabling the '{friendly_name}' privilege escalation technique. "
                        f"Required actions: {', '.join(required_actions)}."
                    ),
                    resource_id=principal_arn,
                    remediation=(
                        f"Remove or restrict the following actions for {principal_type} "
                        f"'{principal_name}': {', '.join(required_actions)}. "
                        "Apply least-privilege and use permission boundaries."
                    ),
                    metadata={
                        "technique": technique_id,
                        "required_actions": required_actions,
                        "principal_type": principal_type,
                    },
                    references=[
                        "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
                        "https://bishopfox.com/blog/privilege-escalation-in-aws",
                    ],
                )

    # ══════════════════════════════════════════
    # Action resolution helpers
    # ══════════════════════════════════════════
    def _get_user_effective_actions(self, iam, username: str) -> set[str]:
        """Collect all Allow actions for a user (inline + attached + group)."""
        actions: set[str] = set()

        # User inline policies
        inline_names = self._safe_api_call(iam.list_user_policies, UserName=username)
        if inline_names:
            for pname in inline_names.get("PolicyNames", []):
                resp = self._safe_api_call(
                    iam.get_user_policy, UserName=username, PolicyName=pname
                )
                if resp:
                    actions |= self._extract_actions(resp.get("PolicyDocument", {}))

        # User attached managed policies
        attached = self._safe_api_call(iam.list_attached_user_policies, UserName=username)
        if attached:
            for pol in attached.get("AttachedPolicies", []):
                actions |= self._get_managed_policy_actions(iam, pol["PolicyArn"])

        # Group memberships
        groups = self._safe_api_call(iam.list_groups_for_user, UserName=username)
        if groups:
            for grp in groups.get("Groups", []):
                grp_name = grp["GroupName"]
                # Group inline
                grp_inline = self._safe_api_call(iam.list_group_policies, GroupName=grp_name)
                if grp_inline:
                    for pname in grp_inline.get("PolicyNames", []):
                        resp = self._safe_api_call(
                            iam.get_group_policy, GroupName=grp_name, PolicyName=pname
                        )
                        if resp:
                            actions |= self._extract_actions(resp.get("PolicyDocument", {}))
                # Group attached
                grp_attached = self._safe_api_call(
                    iam.list_attached_group_policies, GroupName=grp_name
                )
                if grp_attached:
                    for pol in grp_attached.get("AttachedPolicies", []):
                        actions |= self._get_managed_policy_actions(iam, pol["PolicyArn"])

        return actions

    def _get_role_effective_actions(self, iam, role_name: str) -> set[str]:
        """Collect all Allow actions for a role (inline + attached)."""
        actions: set[str] = set()

        # Inline
        inline_names = self._safe_api_call(iam.list_role_policies, RoleName=role_name)
        if inline_names:
            for pname in inline_names.get("PolicyNames", []):
                resp = self._safe_api_call(
                    iam.get_role_policy, RoleName=role_name, PolicyName=pname
                )
                if resp:
                    actions |= self._extract_actions(resp.get("PolicyDocument", {}))

        # Attached
        attached = self._safe_api_call(iam.list_attached_role_policies, RoleName=role_name)
        if attached:
            for pol in attached.get("AttachedPolicies", []):
                actions |= self._get_managed_policy_actions(iam, pol["PolicyArn"])

        return actions

    def _get_managed_policy_actions(self, iam, policy_arn: str) -> set[str]:
        """Resolve a managed policy ARN to its set of allowed actions."""
        actions: set[str] = set()
        resp = self._safe_api_call(iam.get_policy, PolicyArn=policy_arn)
        if not resp:
            return actions
        version_id = resp["Policy"].get("DefaultVersionId", "v1")
        ver_resp = self._safe_api_call(
            iam.get_policy_version, PolicyArn=policy_arn, VersionId=version_id
        )
        if ver_resp:
            actions |= self._extract_actions(ver_resp["PolicyVersion"].get("Document", {}))
        return actions

    @staticmethod
    def _extract_actions(document: dict | str) -> set[str]:
        """Extract all Allow actions from a policy document."""
        if isinstance(document, str):
            document = json.loads(document)
        actions: set[str] = set()
        statements = document.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            acts = stmt.get("Action", [])
            if isinstance(acts, str):
                acts = [acts]
            actions.update(acts)
        return actions

    @staticmethod
    def _extract_principals(principal: Any) -> list[str]:
        """Flatten a Principal field to a list of strings."""
        if isinstance(principal, str):
            return [principal]
        if isinstance(principal, dict):
            result = []
            for key, val in principal.items():
                if isinstance(val, str):
                    result.append(val)
                elif isinstance(val, list):
                    result.extend(val)
            return result
        return []

    @staticmethod
    def _has_all_actions(effective: set[str], required: list[str]) -> bool:
        """
        Check whether *effective* covers all *required* actions.
        Handles wildcards like "iam:*" and "*".
        """
        for req in required:
            if req in effective:
                continue
            # Check service wildcard (e.g. "iam:*" covers "iam:CreateUser")
            svc = req.split(":")[0] if ":" in req else ""
            if f"{svc}:*" in effective:
                continue
            # Check full wildcard
            if "*" in effective:
                continue
            return False
        return True

    @staticmethod
    def _is_admin(actions: set[str]) -> bool:
        """Rough check whether a set of actions is effectively admin."""
        if "*" in actions:
            return True
        if "iam:*" in actions:
            return True
        # Count sensitive actions
        admin_like = {"iam:CreatePolicyVersion", "iam:AttachUserPolicy",
                      "iam:AttachRolePolicy", "iam:PutRolePolicy",
                      "iam:PutUserPolicy", "iam:CreateUser", "iam:CreateRole"}
        if len(actions & admin_like) >= 3:
            return True
        return False

    @staticmethod
    def _technique_is_critical(technique_id: str) -> bool:
        """Some techniques are direct admin, others are stepping stones."""
        critical_techniques = {
            "iam_create_policy_version",
            "iam_set_default_policy_version",
            "iam_attach_user_policy",
            "iam_attach_role_policy",
            "iam_put_user_policy",
            "iam_put_role_policy",
            "iam_pass_role_lambda",
            "iam_pass_role_ec2",
            "iam_pass_role_cloudformation",
        }
        return technique_id in critical_techniques
