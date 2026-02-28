"""
ECS & ECR Security Auditor
============================
Checks:
  • Task definitions with privileged containers
  • Containers running as root (user = root / 0)
  • Host network mode (container escape risk)
  • Host PID / IPC mode (namespace breakout)
  • Host path volume mounts (filesystem escape)
  • Missing logging configuration (awslogs driver)
  • Read-only root filesystem not enabled
  • Task execution / task role overly permissive
  • Secrets passed via environment variables (not Secrets Manager)
  • ECS clusters without Container Insights
  • Public-facing ECS services (public IP assignment)
  • Services with no circuit-breaker / min healthy percent 0
  • Fargate platform version not latest
  • ECR repositories without image scanning
  • ECR repositories without lifecycle policies
  • ECR repositories allowing public access
  • Container images with critical/high scan findings
"""

from __future__ import annotations

import json
import logging

from ..core import BaseAuditor
from ..config import CRITICAL, HIGH, MEDIUM, LOW, INFO

log = logging.getLogger("aws_audit.ecs")

SECRET_KEYWORDS = {
    "password", "secret", "api_key", "apikey", "token", "private_key",
    "access_key", "db_pass", "database_password", "auth", "credential",
    "aws_secret", "aws_access", "connection_string", "passwd",
}


class ECSAuditor(BaseAuditor):
    """Audit ECS clusters, services, task definitions, and ECR repositories."""

    @property
    def service_name(self) -> str:
        return "ECS"

    def run(self) -> None:
        log.info("[ECS] Starting audit …")
        for region in self.regions:
            log.info("[ECS] Scanning region %s", region)
            self._check_clusters(region)
            self._check_task_definitions(region)
            self._check_ecr_repositories(region)
        log.info("[ECS] Audit complete — %d findings", len(self.findings))

    # ══════════════════════════════════════════
    # ECS Clusters
    # ══════════════════════════════════════════
    def _check_clusters(self, region: str) -> None:
        ecs = self.client("ecs", region)

        # List clusters
        cluster_arns: list[str] = []
        resp = self._safe_api_call(ecs.list_clusters)
        if resp:
            cluster_arns = resp.get("clusterArns", [])

        if not cluster_arns:
            return

        # Describe clusters (batches of 100)
        for i in range(0, len(cluster_arns), 100):
            batch = cluster_arns[i : i + 100]
            desc = self._safe_api_call(
                ecs.describe_clusters,
                clusters=batch,
                include=["SETTINGS", "CONFIGURATIONS"],
            )
            if not desc:
                continue

            for cluster in desc.get("clusters", []):
                cluster_name = cluster.get("clusterName", "")
                cluster_arn = cluster.get("clusterArn", "")

                # Container Insights
                insights_enabled = False
                for setting in cluster.get("settings", []):
                    if setting.get("name") == "containerInsights" and setting.get("value") == "enabled":
                        insights_enabled = True
                if not insights_enabled:
                    self.add_finding(
                        title=f"ECS cluster '{cluster_name}' has Container Insights disabled",
                        severity=MEDIUM,
                        service="ECS",
                        category="Logging & Monitoring",
                        region=region,
                        description=(
                            f"Cluster '{cluster_name}' does not have Container Insights enabled. "
                            "Container-level metrics and logs are not being collected."
                        ),
                        resource_id=cluster_arn,
                        remediation="Enable Container Insights in the cluster settings for container-level monitoring.",
                    )

                # Check services in this cluster
                self._check_services(ecs, cluster_arn, cluster_name, region)

    # ══════════════════════════════════════════
    # ECS Services
    # ══════════════════════════════════════════
    def _check_services(self, ecs, cluster_arn: str, cluster_name: str, region: str) -> None:
        service_arns: list[str] = []
        paginator = ecs.get_paginator("list_services")
        try:
            for page in paginator.paginate(cluster=cluster_arn):
                service_arns.extend(page.get("serviceArns", []))
        except Exception as exc:
            log.warning("[ECS] Error listing services for %s: %s", cluster_name, exc)
            return

        if not service_arns:
            return

        # Describe services (batches of 10)
        for i in range(0, len(service_arns), 10):
            batch = service_arns[i : i + 10]
            desc = self._safe_api_call(
                ecs.describe_services, cluster=cluster_arn, services=batch,
            )
            if not desc:
                continue

            for svc in desc.get("services", []):
                svc_name = svc.get("serviceName", "")
                svc_arn = svc.get("serviceArn", "")

                # Public IP assignment (Fargate awsvpcConfiguration)
                net_config = svc.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
                if net_config.get("assignPublicIp") == "ENABLED":
                    self.add_finding(
                        title=f"ECS service '{svc_name}' assigns public IPs to tasks",
                        severity=HIGH,
                        service="ECS",
                        category="Network Security",
                        region=region,
                        description=(
                            f"Service '{svc_name}' in cluster '{cluster_name}' assigns public "
                            "IPs to tasks. Containers are directly reachable from the internet."
                        ),
                        resource_id=svc_arn,
                        remediation=(
                            "Set assignPublicIp=DISABLED and use a load balancer / NAT gateway "
                            "for internet access."
                        ),
                    )

                # Deployment: no circuit breaker
                deploy_config = svc.get("deploymentConfiguration", {})
                circuit = deploy_config.get("deploymentCircuitBreaker", {})
                if not circuit.get("enable", False):
                    self.add_finding(
                        title=f"ECS service '{svc_name}' has no deployment circuit breaker",
                        severity=LOW,
                        service="ECS",
                        category="Reliability",
                        region=region,
                        description="No circuit breaker — a bad deployment can loop indefinitely.",
                        resource_id=svc_arn,
                        remediation="Enable the deployment circuit breaker with rollback.",
                    )

                # Min healthy percent = 0 (full outage during deploy)
                min_healthy = deploy_config.get("minimumHealthyPercent", 100)
                if min_healthy == 0:
                    self.add_finding(
                        title=f"ECS service '{svc_name}' minimumHealthyPercent is 0",
                        severity=MEDIUM,
                        service="ECS",
                        category="Availability",
                        region=region,
                        description="All tasks can be drained simultaneously during deployment — potential full outage.",
                        resource_id=svc_arn,
                        remediation="Set minimumHealthyPercent to at least 50.",
                    )

                # Fargate platform version
                launch_type = svc.get("launchType", "")
                platform_ver = svc.get("platformVersion", "")
                if launch_type == "FARGATE" and platform_ver not in ("LATEST", "1.4.0", ""):
                    self.add_finding(
                        title=f"ECS Fargate service '{svc_name}' using old platform version '{platform_ver}'",
                        severity=MEDIUM,
                        service="ECS",
                        category="Patching",
                        region=region,
                        description=f"Platform version '{platform_ver}' may be missing security patches.",
                        resource_id=svc_arn,
                        remediation="Update to LATEST platform version.",
                    )

    # ══════════════════════════════════════════
    # ECS Task Definitions
    # ══════════════════════════════════════════
    def _check_task_definitions(self, region: str) -> None:
        ecs = self.client("ecs", region)

        # List task definition families and get latest revision of each
        families: list[str] = []
        paginator = ecs.get_paginator("list_task_definition_families")
        try:
            for page in paginator.paginate(status="ACTIVE"):
                families.extend(page.get("families", []))
        except Exception as exc:
            log.warning("[ECS] Error listing task families in %s: %s", region, exc)
            return

        for family in families:
            resp = self._safe_api_call(ecs.describe_task_definition, taskDefinition=family)
            if not resp:
                continue
            td = resp.get("taskDefinition", {})
            td_arn = td.get("taskDefinitionArn", "")
            td_family = td.get("family", family)
            revision = td.get("revision", "?")
            td_label = f"{td_family}:{revision}"

            # Network mode
            network_mode = td.get("networkMode", "")
            if network_mode == "host":
                self.add_finding(
                    title=f"Task def '{td_label}' uses host network mode",
                    severity=HIGH,
                    service="ECS",
                    category="Container Escape",
                    region=region,
                    description=(
                        f"Task definition '{td_label}' uses networkMode=host. "
                        "Containers share the host's network namespace, enabling "
                        "network-level breakout and access to host services."
                    ),
                    resource_id=td_arn,
                    remediation="Use awsvpc or bridge network mode instead of host.",
                )

            # PID mode
            if td.get("pidMode") == "host":
                self.add_finding(
                    title=f"Task def '{td_label}' uses host PID namespace",
                    severity=HIGH,
                    service="ECS",
                    category="Container Escape",
                    region=region,
                    description="Containers can see and signal host processes — namespace breakout risk.",
                    resource_id=td_arn,
                    remediation="Remove pidMode=host unless absolutely required.",
                )

            # IPC mode
            if td.get("ipcMode") == "host":
                self.add_finding(
                    title=f"Task def '{td_label}' uses host IPC namespace",
                    severity=HIGH,
                    service="ECS",
                    category="Container Escape",
                    region=region,
                    description="Containers share host IPC namespace — can access shared memory of host processes.",
                    resource_id=td_arn,
                    remediation="Remove ipcMode=host.",
                )

            # Host path volumes
            for vol in td.get("volumes", []):
                host = vol.get("host", {})
                if host.get("sourcePath"):
                    severity = CRITICAL if host["sourcePath"] in ("/", "/etc", "/var/run/docker.sock") else HIGH
                    self.add_finding(
                        title=f"Task def '{td_label}' mounts host path '{host['sourcePath']}'",
                        severity=severity,
                        service="ECS",
                        category="Container Escape",
                        region=region,
                        description=(
                            f"Volume '{vol.get('name', '?')}' mounts host path "
                            f"'{host['sourcePath']}'. This allows container filesystem escape."
                        ),
                        resource_id=td_arn,
                        remediation="Use EFS or EBS volumes instead of host bind mounts.",
                        metadata={"host_path": host["sourcePath"], "volume_name": vol.get("name")},
                    )

            # Task execution role / task role
            task_role = td.get("taskRoleArn", "")
            exec_role = td.get("executionRoleArn", "")
            if task_role:
                self._check_task_role(task_role, td_label, td_arn, region)

            # Container definitions
            for container in td.get("containerDefinitions", []):
                self._check_container_def(container, td_label, td_arn, region)

    def _check_container_def(self, container: dict, td_label: str, td_arn: str, region: str) -> None:
        c_name = container.get("name", "unknown")
        label = f"{td_label}/{c_name}"

        # Privileged mode
        if container.get("privileged", False):
            self.add_finding(
                title=f"Container '{label}' runs in privileged mode",
                severity=CRITICAL,
                service="ECS",
                category="Container Escape",
                region=region,
                description=(
                    f"Container '{c_name}' in task def '{td_label}' has privileged=true. "
                    "The container has full access to the host — trivial breakout. "
                    "This is the primary vector for ECS container escape."
                ),
                resource_id=td_arn,
                remediation="Remove privileged=true. Use specific Linux capabilities if needed.",
                references=[
                    "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
                ],
            )

        # Running as root
        user = container.get("user", "")
        if not user or user == "root" or user == "0":
            self.add_finding(
                title=f"Container '{label}' runs as root",
                severity=MEDIUM,
                service="ECS",
                category="Container Security",
                region=region,
                description=(
                    f"Container '{c_name}' runs as root (user={user or 'not set'}). "
                    "Combined with other misconfigs, this eases privilege escalation."
                ),
                resource_id=td_arn,
                remediation="Set a non-root user in the container definition or Dockerfile.",
            )

        # Read-only root filesystem
        if not container.get("readonlyRootFilesystem", False):
            self.add_finding(
                title=f"Container '{label}' does not use read-only root filesystem",
                severity=LOW,
                service="ECS",
                category="Container Hardening",
                region=region,
                description="Writable root filesystem allows an attacker to modify binaries or drop tools.",
                resource_id=td_arn,
                remediation="Set readonlyRootFilesystem=true, use tmpfs mounts for writable directories.",
            )

        # Logging
        log_config = container.get("logConfiguration", {})
        if not log_config or not log_config.get("logDriver"):
            self.add_finding(
                title=f"Container '{label}' has no logging configured",
                severity=HIGH,
                service="ECS",
                category="Logging & Monitoring",
                region=region,
                description="No log driver configured — container stdout/stderr is lost. Forensics will be impossible.",
                resource_id=td_arn,
                remediation="Configure a log driver (e.g. awslogs, splunk, fluentd).",
            )

        # Secrets in environment variables
        for env in container.get("environment", []):
            env_name = env.get("name", "")
            if any(kw in env_name.lower() for kw in SECRET_KEYWORDS):
                self.add_finding(
                    title=f"Container '{label}' has potential secret in env var '{env_name}'",
                    severity=HIGH,
                    service="ECS",
                    category="Secret Exposure",
                    region=region,
                    description=(
                        f"Environment variable '{env_name}' appears to contain a secret "
                        "passed as plain text. Visible in task definition metadata and "
                        "container inspect output."
                    ),
                    resource_id=td_arn,
                    remediation=(
                        "Use the 'secrets' property with Secrets Manager or SSM Parameter "
                        "Store instead of 'environment'."
                    ),
                    metadata={"env_var_name": env_name},
                )

        # Linux capabilities — added dangerous caps
        linux_params = container.get("linuxParameters", {})
        cap_add = linux_params.get("capabilities", {}).get("add", [])
        dangerous_caps = {"SYS_ADMIN", "SYS_PTRACE", "SYS_RAWIO", "NET_ADMIN",
                          "DAC_OVERRIDE", "ALL", "NET_RAW", "SYS_MODULE"}
        added_dangerous = [c for c in cap_add if c in dangerous_caps]
        if added_dangerous:
            self.add_finding(
                title=f"Container '{label}' adds dangerous Linux capabilities: {', '.join(added_dangerous)}",
                severity=HIGH if "SYS_ADMIN" in added_dangerous or "ALL" in added_dangerous else MEDIUM,
                service="ECS",
                category="Container Escape",
                region=region,
                description=(
                    f"Container adds capabilities [{', '.join(added_dangerous)}]. "
                    "SYS_ADMIN, SYS_PTRACE, and ALL can enable container breakout."
                ),
                resource_id=td_arn,
                remediation="Remove dangerous capabilities. Drop ALL and add only what's needed.",
                metadata={"capabilities_added": added_dangerous},
            )

        # Resource limits — no memory limit
        if not container.get("memory") and not container.get("memoryReservation"):
            self.add_finding(
                title=f"Container '{label}' has no memory limit",
                severity=LOW,
                service="ECS",
                category="Resource Management",
                region=region,
                description="No memory limit — a runaway container can consume all host memory.",
                resource_id=td_arn,
                remediation="Set memory or memoryReservation to prevent resource exhaustion.",
            )

    def _check_task_role(self, role_arn: str, td_label: str, td_arn: str, region: str) -> None:
        """Check if the task IAM role has dangerously broad permissions."""
        iam = self.client("iam")
        # Extract role name from ARN
        role_name = role_arn.rsplit("/", 1)[-1] if "/" in role_arn else role_arn

        # Check attached policies
        attached = self._safe_api_call(iam.list_attached_role_policies, RoleName=role_name)
        if attached:
            for pol in attached.get("AttachedPolicies", []):
                policy_name = pol.get("PolicyName", "")
                policy_arn = pol.get("PolicyArn", "")
                # Admin or full-access policies on a task role
                if any(x in policy_name for x in ("AdministratorAccess", "FullAccess", "PowerUser")):
                    self.add_finding(
                        title=f"Task def '{td_label}' role has high-risk policy: {policy_name}",
                        severity=CRITICAL,
                        service="ECS",
                        category="Excessive Permissions",
                        region=region,
                        description=(
                            f"Task role '{role_name}' for task def '{td_label}' has "
                            f"'{policy_name}' attached. A compromised container inherits "
                            "these broad permissions."
                        ),
                        resource_id=td_arn,
                        remediation="Replace with a least-privilege policy scoped to the task's needs.",
                        metadata={"role_arn": role_arn, "policy_arn": policy_arn},
                    )

        # Check inline policies for wildcards
        inline_resp = self._safe_api_call(iam.list_role_policies, RoleName=role_name)
        if inline_resp:
            for pname in inline_resp.get("PolicyNames", []):
                pol_resp = self._safe_api_call(
                    iam.get_role_policy, RoleName=role_name, PolicyName=pname,
                )
                if not pol_resp:
                    continue
                doc = pol_resp.get("PolicyDocument", {})
                if isinstance(doc, str):
                    doc = json.loads(doc)
                for stmt in doc.get("Statement", []):
                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]
                    if stmt.get("Effect") == "Allow" and "*" in actions and "*" in resources:
                        self.add_finding(
                            title=f"Task def '{td_label}' role inline policy '{pname}' grants *:*",
                            severity=CRITICAL,
                            service="ECS",
                            category="Excessive Permissions",
                            region=region,
                            description=(
                                f"Inline policy '{pname}' on task role '{role_name}' "
                                "allows all actions on all resources — full admin from any container."
                            ),
                            resource_id=td_arn,
                            remediation="Scope down the inline policy to least-privilege.",
                            metadata={"role_arn": role_arn, "policy_name": pname},
                        )

    # ══════════════════════════════════════════
    # ECR Repositories
    # ══════════════════════════════════════════
    def _check_ecr_repositories(self, region: str) -> None:
        ecr = self.client("ecr", region)

        repos: list[dict] = []
        paginator = ecr.get_paginator("describe_repositories")
        try:
            for page in paginator.paginate():
                repos.extend(page.get("repositories", []))
        except Exception as exc:
            log.warning("[ECS] Error listing ECR repos in %s: %s", region, exc)
            return

        for repo in repos:
            repo_name = repo.get("repositoryName", "")
            repo_arn = repo.get("repositoryArn", "")
            repo_uri = repo.get("repositoryUri", "")

            # Image scanning
            scan_config = repo.get("imageScanningConfiguration", {})
            if not scan_config.get("scanOnPush", False):
                self.add_finding(
                    title=f"ECR repo '{repo_name}' does not scan images on push",
                    severity=MEDIUM,
                    service="ECR",
                    category="Vulnerability Management",
                    region=region,
                    description="Images pushed to this repo are not automatically scanned for CVEs.",
                    resource_id=repo_arn,
                    remediation="Enable imageScanningConfiguration.scanOnPush=true.",
                )

            # Image tag mutability
            if repo.get("imageTagMutability") == "MUTABLE":
                self.add_finding(
                    title=f"ECR repo '{repo_name}' has mutable image tags",
                    severity=MEDIUM,
                    service="ECR",
                    category="Supply Chain",
                    region=region,
                    description=(
                        "Image tags are mutable — a 'latest' or versioned tag can be "
                        "overwritten with a different (potentially malicious) image."
                    ),
                    resource_id=repo_arn,
                    remediation="Set imageTagMutability=IMMUTABLE to prevent tag overwriting.",
                )

            # Lifecycle policy
            lifecycle = self._safe_api_call(ecr.get_lifecycle_policy, repositoryName=repo_name)
            if lifecycle is None:
                self.add_finding(
                    title=f"ECR repo '{repo_name}' has no lifecycle policy",
                    severity=LOW,
                    service="ECR",
                    category="Cost & Hygiene",
                    region=region,
                    description="No lifecycle policy — old/vulnerable images accumulate.",
                    resource_id=repo_arn,
                    remediation="Configure a lifecycle policy to expire untagged and old images.",
                )

            # Repository policy — public access
            policy_resp = self._safe_api_call(ecr.get_repository_policy, repositoryName=repo_name)
            if policy_resp:
                try:
                    policy = json.loads(policy_resp.get("policyText", "{}"))
                    for stmt in policy.get("Statement", []):
                        principal = stmt.get("Principal", "")
                        condition = stmt.get("Condition", {})
                        if stmt.get("Effect") == "Allow" and (
                            principal == "*" or principal == {"AWS": "*"}
                        ) and not condition:
                            self.add_finding(
                                title=f"ECR repo '{repo_name}' policy allows public access",
                                severity=CRITICAL,
                                service="ECR",
                                category="Public Access",
                                region=region,
                                description=(
                                    f"Repository policy allows Principal '*' without conditions. "
                                    "Anyone can pull images, potentially exposing proprietary code and secrets."
                                ),
                                resource_id=repo_arn,
                                remediation="Restrict the repository policy to specific AWS accounts.",
                            )
                except (json.JSONDecodeError, TypeError):
                    pass

            # Check latest image scan findings
            self._check_image_scan_findings(ecr, repo_name, repo_arn, region)

    def _check_image_scan_findings(self, ecr, repo_name: str, repo_arn: str, region: str) -> None:
        """Check the most recent image for scan findings."""
        # Get the latest image
        images_resp = self._safe_api_call(
            ecr.describe_images,
            repositoryName=repo_name,
            filter={"tagStatus": "TAGGED"},
            maxResults=5,
        )
        if not images_resp:
            return

        for image in images_resp.get("imageDetails", [])[:3]:  # Check last 3 tagged images
            image_digest = image.get("imageDigest", "")
            tags = image.get("imageTags", [])
            tag_str = ", ".join(tags[:3]) if tags else image_digest[:16]

            scan = image.get("imageScanStatus", {})
            if scan.get("status") != "COMPLETE":
                continue

            findings_summary = image.get("imageScanFindingsSummary", {})
            vuln_counts = findings_summary.get("findingSeverityCounts", {})

            critical_count = vuln_counts.get("CRITICAL", 0)
            high_count = vuln_counts.get("HIGH", 0)

            if critical_count > 0:
                self.add_finding(
                    title=f"ECR image '{repo_name}:{tag_str}' has {critical_count} CRITICAL vulnerabilities",
                    severity=CRITICAL,
                    service="ECR",
                    category="Vulnerability Management",
                    region=region,
                    description=(
                        f"Image scan found {critical_count} CRITICAL and {high_count} HIGH "
                        f"vulnerabilities in {repo_name}:{tag_str}."
                    ),
                    resource_id=repo_arn,
                    remediation="Update base image and dependencies, rebuild and rescan.",
                    metadata={"image_tags": tags, "digest": image_digest,
                              "critical": critical_count, "high": high_count},
                )
            elif high_count > 0:
                self.add_finding(
                    title=f"ECR image '{repo_name}:{tag_str}' has {high_count} HIGH vulnerabilities",
                    severity=HIGH,
                    service="ECR",
                    category="Vulnerability Management",
                    region=region,
                    description=f"Image scan found {high_count} HIGH vulnerabilities.",
                    resource_id=repo_arn,
                    remediation="Update dependencies and rebuild the image.",
                    metadata={"image_tags": tags, "digest": image_digest, "high": high_count},
                )
