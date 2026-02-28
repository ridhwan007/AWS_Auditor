"""
RDS Security Auditor
====================
Checks:
  • Public accessibility
  • Encryption at rest
  • Auto minor version upgrade
  • Multi-AZ deployment
  • Backup retention
  • Deletion protection
  • Storage encryption
  • IAM authentication
  • Public snapshots
  • Logging / audit logs enabled
  • Default master username
"""

from __future__ import annotations

import logging

from ..core import BaseAuditor
from ..config import CRITICAL, HIGH, MEDIUM, LOW, INFO

log = logging.getLogger("aws_audit.rds")


class RDSAuditor(BaseAuditor):

    @property
    def service_name(self) -> str:
        return "RDS"

    def run(self) -> None:
        log.info("[RDS] Starting audit …")
        for region in self.regions:
            log.info("[RDS] Scanning region %s", region)
            self._check_instances(region)
            self._check_snapshots(region)
            self._check_clusters(region)
        log.info("[RDS] Audit complete — %d findings", len(self.findings))

    # ──────────────────────────────────────────
    # DB Instances
    # ──────────────────────────────────────────
    def _check_instances(self, region: str) -> None:
        instances = self._paginate(
            "rds", "describe_db_instances", "DBInstances", region=region,
        )
        for db in instances:
            db_id = db["DBInstanceIdentifier"]
            arn = db.get("DBInstanceArn", f"arn:aws:rds:{region}:{self.account_id}:db:{db_id}")

            # Public access
            if db.get("PubliclyAccessible", False):
                self.add_finding(
                    title=f"RDS instance '{db_id}' is publicly accessible",
                    severity=CRITICAL,
                    service="RDS",
                    category="Network Security",
                    region=region,
                    description=(
                        f"RDS instance {db_id} has PubliclyAccessible=true. "
                        "Combined with a permissive security group, the database "
                        "may be reachable from the internet."
                    ),
                    resource_id=arn,
                    remediation="Set PubliclyAccessible=false and use private subnets + VPN/peering.",
                )

            # Encryption at rest
            if not db.get("StorageEncrypted", False):
                self.add_finding(
                    title=f"RDS instance '{db_id}' is not encrypted at rest",
                    severity=HIGH,
                    service="RDS",
                    category="Encryption",
                    region=region,
                    description=f"RDS instance {db_id} storage is unencrypted.",
                    resource_id=arn,
                    remediation="Enable encryption (requires creating an encrypted snapshot and restoring).",
                    compliance=["CIS 2.3.1"],
                )

            # Auto minor version upgrade
            if not db.get("AutoMinorVersionUpgrade", False):
                self.add_finding(
                    title=f"RDS instance '{db_id}' auto minor version upgrade disabled",
                    severity=LOW,
                    service="RDS",
                    category="Patching",
                    region=region,
                    description="Auto minor version upgrade is disabled — security patches may be missed.",
                    resource_id=arn,
                    remediation="Enable AutoMinorVersionUpgrade.",
                )

            # Multi-AZ
            if not db.get("MultiAZ", False):
                self.add_finding(
                    title=f"RDS instance '{db_id}' is not Multi-AZ",
                    severity=LOW,
                    service="RDS",
                    category="Availability",
                    region=region,
                    description="Instance is in a single AZ — no automatic failover.",
                    resource_id=arn,
                    remediation="Enable Multi-AZ for production databases.",
                )

            # Backup retention
            retention = db.get("BackupRetentionPeriod", 0)
            if retention < 7:
                self.add_finding(
                    title=f"RDS instance '{db_id}' backup retention is only {retention} days",
                    severity=MEDIUM,
                    service="RDS",
                    category="Data Protection",
                    region=region,
                    description=f"Backup retention is {retention} days. Recommended ≥7.",
                    resource_id=arn,
                    remediation="Increase BackupRetentionPeriod to at least 7 days.",
                )

            # Deletion protection
            if not db.get("DeletionProtection", False):
                self.add_finding(
                    title=f"RDS instance '{db_id}' deletion protection disabled",
                    severity=MEDIUM,
                    service="RDS",
                    category="Data Protection",
                    region=region,
                    description="Deletion protection is off — the instance can be deleted accidentally.",
                    resource_id=arn,
                    remediation="Enable DeletionProtection for production databases.",
                )

            # IAM DB authentication
            if not db.get("IAMDatabaseAuthenticationEnabled", False):
                self.add_finding(
                    title=f"RDS instance '{db_id}' IAM DB authentication disabled",
                    severity=LOW,
                    service="RDS",
                    category="Authentication",
                    region=region,
                    description="IAM database authentication is not enabled.",
                    resource_id=arn,
                    remediation="Enable IAM authentication for credential-less access.",
                )

            # Default master username
            master_user = db.get("MasterUsername", "")
            if master_user in ("admin", "root", "postgres", "master", "sa"):
                self.add_finding(
                    title=f"RDS instance '{db_id}' uses default master username '{master_user}'",
                    severity=LOW,
                    service="RDS",
                    category="Best Practice",
                    region=region,
                    description=f"Master username is '{master_user}' — a commonly guessed default.",
                    resource_id=arn,
                    remediation="Use a non-default master username.",
                )

            # Logging
            engine = db.get("Engine", "")
            enabled_logs = db.get("EnabledCloudwatchLogsExports", [])
            expected_logs = {
                "mysql": ["audit", "error", "general", "slowquery"],
                "mariadb": ["audit", "error", "general", "slowquery"],
                "postgres": ["postgresql", "upgrade"],
                "oracle": ["audit", "alert", "listener", "trace"],
                "sqlserver": ["agent", "error"],
            }
            for eng_prefix, logs in expected_logs.items():
                if engine.startswith(eng_prefix):
                    missing = [l for l in logs if l not in enabled_logs]
                    if missing:
                        self.add_finding(
                            title=f"RDS '{db_id}' missing CloudWatch log exports: {', '.join(missing)}",
                            severity=MEDIUM if "audit" in missing else LOW,
                            service="RDS",
                            category="Logging & Monitoring",
                            region=region,
                            description=f"CloudWatch log exports not enabled for: {', '.join(missing)}.",
                            resource_id=arn,
                            remediation="Enable the missing log exports in ModifyDBInstance.",
                            metadata={"missing_logs": missing},
                        )
                    break

    # ──────────────────────────────────────────
    # DB Snapshots
    # ──────────────────────────────────────────
    def _check_snapshots(self, region: str) -> None:
        snapshots = self._paginate(
            "rds", "describe_db_snapshots", "DBSnapshots",
            region=region, SnapshotType="manual",
        )
        rds = self.client("rds", region)
        for snap in snapshots:
            snap_id = snap["DBSnapshotIdentifier"]
            arn = snap.get("DBSnapshotArn", "")

            attrs = self._safe_api_call(
                rds.describe_db_snapshot_attributes, DBSnapshotIdentifier=snap_id,
            )
            if attrs:
                result = attrs.get("DBSnapshotAttributesResult", {})
                for attr in result.get("DBSnapshotAttributes", []):
                    if attr.get("AttributeName") == "restore" and "all" in attr.get("AttributeValues", []):
                        self.add_finding(
                            title=f"RDS snapshot '{snap_id}' is publicly shared",
                            severity=CRITICAL,
                            service="RDS",
                            category="Data Exposure",
                            region=region,
                            description=(
                                f"RDS snapshot {snap_id} is shared with all AWS accounts. "
                                "Anyone can restore it and access the data."
                            ),
                            resource_id=arn,
                            remediation="Remove the 'all' value from the 'restore' attribute.",
                        )

            # Unencrypted snapshot
            if not snap.get("Encrypted", False):
                self.add_finding(
                    title=f"RDS snapshot '{snap_id}' is not encrypted",
                    severity=MEDIUM,
                    service="RDS",
                    category="Encryption",
                    region=region,
                    description=f"Snapshot {snap_id} is unencrypted.",
                    resource_id=arn,
                    remediation="Copy the snapshot with encryption enabled.",
                )

    # ──────────────────────────────────────────
    # Aurora Clusters
    # ──────────────────────────────────────────
    def _check_clusters(self, region: str) -> None:
        clusters = self._paginate(
            "rds", "describe_db_clusters", "DBClusters", region=region,
        )
        for cluster in clusters:
            cluster_id = cluster["DBClusterIdentifier"]
            arn = cluster.get("DBClusterArn", "")

            if not cluster.get("StorageEncrypted", False):
                self.add_finding(
                    title=f"Aurora cluster '{cluster_id}' is not encrypted",
                    severity=HIGH,
                    service="RDS",
                    category="Encryption",
                    region=region,
                    description=f"Aurora cluster {cluster_id} storage is unencrypted.",
                    resource_id=arn,
                    remediation="Recreate the cluster with encryption enabled.",
                )

            if not cluster.get("DeletionProtection", False):
                self.add_finding(
                    title=f"Aurora cluster '{cluster_id}' deletion protection disabled",
                    severity=MEDIUM,
                    service="RDS",
                    category="Data Protection",
                    region=region,
                    description="Cluster can be deleted without deletion protection.",
                    resource_id=arn,
                    remediation="Enable DeletionProtection.",
                )

            retention = cluster.get("BackupRetentionPeriod", 1)
            if retention < 7:
                self.add_finding(
                    title=f"Aurora cluster '{cluster_id}' backup retention is {retention} days",
                    severity=MEDIUM,
                    service="RDS",
                    category="Data Protection",
                    region=region,
                    description=f"Backup retention is {retention} days (recommend ≥7).",
                    resource_id=arn,
                    remediation="Increase BackupRetentionPeriod.",
                )
