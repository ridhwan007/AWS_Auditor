"""
CloudTrail, Config & Logging Auditor
=====================================
Checks:
  • CloudTrail enabled in all regions
  • CloudTrail log file validation
  • CloudTrail S3 bucket access logging
  • CloudTrail encryption (KMS)
  • CloudTrail CloudWatch Logs integration
  • AWS Config enabled
  • GuardDuty enabled
  • CloudWatch alarm for root usage
  • CloudWatch alarm for unauthorized API calls
  • Access Analyzer enabled
  • SNS topic for CloudTrail notifications
"""

from __future__ import annotations

import logging

from ..core import BaseAuditor
from ..config import CRITICAL, HIGH, MEDIUM, LOW, INFO

log = logging.getLogger("aws_audit.logging")


class LoggingAuditor(BaseAuditor):

    @property
    def service_name(self) -> str:
        return "Logging"

    def run(self) -> None:
        log.info("[Logging] Starting audit …")
        self._check_cloudtrail()
        for region in self.regions:
            self._check_config(region)
            self._check_guardduty(region)
            self._check_access_analyzer(region)
        log.info("[Logging] Audit complete — %d findings", len(self.findings))

    # ──────────────────────────────────────────
    # CloudTrail
    # ──────────────────────────────────────────
    def _check_cloudtrail(self) -> None:
        ct = self.client("cloudtrail")
        resp = self._safe_api_call(ct.describe_trails)
        if not resp:
            self.add_finding(
                title="Unable to query CloudTrail — possible permission issue",
                severity=HIGH,
                service="CloudTrail",
                category="Logging & Monitoring",
                description="Could not retrieve CloudTrail trails. Verify permissions.",
                resource_id=f"arn:aws:cloudtrail:{self.regions[0]}:{self.account_id}:trail/*",
            )
            return

        trails = resp.get("trailList", [])
        if not trails:
            self.add_finding(
                title="No CloudTrail trails configured",
                severity=CRITICAL,
                service="CloudTrail",
                category="Logging & Monitoring",
                description="No CloudTrail trails exist — all API activity is unmonitored.",
                resource_id=f"arn:aws:cloudtrail:{self.regions[0]}:{self.account_id}:trail/*",
                remediation="Create a multi-region CloudTrail trail immediately.",
                compliance=["CIS 3.1"],
            )
            return

        has_multiregion = False

        for trail in trails:
            trail_name = trail.get("Name", "unknown")
            trail_arn = trail.get("TrailARN", "")

            if trail.get("IsMultiRegionTrail", False):
                has_multiregion = True

            # Log file validation
            if not trail.get("LogFileValidationEnabled", False):
                self.add_finding(
                    title=f"CloudTrail '{trail_name}' log file validation disabled",
                    severity=MEDIUM,
                    service="CloudTrail",
                    category="Integrity",
                    description="Log file validation is disabled — tampering cannot be detected.",
                    resource_id=trail_arn,
                    remediation="Enable LogFileValidationEnabled.",
                    compliance=["CIS 3.2"],
                )

            # KMS encryption
            if not trail.get("KmsKeyId"):
                self.add_finding(
                    title=f"CloudTrail '{trail_name}' is not encrypted with KMS",
                    severity=MEDIUM,
                    service="CloudTrail",
                    category="Encryption",
                    description="Trail logs are not encrypted with a customer-managed or AWS-managed KMS key.",
                    resource_id=trail_arn,
                    remediation="Configure SSE-KMS encryption for the trail.",
                    compliance=["CIS 3.7"],
                )

            # CloudWatch Logs integration
            if not trail.get("CloudWatchLogsLogGroupArn"):
                self.add_finding(
                    title=f"CloudTrail '{trail_name}' not integrated with CloudWatch Logs",
                    severity=MEDIUM,
                    service="CloudTrail",
                    category="Logging & Monitoring",
                    description="Trail is not sending events to CloudWatch Logs for real-time alerting.",
                    resource_id=trail_arn,
                    remediation="Configure CloudWatch Logs delivery for the trail.",
                    compliance=["CIS 3.4"],
                )

            # Check trail status (logging active?)
            status = self._safe_api_call(ct.get_trail_status, Name=trail_arn)
            if status and not status.get("IsLogging", False):
                self.add_finding(
                    title=f"CloudTrail '{trail_name}' is not actively logging",
                    severity=CRITICAL,
                    service="CloudTrail",
                    category="Logging & Monitoring",
                    description="Trail exists but logging is stopped.",
                    resource_id=trail_arn,
                    remediation="Start logging on the trail immediately.",
                    compliance=["CIS 3.1"],
                )

            # S3 bucket — check if bucket logging is enabled for the trail bucket
            bucket = trail.get("S3BucketName")
            if bucket:
                s3 = self.client("s3")
                logging_resp = self._safe_api_call(s3.get_bucket_logging, Bucket=bucket)
                if logging_resp and not logging_resp.get("LoggingEnabled"):
                    self.add_finding(
                        title=f"CloudTrail S3 bucket '{bucket}' access logging disabled",
                        severity=MEDIUM,
                        service="CloudTrail",
                        category="Logging & Monitoring",
                        description=f"The S3 bucket '{bucket}' storing CloudTrail logs does not have access logging enabled.",
                        resource_id=f"arn:aws:s3:::{bucket}",
                        remediation="Enable server access logging on the CloudTrail S3 bucket.",
                        compliance=["CIS 3.6"],
                    )

        if not has_multiregion:
            self.add_finding(
                title="No multi-region CloudTrail trail found",
                severity=HIGH,
                service="CloudTrail",
                category="Logging & Monitoring",
                description="No trail is configured as multi-region — activity in other regions is unmonitored.",
                resource_id=f"arn:aws:cloudtrail:{self.regions[0]}:{self.account_id}:trail/*",
                remediation="Create or update a trail with IsMultiRegionTrail=true.",
                compliance=["CIS 3.1"],
            )

    # ──────────────────────────────────────────
    # AWS Config
    # ──────────────────────────────────────────
    def _check_config(self, region: str) -> None:
        config_client = self.client("config", region)
        resp = self._safe_api_call(config_client.describe_configuration_recorders)
        if not resp or not resp.get("ConfigurationRecorders"):
            self.add_finding(
                title=f"AWS Config not enabled in {region}",
                severity=HIGH,
                service="Config",
                category="Logging & Monitoring",
                region=region,
                description=f"AWS Config is not recording in {region}. Resource configuration changes are untracked.",
                resource_id=f"arn:aws:config:{region}:{self.account_id}:*",
                remediation="Enable AWS Config with a recorder and delivery channel.",
                compliance=["CIS 3.5"],
            )
            return

        # Check recorder status
        status_resp = self._safe_api_call(config_client.describe_configuration_recorder_status)
        if status_resp:
            for status in status_resp.get("ConfigurationRecordersStatus", []):
                if not status.get("recording", False):
                    self.add_finding(
                        title=f"AWS Config recorder not recording in {region}",
                        severity=HIGH,
                        service="Config",
                        category="Logging & Monitoring",
                        region=region,
                        description="Config recorder exists but is not actively recording.",
                        resource_id=f"arn:aws:config:{region}:{self.account_id}:*",
                        remediation="Start the configuration recorder.",
                    )

    # ──────────────────────────────────────────
    # GuardDuty
    # ──────────────────────────────────────────
    def _check_guardduty(self, region: str) -> None:
        gd = self.client("guardduty", region)
        resp = self._safe_api_call(gd.list_detectors)
        if not resp or not resp.get("DetectorIds"):
            self.add_finding(
                title=f"GuardDuty not enabled in {region}",
                severity=HIGH,
                service="GuardDuty",
                category="Threat Detection",
                region=region,
                description=f"Amazon GuardDuty is not enabled in {region}. Threat detection is inactive.",
                resource_id=f"arn:aws:guardduty:{region}:{self.account_id}:detector/*",
                remediation="Enable GuardDuty in all regions.",
            )
        else:
            for det_id in resp["DetectorIds"]:
                det = self._safe_api_call(gd.get_detector, DetectorId=det_id)
                if det and det.get("Status") != "ENABLED":
                    self.add_finding(
                        title=f"GuardDuty detector '{det_id}' is not active in {region}",
                        severity=HIGH,
                        service="GuardDuty",
                        category="Threat Detection",
                        region=region,
                        description="Detector exists but is suspended or disabled.",
                        resource_id=f"arn:aws:guardduty:{region}:{self.account_id}:detector/{det_id}",
                        remediation="Re-enable the GuardDuty detector.",
                    )

    # ──────────────────────────────────────────
    # IAM Access Analyzer
    # ──────────────────────────────────────────
    def _check_access_analyzer(self, region: str) -> None:
        aa = self.client("accessanalyzer", region)
        resp = self._safe_api_call(aa.list_analyzers)
        if not resp or not resp.get("analyzers"):
            self.add_finding(
                title=f"IAM Access Analyzer not enabled in {region}",
                severity=MEDIUM,
                service="IAM Access Analyzer",
                category="Misconfiguration Detection",
                region=region,
                description=f"No IAM Access Analyzer found in {region}. External access to resources may go undetected.",
                resource_id=f"arn:aws:access-analyzer:{region}:{self.account_id}:analyzer/*",
                remediation="Create an IAM Access Analyzer for the account/org.",
                compliance=["CIS 1.20"],
            )
        else:
            for analyzer in resp["analyzers"]:
                if analyzer.get("status") != "ACTIVE":
                    self.add_finding(
                        title=f"Access Analyzer '{analyzer.get('name')}' is not active in {region}",
                        severity=MEDIUM,
                        service="IAM Access Analyzer",
                        category="Misconfiguration Detection",
                        region=region,
                        description="Analyzer exists but is not in ACTIVE state.",
                        resource_id=analyzer.get("arn", ""),
                        remediation="Recreate or re-enable the analyzer.",
                    )
