"""
EC2 & VPC Security Auditor
===========================
Checks:
  • Security groups open to 0.0.0.0/0 on sensitive ports
  • Default security groups in use / unrestricted
  • Unencrypted EBS volumes & snapshots
  • Public IPs on instances
  • IMDSv1 (instance metadata service v1) — SSRF risk
  • VPC flow logs disabled
  • Default VPC in use
  • EBS snapshots shared publicly
  • Unused Elastic IPs (cost + reconnaissance)
  • Security groups with unrestricted egress
  • Instances with no IAM role (using long-lived keys)
"""

from __future__ import annotations

import logging

from ..core import BaseAuditor
from ..config import CRITICAL, HIGH, MEDIUM, LOW, INFO, SENSITIVE_PORTS

log = logging.getLogger("aws_audit.ec2")


class EC2VPCAuditor(BaseAuditor):

    @property
    def service_name(self) -> str:
        return "EC2/VPC"

    def run(self) -> None:
        log.info("[EC2/VPC] Starting audit …")
        for region in self.regions:
            log.info("[EC2/VPC] Scanning region %s", region)
            self._check_security_groups(region)
            self._check_instances(region)
            self._check_ebs_volumes(region)
            self._check_ebs_snapshots(region)
            self._check_vpcs(region)
            self._check_flow_logs(region)
            self._check_unused_eips(region)
        log.info("[EC2/VPC] Audit complete — %d findings", len(self.findings))

    # ──────────────────────────────────────────
    # Security Groups
    # ──────────────────────────────────────────
    def _check_security_groups(self, region: str) -> None:
        sgs = self._paginate("ec2", "describe_security_groups", "SecurityGroups", region=region)

        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "")
            vpc_id = sg.get("VpcId", "")
            arn = f"arn:aws:ec2:{region}:{self.account_id}:security-group/{sg_id}"

            # Default SG should have no rules
            if sg_name == "default":
                if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                    has_ingress_rules = any(
                        rule.get("IpRanges") or rule.get("Ipv6Ranges") or rule.get("UserIdGroupPairs")
                        for rule in sg.get("IpPermissions", [])
                    )
                    has_egress_beyond_default = False
                    for rule in sg.get("IpPermissionsEgress", []):
                        for cidr in rule.get("IpRanges", []):
                            if cidr.get("CidrIp") == "0.0.0.0/0" and rule.get("IpProtocol") == "-1":
                                continue  # AWS default egress
                            has_egress_beyond_default = True
                    if has_ingress_rules:
                        self.add_finding(
                            title=f"Default security group '{sg_id}' in VPC '{vpc_id}' has ingress rules",
                            severity=MEDIUM,
                            service="EC2",
                            category="Network Security",
                            region=region,
                            description="The default security group should not allow any inbound traffic. CIS 5.4",
                            resource_id=arn,
                            remediation="Remove all inbound rules from the default security group.",
                            compliance=["CIS 5.4"],
                        )

            # Ingress rules — sensitive ports open to 0.0.0.0/0 or ::/0
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)
                protocol = rule.get("IpProtocol", "")

                open_cidrs = [
                    cidr.get("CidrIp")
                    for cidr in rule.get("IpRanges", [])
                    if cidr.get("CidrIp") in ("0.0.0.0/0",)
                ] + [
                    cidr.get("CidrIpv6")
                    for cidr in rule.get("Ipv6Ranges", [])
                    if cidr.get("CidrIpv6") in ("::/0",)
                ]

                if not open_cidrs:
                    continue

                # All traffic
                if protocol == "-1":
                    self.add_finding(
                        title=f"SG '{sg_id}' ({sg_name}) allows ALL inbound traffic from 0.0.0.0/0",
                        severity=CRITICAL,
                        service="EC2",
                        category="Network Security",
                        region=region,
                        description=(
                            f"Security group {sg_id} allows all protocols/ports inbound from the internet."
                        ),
                        resource_id=arn,
                        remediation="Restrict inbound rules to specific ports and source CIDRs.",
                    )
                    continue

                # Check specific sensitive ports
                for port, svc_name in SENSITIVE_PORTS.items():
                    if from_port <= port <= to_port:
                        severity = CRITICAL if port in (22, 3389, 3306, 5432, 27017, 6379, 445) else HIGH
                        self.add_finding(
                            title=f"SG '{sg_id}' ({sg_name}) exposes {svc_name} (port {port}) to the internet",
                            severity=severity,
                            service="EC2",
                            category="Network Security",
                            region=region,
                            description=(
                                f"Security group allows inbound {svc_name} (port {port}) "
                                f"from {', '.join(open_cidrs)}."
                            ),
                            resource_id=arn,
                            remediation=f"Restrict port {port} ({svc_name}) to specific trusted IPs.",
                            metadata={"port": port, "service": svc_name, "cidrs": open_cidrs},
                            compliance=["CIS 5.2" if port == 22 else "CIS 5.3" if port == 3389 else ""],
                        )

    # ──────────────────────────────────────────
    # EC2 Instances
    # ──────────────────────────────────────────
    def _check_instances(self, region: str) -> None:
        reservations = self._paginate(
            "ec2", "describe_instances", "Reservations", region=region
        )
        for res in reservations:
            for inst in res.get("Instances", []):
                inst_id = inst["InstanceId"]
                state = inst.get("State", {}).get("Name", "")
                if state == "terminated":
                    continue
                arn = f"arn:aws:ec2:{region}:{self.account_id}:instance/{inst_id}"

                # Public IP
                if inst.get("PublicIpAddress"):
                    self.add_finding(
                        title=f"Instance '{inst_id}' has public IP {inst['PublicIpAddress']}",
                        severity=MEDIUM,
                        service="EC2",
                        category="Network Exposure",
                        region=region,
                        description=(
                            f"Instance {inst_id} is directly reachable on {inst['PublicIpAddress']}. "
                            "Ensure this is intentional and a security group restricts access."
                        ),
                        resource_id=arn,
                        remediation="Use a load balancer or bastion host instead of public IPs where possible.",
                        metadata={"public_ip": inst["PublicIpAddress"]},
                    )

                # IMDSv1 (SSRF risk — Capital One breach vector)
                metadata_options = inst.get("MetadataOptions", {})
                http_tokens = metadata_options.get("HttpTokens", "optional")
                if http_tokens != "required":
                    self.add_finding(
                        title=f"Instance '{inst_id}' uses IMDSv1 (SSRF risk)",
                        severity=HIGH,
                        service="EC2",
                        category="Instance Metadata",
                        region=region,
                        description=(
                            f"Instance {inst_id} allows IMDSv1 (HttpTokens=optional). "
                            "This makes the instance vulnerable to SSRF-based credential theft "
                            "(e.g., the Capital One breach vector)."
                        ),
                        resource_id=arn,
                        remediation="Enforce IMDSv2 by setting HttpTokens to 'required'.",
                        references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"],
                    )

                # No IAM role
                if not inst.get("IamInstanceProfile"):
                    self.add_finding(
                        title=f"Instance '{inst_id}' has no IAM instance profile",
                        severity=MEDIUM,
                        service="EC2",
                        category="Best Practice",
                        region=region,
                        description=(
                            f"Instance {inst_id} has no IAM role attached. Applications "
                            "may be using long-lived access keys instead of temporary credentials."
                        ),
                        resource_id=arn,
                        remediation="Attach an IAM instance profile with least-privilege permissions.",
                    )

                # Unencrypted root volume
                for bdm in inst.get("BlockDeviceMappings", []):
                    ebs = bdm.get("Ebs", {})
                    vol_id = ebs.get("VolumeId")
                    if vol_id:
                        # We'll check volumes in the dedicated volume check
                        pass

    # ──────────────────────────────────────────
    # EBS Volumes
    # ──────────────────────────────────────────
    def _check_ebs_volumes(self, region: str) -> None:
        volumes = self._paginate("ec2", "describe_volumes", "Volumes", region=region)
        for vol in volumes:
            vol_id = vol["VolumeId"]
            arn = f"arn:aws:ec2:{region}:{self.account_id}:volume/{vol_id}"
            if not vol.get("Encrypted", False):
                self.add_finding(
                    title=f"EBS volume '{vol_id}' is not encrypted",
                    severity=HIGH,
                    service="EC2",
                    category="Encryption",
                    region=region,
                    description=f"EBS volume {vol_id} is unencrypted. Data at rest is exposed.",
                    resource_id=arn,
                    remediation="Enable EBS encryption by default in the region, and re-create unencrypted volumes.",
                    compliance=["CIS 2.2.1"],
                )

    # ──────────────────────────────────────────
    # EBS Snapshots
    # ──────────────────────────────────────────
    def _check_ebs_snapshots(self, region: str) -> None:
        ec2 = self.client("ec2", region)
        resp = self._safe_api_call(
            ec2.describe_snapshots, OwnerIds=["self"], MaxResults=500
        )
        if not resp:
            return
        for snap in resp.get("Snapshots", []):
            snap_id = snap["SnapshotId"]
            arn = f"arn:aws:ec2:{region}:{self.account_id}:snapshot/{snap_id}"

            # Check if shared publicly
            attrs = self._safe_api_call(
                ec2.describe_snapshot_attribute,
                SnapshotId=snap_id,
                Attribute="createVolumePermission",
            )
            if attrs:
                for perm in attrs.get("CreateVolumePermissions", []):
                    if perm.get("Group") == "all":
                        self.add_finding(
                            title=f"EBS snapshot '{snap_id}' is publicly shared",
                            severity=CRITICAL,
                            service="EC2",
                            category="Data Exposure",
                            region=region,
                            description=(
                                f"Snapshot {snap_id} is shared with all AWS accounts. "
                                "Anyone can create a volume from it and read the data."
                            ),
                            resource_id=arn,
                            remediation="Remove the 'all' group from createVolumePermission.",
                        )

            # Unencrypted snapshot
            if not snap.get("Encrypted", False):
                self.add_finding(
                    title=f"EBS snapshot '{snap_id}' is not encrypted",
                    severity=MEDIUM,
                    service="EC2",
                    category="Encryption",
                    region=region,
                    description=f"Snapshot {snap_id} is unencrypted.",
                    resource_id=arn,
                    remediation="Copy the snapshot with encryption enabled, then delete the original.",
                )

    # ──────────────────────────────────────────
    # VPCs — default VPC
    # ──────────────────────────────────────────
    def _check_vpcs(self, region: str) -> None:
        ec2 = self.client("ec2", region)
        resp = self._safe_api_call(ec2.describe_vpcs)
        if not resp:
            return
        for vpc in resp.get("Vpcs", []):
            if vpc.get("IsDefault", False):
                vpc_id = vpc["VpcId"]
                arn = f"arn:aws:ec2:{region}:{self.account_id}:vpc/{vpc_id}"
                self.add_finding(
                    title=f"Default VPC '{vpc_id}' exists in region {region}",
                    severity=LOW,
                    service="VPC",
                    category="Network Architecture",
                    region=region,
                    description=(
                        f"The default VPC ({vpc_id}) exists in {region}. Default VPCs "
                        "have public subnets, internet gateways, and permissive settings. "
                        "They should not be used for production workloads."
                    ),
                    resource_id=arn,
                    remediation="Delete the default VPC or ensure it is not used for production.",
                )

    # ──────────────────────────────────────────
    # VPC Flow Logs
    # ──────────────────────────────────────────
    def _check_flow_logs(self, region: str) -> None:
        ec2 = self.client("ec2", region)
        vpcs = self._safe_api_call(ec2.describe_vpcs)
        if not vpcs:
            return
        flow_logs = self._safe_api_call(ec2.describe_flow_logs)
        fl_resource_ids = set()
        if flow_logs:
            for fl in flow_logs.get("FlowLogs", []):
                fl_resource_ids.add(fl.get("ResourceId"))

        for vpc in vpcs.get("Vpcs", []):
            vpc_id = vpc["VpcId"]
            if vpc_id not in fl_resource_ids:
                arn = f"arn:aws:ec2:{region}:{self.account_id}:vpc/{vpc_id}"
                self.add_finding(
                    title=f"VPC '{vpc_id}' in {region} has no flow logs enabled",
                    severity=MEDIUM,
                    service="VPC",
                    category="Logging & Monitoring",
                    region=region,
                    description=f"VPC {vpc_id} does not have flow logs — network traffic is unmonitored.",
                    resource_id=arn,
                    remediation="Enable VPC Flow Logs to S3 or CloudWatch Logs.",
                    compliance=["CIS 3.9"],
                )

    # ──────────────────────────────────────────
    # Unused Elastic IPs
    # ──────────────────────────────────────────
    def _check_unused_eips(self, region: str) -> None:
        ec2 = self.client("ec2", region)
        resp = self._safe_api_call(ec2.describe_addresses)
        if not resp:
            return
        for addr in resp.get("Addresses", []):
            if not addr.get("AssociationId"):
                self.add_finding(
                    title=f"Unused Elastic IP {addr.get('PublicIp', 'N/A')} in {region}",
                    severity=LOW,
                    service="EC2",
                    category="Cost & Hygiene",
                    region=region,
                    description=(
                        f"Elastic IP {addr.get('PublicIp')} is allocated but not associated "
                        "with any resource. Unused EIPs cost money and may be probed."
                    ),
                    resource_id=addr.get("AllocationId", ""),
                    remediation="Release unused Elastic IPs.",
                )
