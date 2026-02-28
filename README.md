# AWS Security Audit Tool

A comprehensive, modular Python tool that audits your AWS account for **vulnerabilities**, **risky permissions**, **misconfigurations**, and **privilege escalation attack vectors** — outputting a structured JSON report.

---

## Features

### Service Auditors
| Service | Checks |
|---------|--------|
| **IAM** | Root MFA, access keys, stale credentials, password policy (CIS), inline policies, overly permissive policies, wildcard permissions, cross-account trust, high-risk managed policies |
| **S3** | Public buckets (ACL & policy), Block Public Access, encryption, versioning, MFA Delete, access logging, HTTPS enforcement, lifecycle rules |
| **EC2/VPC** | Open security groups (sensitive ports), IMDSv1 (SSRF risk), public IPs, unencrypted EBS, public snapshots, default VPCs, flow logs, unused EIPs, instances without IAM roles |
| **RDS** | Public accessibility, encryption, backups, deletion protection, IAM auth, default usernames, public snapshots, audit logging, Aurora clusters |
| **CloudTrail/Logging** | Multi-region trail, log validation, KMS encryption, CloudWatch integration, AWS Config, GuardDuty, IAM Access Analyzer |
| **Lambda** | Public functions, deprecated runtimes, VPC config, secrets in env vars, dead-letter queues |
| **KMS** | Key rotation, overly permissive key policies, keys pending deletion |

### Privilege Escalation Detection
Detects **22+ known IAM privilege escalation attack paths** based on research from Rhino Security Labs, Bishop Fox, and AWS documentation:

- Policy manipulation (CreatePolicyVersion, SetDefaultPolicyVersion)
- Policy attachment (AttachUserPolicy, AttachRolePolicy, PutUserPolicy, etc.)
- Credential creation (CreateAccessKey, CreateLoginProfile, UpdateLoginProfile)
- Role assumption chains (role A → assume admin role B)
- PassRole exploitation (EC2, Lambda, CloudFormation, Glue, SageMaker, DataPipeline)
- Function code injection (Lambda UpdateFunctionCode/Config)
- Session hijacking (SSM StartSession/SendCommand, EC2 Instance Connect)
- CodeStar project creation/member association

### Report Output
- **JSON report** with metadata, severity breakdown, risk score/rating, top affected resources
- **Rich terminal summary** with colour-coded severity tables
- **Exit codes**: 0 = clean, 1 = HIGH findings, 2 = CRITICAL findings (CI/CD friendly)

---

## Installation

```bash
cd Cloud_AWS_ASM
pip install -r requirements.txt
```

### Prerequisites
- Python 3.10+
- AWS credentials configured (`aws configure`, environment variables, or IAM role)
- Read-only IAM permissions (see below)

---

## Usage

```bash
# Basic scan (us-east-1, all services)
python -m Cloud_AWS_ASM.scanner

# Specific profile and regions
python -m Cloud_AWS_ASM.scanner --profile production --regions us-east-1,eu-west-1

# All commercial regions
python -m Cloud_AWS_ASM.scanner --all-regions --output full_audit.json

# Specific services only
python -m Cloud_AWS_ASM.scanner --services iam,s3,privesc

# Only CRITICAL and HIGH findings
python -m Cloud_AWS_ASM.scanner --severity CRITICAL,HIGH

# JSON to stdout (for piping)
python -m Cloud_AWS_ASM.scanner --json-only --quiet

# Verbose debug output
python -m Cloud_AWS_ASM.scanner -v
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--profile, -p` | AWS CLI profile name |
| `--regions, -r` | Comma-separated regions (default: `us-east-1`) |
| `--all-regions` | Scan all commercial AWS regions |
| `--services, -s` | Comma-separated services: `iam,s3,ec2,rds,logging,lambda,kms,privesc` |
| `--output, -o` | Output JSON path (auto-generated if omitted) |
| `--severity` | Filter by severity (e.g. `CRITICAL,HIGH`) |
| `--json-only` | Output raw JSON to stdout |
| `--quiet, -q` | Suppress progress logging |
| `--verbose, -v` | Enable debug logging |

---

## Output Format

```json
{
  "metadata": {
    "tool": "AWS Security Audit Tool",
    "version": "1.0.0",
    "timestamp": "2026-02-28T12:00:00+00:00",
    "account_id": "123456789012",
    "regions_scanned": ["us-east-1", "eu-west-1"],
    "scan_duration_seconds": 45.2
  },
  "summary": {
    "total_findings": 42,
    "risk_score": 185,
    "risk_rating": "CRITICAL",
    "severity_breakdown": {
      "CRITICAL": 5,
      "HIGH": 12,
      "MEDIUM": 15,
      "LOW": 8,
      "INFO": 2
    },
    "privilege_escalation": {
      "total_paths": 3,
      "unique_techniques": 2,
      "techniques": ["iam_attach_role_policy", "iam_pass_role_lambda"]
    }
  },
  "findings": [
    {
      "finding_id": "uuid",
      "title": "Root account MFA not enabled",
      "severity": "CRITICAL",
      "service": "IAM",
      "category": "Authentication",
      "description": "...",
      "resource_id": "arn:aws:iam::123456789012:root",
      "region": "global",
      "remediation": "Enable a hardware MFA device...",
      "compliance": ["CIS 1.5", "SOC2 CC6.1"],
      "references": [],
      "metadata": {},
      "timestamp": "2026-02-28T12:00:00+00:00"
    }
  ],
  "errors": []
}
```

---

## Required IAM Permissions

Attach the **SecurityAudit** AWS-managed policy, or create a custom policy with:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*", "iam:List*", "iam:GenerateCredentialReport",
        "s3:GetBucket*", "s3:GetEncryptionConfiguration", "s3:ListAllMyBuckets",
        "ec2:Describe*",
        "rds:Describe*",
        "cloudtrail:Describe*", "cloudtrail:GetTrailStatus",
        "config:Describe*",
        "guardduty:List*", "guardduty:GetDetector",
        "access-analyzer:List*",
        "lambda:List*", "lambda:GetPolicy", "lambda:GetFunction",
        "kms:List*", "kms:Describe*", "kms:GetKeyRotationStatus", "kms:GetKeyPolicy",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Architecture

```
Cloud_AWS_ASM/
├── __init__.py
├── __main__.py            # python -m entry point
├── scanner.py             # CLI & orchestrator
├── core.py                # Finding model & BaseAuditor ABC
├── config.py              # Constants, thresholds, privesc action map
├── report.py              # JSON report generator & terminal summary
├── requirements.txt
├── README.md
└── auditors/
    ├── __init__.py
    ├── iam_auditor.py         # IAM checks
    ├── s3_auditor.py          # S3 checks
    ├── ec2_vpc_auditor.py     # EC2 & VPC checks
    ├── rds_auditor.py         # RDS & Aurora checks
    ├── logging_auditor.py     # CloudTrail, Config, GuardDuty, Access Analyzer
    ├── lambda_kms_auditor.py  # Lambda & KMS checks
    └── privesc_auditor.py     # Privilege escalation path detection
```

---

## References

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [Rhino Security Labs — AWS Privilege Escalation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [SentinelOne — AWS Security Issues](https://www.sentinelone.com/cybersecurity-101/cloud-security/aws-security-issues/)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
