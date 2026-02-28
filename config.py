"""
AWS Security Audit Tool — Configuration & Constants
"""

# ──────────────────────────────────────────────
# Severity Levels
# ──────────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

# ──────────────────────────────────────────────
# Dangerous IAM Actions (privilege-escalation)
# Reference: Rhino Security Labs, Bishop Fox, AWS docs
# ──────────────────────────────────────────────
PRIVESC_ACTIONS: dict[str, list[str]] = {
    "iam_create_user_login_profile": [
        "iam:CreateLoginProfile",
    ],
    "iam_update_login_profile": [
        "iam:UpdateLoginProfile",
    ],
    "iam_create_access_key": [
        "iam:CreateAccessKey",
    ],
    "iam_create_policy_version": [
        "iam:CreatePolicyVersion",
    ],
    "iam_set_default_policy_version": [
        "iam:SetDefaultPolicyVersion",
    ],
    "iam_attach_user_policy": [
        "iam:AttachUserPolicy",
    ],
    "iam_attach_group_policy": [
        "iam:AttachGroupPolicy",
    ],
    "iam_attach_role_policy": [
        "iam:AttachRolePolicy",
    ],
    "iam_put_user_policy": [
        "iam:PutUserPolicy",
    ],
    "iam_put_group_policy": [
        "iam:PutGroupPolicy",
    ],
    "iam_put_role_policy": [
        "iam:PutRolePolicy",
    ],
    "iam_add_user_to_group": [
        "iam:AddUserToGroup",
    ],
    "iam_update_assume_role_policy": [
        "iam:UpdateAssumeRolePolicy",
    ],
    "iam_pass_role_ec2": [
        "iam:PassRole",
        "ec2:RunInstances",
    ],
    "iam_pass_role_lambda": [
        "iam:PassRole",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
    ],
    "iam_pass_role_cloudformation": [
        "iam:PassRole",
        "cloudformation:CreateStack",
    ],
    "iam_pass_role_datapipeline": [
        "iam:PassRole",
        "datapipeline:CreatePipeline",
        "datapipeline:PutPipelineDefinition",
        "datapipeline:ActivatePipeline",
    ],
    "iam_pass_role_glue": [
        "iam:PassRole",
        "glue:CreateDevEndpoint",
    ],
    "lambda_update_function_code": [
        "lambda:UpdateFunctionCode",
    ],
    "lambda_update_function_config": [
        "lambda:UpdateFunctionConfiguration",
    ],
    "glue_update_dev_endpoint": [
        "glue:UpdateDevEndpoint",
    ],
    "sts_assume_role": [
        "sts:AssumeRole",
    ],
    "ssm_start_session": [
        "ssm:StartSession",
    ],
    "ssm_send_command": [
        "ssm:SendCommand",
    ],
    "ec2_instance_connect": [
        "ec2-instance-connect:SendSSHPublicKey",
    ],
    "codestar_create_project": [
        "codestar:CreateProject",
    ],
    "codestar_associate_member": [
        "codestar:AssociateTeamMember",
    ],
    "sagemaker_create_notebook": [
        "sagemaker:CreateNotebookInstance",
        "iam:PassRole",
    ],
    "sagemaker_create_training_job": [
        "sagemaker:CreateTrainingJob",
        "iam:PassRole",
    ],
}

# Actions that grant admin-equivalent access
ADMIN_ACTIONS = [
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:CreateUser",
    "iam:CreateRole",
    "sts:AssumeRole",
]

# High-risk managed policy ARNs
HIGH_RISK_POLICIES = [
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "arn:aws:iam::aws:policy/AmazonRDSFullAccess",
    "arn:aws:iam::aws:policy/AmazonVPCFullAccess",
    "arn:aws:iam::aws:policy/AWSLambda_FullAccess",
]

# Sensitive ports
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1434: "MSSQL-UDP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Transport",
    11211: "Memcached",
    27017: "MongoDB",
}

# CIS Benchmark password policy minimums
CIS_PASSWORD_POLICY = {
    "MinimumPasswordLength": 14,
    "RequireSymbols": True,
    "RequireNumbers": True,
    "RequireUppercaseCharacters": True,
    "RequireLowercaseCharacters": True,
    "MaxPasswordAge": 90,
    "PasswordReusePrevention": 24,
}

# Max days since last credential use before flagged stale
STALE_CREDENTIAL_DAYS = 90
STALE_ACCESS_KEY_DAYS = 90
