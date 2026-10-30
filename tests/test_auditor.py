
from app.auditor import audit_iam_policy
from app.s3_auditor import audit_s3_configuration


def test_iam_detects_full_wildcard_access():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }]
    }

    findings = audit_iam_policy(policy)

    assert any(
        finding["check"] == "IAM_WILDCARD_ACCESS"
        and finding["severity"] == "HIGH"
        for finding in findings
    )


def test_iam_accepts_specific_read_permission():
    policy = {
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": [
                "arn:aws:s3:::example-bucket/*"
            ]
        }]
    }

    assert audit_iam_policy(policy) == []


def test_s3_detects_disabled_public_access_block():
    config = {
        "public_access_block": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False
        },
        "encryption": {"enabled": True}
    }

    findings = audit_s3_configuration(config)

    assert any(
        finding["check"] == "S3_PUBLIC_ACCESS_BLOCK_DISABLED"
        for finding in findings
    )


def test_s3_detects_unconfirmed_encryption():
    config = {
        "public_access_block": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        },
        "encryption": {"enabled": False}
    }

    findings = audit_s3_configuration(config)

    assert any(
        finding["check"] == "S3_ENCRYPTION_NOT_CONFIRMED"
        for finding in findings
    )
