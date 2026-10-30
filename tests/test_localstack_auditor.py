

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "app"))

from s3_auditor import audit_s3_configuration


def test_secure_s3_configuration_has_no_high_findings():
    config = {
        "public_access_block": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        "encryption": {"enabled": True},
    }

    findings = audit_s3_configuration(config)

    assert not any(f["severity"] == "HIGH" for f in findings)


def test_disabled_public_access_block_is_high_risk():
    config = {
        "public_access_block": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        "encryption": {"enabled": True},
    }

    findings = audit_s3_configuration(config)

    assert any(
        f["severity"] == "HIGH"
        and f["check"] == "S3_PUBLIC_ACCESS_BLOCK_DISABLED"
        for f in findings
    )


def test_missing_encryption_is_flagged():
    config = {
        "public_access_block": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        "encryption": {"enabled": False},
    }

    findings = audit_s3_configuration(config)

    assert any(
        f["check"] == "S3_ENCRYPTION_NOT_CONFIRMED"
        for f in findings
    )
