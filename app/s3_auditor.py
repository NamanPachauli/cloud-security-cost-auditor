
def audit_s3_configuration(config):
    """
    Audit a normalized S3 configuration.
    Missing settings are treated as unknown, not as secure.
    """
    findings = []

    public_block = config.get("public_access_block")
    encryption = config.get("encryption")

    if public_block is None:
        findings.append({
            "severity": "REVIEW",
            "check": "S3_PUBLIC_ACCESS_UNKNOWN",
            "message": "Public access settings were not provided.",
            "recommendation": "Retrieve and verify all four S3 public-access block settings."
        })
    else:
        required_settings = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]

        missing = [
            key for key in required_settings
            if key not in public_block
        ]

        if missing:
            findings.append({
                "severity": "REVIEW",
                "check": "S3_PUBLIC_ACCESS_INCOMPLETE",
                "message": f"Missing settings: {', '.join(missing)}",
                "recommendation": "Retrieve all four public-access block settings."
            })
        else:
            disabled = [
                key for key in required_settings
                if public_block[key] is not True
            ]

            if disabled:
                findings.append({
                    "severity": "HIGH",
                    "check": "S3_PUBLIC_ACCESS_BLOCK_DISABLED",
                    "message": f"Public access protections are disabled or false: {', '.join(disabled)}",
                    "recommendation": "Enable all four protections unless a documented requirement justifies otherwise."
                })

    if encryption is None:
        findings.append({
            "severity": "REVIEW",
            "check": "S3_ENCRYPTION_UNKNOWN",
            "message": "Encryption configuration was not provided.",
            "recommendation": "Retrieve the bucket's default encryption configuration."
        })
    elif encryption.get("enabled") is not True:
        findings.append({
            "severity": "HIGH",
            "check": "S3_ENCRYPTION_NOT_CONFIRMED",
            "message": "Default encryption is not confirmed as enabled.",
            "recommendation": "Enable and verify S3 default encryption."
        })

    if not findings:
        findings.append({
            "severity": "PASS",
            "check": "S3_BASIC_SECURITY_CHECKS",
            "message": "Provided public-access and encryption settings passed these basic checks."
        })

    return findings
