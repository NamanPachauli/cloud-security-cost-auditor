
import boto3
from botocore.exceptions import BotoCoreError, ClientError


def get_local_s3_client():
    return boto3.client(
        "s3",
        endpoint_url="http://localhost:4566",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def audit_local_s3():
    client = get_local_s3_client()
    results = []

    try:
        response = client.list_buckets()

        for bucket in response.get("Buckets", []):
            name = bucket["Name"]
            findings = []

            try:
                public_access = client.get_public_access_block(
                    Bucket=name
                )["PublicAccessBlockConfiguration"]

                if not all(public_access.get(key, False) for key in [
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                ]):
                    findings.append({
                        "severity": "HIGH",
                        "check": "S3_PUBLIC_ACCESS_BLOCK_DISABLED",
                    })

            except ClientError as error:
                code = error.response.get("Error", {}).get("Code", "")

                if code in (
                    "NoSuchPublicAccessBlockConfiguration",
                    "NoSuchBucket",
                ):
                    findings.append({
                        "severity": "REVIEW",
                        "check": "S3_PUBLIC_ACCESS_BLOCK_NOT_CONFIGURED",
                    })
                else:
                    findings.append({
                        "severity": "REVIEW",
                        "check": "S3_PUBLIC_ACCESS_CHECK_ERROR",
                        "detail": code,
                    })

            try:
                client.get_bucket_encryption(Bucket=name)
            except ClientError as error:
                code = error.response.get("Error", {}).get("Code", "")

                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    findings.append({
                        "severity": "REVIEW",
                        "check": "S3_ENCRYPTION_NOT_CONFIGURED",
                    })
                else:
                    findings.append({
                        "severity": "REVIEW",
                        "check": "S3_ENCRYPTION_CHECK_ERROR",
                        "detail": code,
                    })

            results.append({
                "bucket": name,
                "findings": findings,
            })

        return results

    except (BotoCoreError, ClientError) as error:
        return [{
            "error": str(error),
            "message": "Unable to query LocalStack S3."
        }]
