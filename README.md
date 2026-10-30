# Cloud Security & Cost Audit Automation

A Python-based cloud security and cost-risk auditing project. It checks sample IAM policies, normalized S3 security configurations, and resource inventories. LocalStack is used to practice S3 API integration locally without creating real AWS resources.

## Project Objectives

- Detect overly permissive IAM policies.
- Check S3 public-access-block settings and encryption configuration.
- Identify potential cloud cost risks in a resource inventory.
- Generate a machine-readable JSON audit report.
- Use automated tests to validate audit logic.

## Technology Stack

- Python
- boto3 and AWS CLI
- pytest
- LocalStack
- JSON
- Git

## Architecture

```text
Sample Policies / Resource Inventory
                 |
                 v
       Python Audit Modules
       |        |        |
       IAM      S3     Cost Risk
       Checks  Checks   Checks
                 |
                 v
       JSON Audit Report
                 |
                 v
         pytest Validation
```

LocalStack S3 integration is a separate local API-based check.

## Security Checks

### IAM
- Detect wildcard permissions such as `Action: "*"` and `Resource: "*"`.

### S3
- Check the four public-access-block settings.
- Check whether default encryption is confirmed.
- Flag missing or incomplete configuration for review.

### Cost Risk
- Flag running compute resources as potential ongoing-cost risks.
- Identify missing ownership and environment tags.
- Identify unattached storage volumes.

Cost-risk findings are indicators, not exact billing estimates.

## Run Locally

Activate the virtual environment in Windows CMD:

```cmd
.venv\Scripts\activate
```

Run automated tests:

```cmd
python -m pytest -v
```

Generate the sample audit report:

```cmd
python app\main.py
```

Inspect the report:

```cmd
type reports\security-audit-report.json
```

## Important Limitations

- LocalStack is a local AWS API simulation, not a real AWS account.
- Sample-data results do not prove that a real AWS environment is secure.
- This project does not guarantee exact cloud costs or prevent all misconfigurations.
- Real AWS integration requires separate authentication, permissions, and cost-safety checks.

## Project Status

Development and testing are in progress. Record only checks that have been run successfully, and include actual test results before publishing.
