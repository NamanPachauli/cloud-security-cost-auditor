

import json
from datetime import datetime, timezone
from pathlib import Path

from auditor import audit_policy_file
from s3_auditor import audit_s3_configuration
from cost_auditor import audit_resource_inventory

ROOT = Path(__file__).resolve().parent.parent
POLICIES = ROOT / "policies"
REPORTS = ROOT / "reports"


def load_json(path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def main():
    REPORTS.mkdir(exist_ok=True)

    iam_findings = audit_policy_file(
        POLICIES / "test-policy.json"
    )

    s3_config = load_json(
        POLICIES / "s3-test-config.json"
    )
    s3_findings = audit_s3_configuration(s3_config)

    inventory = load_json(
        POLICIES / "resource-inventory.json"
    )
    cost_findings = audit_resource_inventory(inventory)

    findings = (
        [{"service": "IAM", **item} for item in iam_findings]
        + [{"service": "S3", **item} for item in s3_findings]
        + [{"service": "COST_RISK", **item} for item in cost_findings]
    )

    severities = ["HIGH", "MEDIUM", "LOW", "REVIEW", "PASS"]
    summary = {
        severity.lower(): sum(
            item["severity"] == severity for item in findings
        )
        for severity in severities
    }
    summary["total_findings"] = len(findings)

    report = {
        "project": "Cloud Security & Cost Audit Automation",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_type": "LOCAL_SAMPLE_DATA",
        "important_note": (
            "Results reflect sample configurations only. "
            "They are not findings from a live AWS account."
        ),
        "summary": summary,
        "findings": findings,
    }

    output = REPORTS / "security-audit-report.json"
    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(summary, indent=2))
    print(f"\nReport saved to: {output}")


if __name__ == "__main__":
    main()
