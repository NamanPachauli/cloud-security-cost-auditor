
import json


def audit_iam_policy(policy_document):
    """Detect basic risky permissions in an IAM policy document."""
    findings = []

    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for index, statement in enumerate(statements, start=1):
        effect = statement.get("Effect", "")
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        if effect != "Allow":
            continue

        wildcard_action = "*" in actions
        wildcard_resource = "*" in resources

        if wildcard_action and wildcard_resource:
            findings.append({
                "severity": "HIGH",
                "check": "IAM_WILDCARD_ACCESS",
                "statement": index,
                "message": (
                    "Allow statement grants wildcard actions "
                    "on all resources."
                ),
                "recommendation": (
                    "Restrict actions and resources to the "
                    "minimum permissions required."
                ),
            })
        elif wildcard_action or wildcard_resource:
            findings.append({
                "severity": "MEDIUM",
                "check": "IAM_WILDCARD_PERMISSION",
                "statement": index,
                "message": (
                    "Allow statement contains a wildcard "
                    "action or resource."
                ),
                "recommendation": (
                    "Review the wildcard and apply least privilege."
                ),
            })

    return findings


def audit_policy_file(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        policy = json.load(file)

    return audit_iam_policy(policy)
