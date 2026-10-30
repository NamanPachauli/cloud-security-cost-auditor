
def audit_resource_inventory(inventory):
    """Flag potential cost risks in a resource inventory."""
    findings = []

    for instance in inventory.get("instances", []):
        instance_id = instance.get("instance_id", "unknown")
        state = instance.get("state", "unknown").lower()

        if state == "running":
            findings.append({
                "severity": "REVIEW",
                "check": "EC2_RUNNING_INSTANCE",
                "resource": instance_id,
                "message": "Instance is running and may incur compute charges.",
                "recommendation": (
                    "Confirm that the instance is needed. "
                    "Stop or terminate it only after checking dependencies."
                )
            })

        tags = instance.get("tags", {})
        if isinstance(tags, list):
            tags = {
                item.get("Key"): item.get("Value")
                for item in tags
                if isinstance(item, dict)
            }

        required_tags = ["Owner", "Environment", "Project"]
        missing_tags = [
            tag for tag in required_tags
            if not tags.get(tag)
        ]

        if missing_tags:
            findings.append({
                "severity": "LOW",
                "check": "RESOURCE_TAGS_MISSING",
                "resource": instance_id,
                "message": (
                    "Missing recommended tags: "
                    + ", ".join(missing_tags)
                ),
                "recommendation": (
                    "Add ownership, environment and project tags "
                    "to improve cost allocation."
                )
            })

    for volume in inventory.get("volumes", []):
        volume_id = volume.get("volume_id", "unknown")
        state = volume.get("state", "unknown").lower()

        if state == "available":
            findings.append({
                "severity": "REVIEW",
                "check": "EBS_UNATTACHED_VOLUME",
                "resource": volume_id,
                "message": (
                    "Volume is unattached and may still incur "
                    "storage charges."
                ),
                "recommendation": (
                    "Verify whether the volume is needed before "
                    "deleting it."
                )
            })

    return findings
