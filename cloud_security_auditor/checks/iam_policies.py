from cloud_security_auditor.models import Finding, Severity


def check_iam_policies(policies):
    findings = []

    for policy in policies:
        actions = policy.get("actions", [])
        resources = policy.get("resources", [])

        if "*" in actions or "*" in resources:
            findings.append(
                Finding(
                    scope="IAM",
                    observation=f"IAM policy '{policy.get('name')}' uses wildcard permissions",
                    severity=Severity.CRITICAL,
                    explanation=(
                        "Wildcard IAM permissions grant unrestricted access and "
                        "significantly increase the blast radius of a compromise."
                    ),
                    recommendation=(
                        "Replace wildcard permissions with least-privilege "
                        "actions and explicitly scoped resources."
                    ),
                )
            )

    return findings
