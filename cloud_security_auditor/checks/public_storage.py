from cloud_security_auditor.models import Finding, Severity


def check_public_storage(resources):
    findings = []

    for resource in resources:
        if resource.get("public") is True:
            findings.append(
                Finding(
                    scope="Cloud Storage",
                    observation=f"Storage resource '{resource.get('name')}' is publicly accessible",
                    severity=Severity.HIGH,
                    explanation=(
                        "Publicly accessible cloud storage resources may expose sensitive data "
                        "to unauthorized users on the internet."
                    ),
                    recommendation=(
                        "Restrict public access to the storage resource and enforce "
                        "least-privilege access controls."
                    ),
                )
            )

    return findings
