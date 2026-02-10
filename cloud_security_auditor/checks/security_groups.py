
from cloud_security_auditor.models import Finding, Severity

SENSITIVE_PORTS = {22, 3389, 3306, 5432}


def check_security_groups(groups):
    findings = []

    for group in groups:
        if (
            group.get("cidr") == "0.0.0.0/0"
            and group.get("port") in SENSITIVE_PORTS
        ):
            findings.append(
                Finding(
                    scope="Network",
                    observation=(
                        f"Security group '{group.get('name')}' allows world-access "
                        f"to port {group.get('port')}"
                    ),
                    severity=Severity.HIGH,
                    explanation=(
                        "Open access to sensitive ports from the internet significantly "
                        "increases the risk of unauthorized access and exploitation."
                    ),
                    recommendation=(
                        "Restrict access to trusted IP ranges or use bastion hosts "
                        "and private networking."
                    ),
                )
            )

    return findings
