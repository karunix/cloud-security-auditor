from cloud_security_auditor.checks.security_groups import check_security_groups
from cloud_security_auditor.models import Severity


def test_world_open_ssh_detected():
    groups = [
        {
            "name": "ssh-open",
            "port": 22,
            "cidr": "0.0.0.0/0",
        }
    ]

    findings = check_security_groups(groups)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_internal_access_ok():
    groups = [
        {
            "name": "internal-db",
            "port": 5432,
            "cidr": "10.0.0.0/8",
        }
    ]

    findings = check_security_groups(groups)

    assert findings == []
