from cloud_security_auditor.checks.public_storage import check_public_storage
from cloud_security_auditor.models import Severity


def test_public_bucket_detected():
    resources = [
        {
            "name": "logs-bucket",
            "public": True,
        }
    ]

    findings = check_public_storage(resources)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_private_bucket_ok():
    resources = [
        {
            "name": "private-backups",
            "public": False,
        }
    ]

    findings = check_public_storage(resources)

    assert findings == []
