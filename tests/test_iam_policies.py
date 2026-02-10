from cloud_security_auditor.checks.iam_policies import check_iam_policies
from cloud_security_auditor.models import Severity


def test_wildcard_policy_detected():
    policies = [
        {
            "name": "AdminAccess",
            "actions": ["*"],
            "resources": ["*"],
        }
    ]

    findings = check_iam_policies(policies)

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_least_privilege_policy_ok():
    policies = [
        {
            "name": "ReadOnlyLogs",
            "actions": ["logs:Read"],
            "resources": ["arn:aws:logs:::log-group/app"],
        }
    ]

    findings = check_iam_policies(policies)

    assert findings == []
