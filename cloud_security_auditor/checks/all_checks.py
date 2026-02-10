from cloud_security_auditor.checks.public_storage import check_public_storage
from cloud_security_auditor.checks.iam_policies import check_iam_policies
from cloud_security_auditor.checks.security_groups import check_security_groups


def run_all_checks(data):
    findings = []

    findings.extend(check_public_storage(data.get("storage", [])))
    findings.extend(check_iam_policies(data.get("iam_policies", [])))
    findings.extend(check_security_groups(data.get("security_groups", [])))

    return findings
