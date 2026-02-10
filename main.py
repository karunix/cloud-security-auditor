import argparse
import json
import sys

from cloud_security_auditor.checks.all_checks import run_all_checks
from cloud_security_auditor.utils import exit_code_from_findings


def parse_args():
    parser = argparse.ArgumentParser(
        description="Cloud Security Auditor"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to JSON file with cloud configuration data"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    with open(args.input) as f:
        data = json.load(f)

    findings = run_all_checks(data)

    if args.json:
        print(json.dumps(
            {"findings": [f.__dict__ for f in findings]},
            default=str,
        ))
    else:
        for f in findings:
            print(f.severity.value, "-", f.observation)

    sys.exit(exit_code_from_findings(findings))


if __name__ == "__main__":
    main()
