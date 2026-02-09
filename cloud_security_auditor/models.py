from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    scope: str
    observation: str
    severity: Severity
    explanation: str
    recommendation: str
