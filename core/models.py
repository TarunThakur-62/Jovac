from dataclasses import dataclass


@dataclass
class Finding:
    category: str
    title: str
    severity: str
    description: str
    recommendation: str
