SEVERITIES = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO"
]


def is_valid_severity(severity):
    return severity in SEVERITIES
