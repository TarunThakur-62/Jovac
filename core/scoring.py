from config import SEVERITY_POINTS


def calculate_score(findings):
    score = 100

    for finding in findings:
        severity = finding.severity

        if severity in SEVERITY_POINTS:
            score -= SEVERITY_POINTS[severity]

    return max(score, 0)


def get_risk_level(score):

    if score >= 90:
        return "LOW"

    elif score >= 70:
        return "MEDIUM"

    elif score >= 40:
        return "HIGH"

    else:
        return "CRITICAL"
