APP_NAME = "LinuxSentinel"
VERSION = "1.0.0"

REPORT_DIRECTORY = "sample_reports"

SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config"
]

SEVERITY_POINTS = {
    "CRITICAL": 15,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0
}
