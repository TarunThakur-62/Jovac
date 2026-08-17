# 🛡️ LinuxSentinel

### Linux Security Audit & System Hardening Tool

LinuxSentinel is a Python-based Linux Security Audit Tool designed to
identify common security weaknesses, misconfigurations, and potentially
risky system configurations.

It performs modular security audits of Linux systems and organizes the
detected issues according to severity. The project also provides security
scoring and report generation in HTML and JSON formats.

---

## 📌 Table of Contents

- [About the Project](#-about-the-project)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Usage](#-usage)
- [Auditing Modules](#-auditing-modules)
- [Core Architecture](#-core-architecture)
- [Reports](#-reports)
- [Testing & Security](#-testing--security)
- [Author & Project Information](#-author--project-information)

---

# 🔎 About the Project

LinuxSentinel is developed as a modular Linux security auditing
framework for examining the security posture of a Linux system.

The tool focuses on different areas of system security such as:

- File permissions
- SUID/SGID binaries
- User accounts
- Running services
- Network configuration
- Firewall configuration
- SSH configuration
- Cron jobs
- System configuration

The audit results can be classified by severity and used to identify
areas that require further security review or hardening.

---

# 🚀 Features

### 🔐 Security Auditing

- File Permission Audit
- SUID/SGID File Audit
- User Account Audit
- Service Audit
- Network Audit
- Firewall Audit
- SSH Security Audit
- Cron Job Audit
- System Configuration Audit

### 📊 Security Analysis

- Severity classification
- Security findings
- Security score calculation
- Modular audit architecture

### 📄 Report Generation

- HTML security reports
- JSON security reports
- Structured audit results

### 🧩 Modular Design

Each security area is implemented as an independent auditor module,
making the project easier to maintain and extend.

---

# 📁 Project Structure

```text
LinuxSentinel/
│
├── main.py
├── cli.py
├── config.py
├── requirements.txt
├── pyproject.toml
├── README.md
│
├── auditors/
│   ├── __init__.py
│   ├── permissions.py
│   ├── suid_sgid.py
│   ├── users.py
│   ├── services.py
│   ├── network.py
│   ├── firewall.py
│   ├── ssh.py
│   ├── cron.py
│   └── system.py
│
├── core/
│   ├── __init__.py
│   ├── scanner.py
│   ├── severity.py
│   ├── scoring.py
│   └── models.py
│
├── reports/
│   ├── __init__.py
│   ├── html_report.py
│   ├── json_report.py
│   └── templates/
│       └── report.html
│
├── utils/
│   ├── __init__.py
│   ├── command.py
│   ├── logger.py
│   └── permissions.py
│
└── tests/
    └── ...
