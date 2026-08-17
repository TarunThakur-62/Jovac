import os
import re
import subprocess


SSH_CONFIG = "/etc/ssh/sshd_config"


def read_ssh_config():
    try:
        with open(SSH_CONFIG, "r") as f:
            return f.readlines()

    except PermissionError:
        print("[ERROR] Permission denied reading SSH configuration.")
        print("[INFO] SSH audit requires root privileges.")
        print("[INFO] Run LinuxSentinel using sudo.")
        return None

    except FileNotFoundError:
        print(f"[ERROR] SSH configuration not found: {SSH_CONFIG}")
        return None

    except OSError as e:
        print(f"[ERROR] Cannot read SSH configuration: {e}")
        return None


def get_effective_ssh_config():

    try:
        result = subprocess.run(
            ["sshd", "-T"],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            return {}

        config = {}

        for line in result.stdout.splitlines():

            parts = line.split(None, 1)

            if len(parts) == 2:
                config[parts[0].lower()] = parts[1].strip()

        return config

    except FileNotFoundError:
        print("[WARN] sshd command not found.")
        return {}

    except Exception as e:
        print(f"[WARN] Unable to read effective SSH configuration: {e}")
        return {}


def check_setting(config, name, secure_values):

    value = config.get(name.lower())

    if value is None:
        return None

    return value.lower() in secure_values


def audit_ssh():

    print()
    print("[*] LinuxSentinel SSH Security Audit")
    print("=" * 72)

    # --------------------------------------------------------
    # Root privilege check
    # --------------------------------------------------------

    if os.geteuid() != 0:

        print()
        print("[WARN] LinuxSentinel is running without root privileges.")
        print("[INFO] Some SSH security checks require root access.")
        print("[INFO] Re-run with:")
        print()
        print("       sudo python3 cli.py")
        print()

    # --------------------------------------------------------
    # Read configuration
    # --------------------------------------------------------

    lines = read_ssh_config()

    if lines is None:

        print()
        print("[!] SSH audit could not access sshd_config.")
        print("[!] No SSH configuration was modified.")
        return []

    findings = []

    # --------------------------------------------------------
    # Parse active configuration
    # --------------------------------------------------------

    config = {}

    for line in lines:

        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        parts = line.split(None, 1)

        if len(parts) == 2:

            key = parts[0].lower()
            value = parts[1].strip()

            config[key] = value

    # --------------------------------------------------------
    # SSH Protocol
    # --------------------------------------------------------

    protocol = config.get("protocol", "2")

    print()
    print("[*] SSH Protocol")
    print("-" * 72)

    if protocol == "1":

        print("[CRITICAL] SSH Protocol 1 is enabled.")

        findings.append({
            "type": "ssh_protocol",
            "severity": "CRITICAL",
            "value": protocol,
            "recommendation": "Use SSH Protocol 2"
        })

    else:

        print("[OK] SSH Protocol 2 configuration detected.")

    # --------------------------------------------------------
    # Root Login
    # --------------------------------------------------------

    print()
    print("[*] Root Login")
    print("-" * 72)

    permit_root = config.get(
        "permitrootlogin",
        "prohibit-password"
    ).lower()

    if permit_root == "yes":

        print("[HIGH] PermitRootLogin is enabled.")

        findings.append({
            "type": "root_login",
            "severity": "HIGH",
            "value": permit_root,
            "recommendation": "Set PermitRootLogin no"
        })

    else:

        print(
            f"[OK] PermitRootLogin = {permit_root}"
        )

    # --------------------------------------------------------
    # Password Authentication
    # --------------------------------------------------------

    print()
    print("[*] Password Authentication")
    print("-" * 72)

    password_auth = config.get(
        "passwordauthentication",
        "yes"
    ).lower()

    if password_auth == "yes":

        print("[MEDIUM] Password authentication is enabled.")

        findings.append({
            "type": "password_authentication",
            "severity": "MEDIUM",
            "value": password_auth,
            "recommendation": "Use key-based authentication where appropriate"
        })

    else:

        print("[OK] Password authentication is disabled.")

    # --------------------------------------------------------
    # Empty Passwords
    # --------------------------------------------------------

    print()
    print("[*] Empty Password Login")
    print("-" * 72)

    permit_empty = config.get(
        "permitemptypasswords",
        "no"
    ).lower()

    if permit_empty == "yes":

        print("[CRITICAL] Empty password authentication enabled.")

        findings.append({
            "type": "empty_passwords",
            "severity": "CRITICAL",
            "value": permit_empty,
            "recommendation": "Set PermitEmptyPasswords no"
        })

    else:

        print("[OK] Empty password authentication disabled.")

    # --------------------------------------------------------
    # X11 Forwarding
    # --------------------------------------------------------

    print()
    print("[*] X11 Forwarding")
    print("-" * 72)

    x11 = config.get(
        "x11forwarding",
        "yes"
    ).lower()

    if x11 == "yes":

        print("[LOW] X11 forwarding is enabled.")

        findings.append({
            "type": "x11_forwarding",
            "severity": "LOW",
            "value": x11,
            "recommendation": "Disable if not required"
        })

    else:

        print("[OK] X11 forwarding disabled.")

    # --------------------------------------------------------
    # Max Authentication Attempts
    # --------------------------------------------------------

    print()
    print("[*] Authentication Attempts")
    print("-" * 72)

    try:

        max_auth = int(
            config.get(
                "maxauthtries",
                "6"
            )
        )

        if max_auth > 6:

            print(
                f"[MEDIUM] MaxAuthTries is high: {max_auth}"
            )

            findings.append({
                "type": "max_auth_tries",
                "severity": "MEDIUM",
                "value": max_auth,
                "recommendation": "Consider MaxAuthTries 3 or lower"
            })

        else:

            print(
                f"[OK] MaxAuthTries = {max_auth}"
            )

    except ValueError:

        print("[WARN] Invalid MaxAuthTries value.")

    # --------------------------------------------------------
    # Login Grace Time
    # --------------------------------------------------------

    print()
    print("[*] Login Grace Time")
    print("-" * 72)

    grace = config.get(
        "logingracetime",
        "120"
    )

    print(f"[INFO] LoginGraceTime = {grace}")

    # --------------------------------------------------------
    # Effective sshd configuration
    # --------------------------------------------------------

    print()
    print("[*] Effective SSH Configuration")
    print("-" * 72)

    effective = get_effective_ssh_config()

    if effective:

        important = [
            "permitrootlogin",
            "passwordauthentication",
            "permitemptypasswords",
            "pubkeyauthentication",
            "x11forwarding",
            "maxauthtries",
            "logingracetime"
        ]

        for key in important:

            if key in effective:

                print(
                    f"{key:<25}: "
                    f"{effective[key]}"
                )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print()
    print("=" * 72)
    print("SSH SECURITY SUMMARY")
    print("=" * 72)

    critical = sum(
        1 for x in findings
        if x["severity"] == "CRITICAL"
    )

    high = sum(
        1 for x in findings
        if x["severity"] == "HIGH"
    )

    medium = sum(
        1 for x in findings
        if x["severity"] == "MEDIUM"
    )

    low = sum(
        1 for x in findings
        if x["severity"] == "LOW"
    )

    print(f"Total findings : {len(findings)}")
    print(f"CRITICAL       : {critical}")
    print(f"HIGH           : {high}")
    print(f"MEDIUM         : {medium}")
    print(f"LOW            : {low}")

    if not findings:
        print()
        print("[+] No obvious SSH security issues detected.")

    else:
        print()
        print("[!] SSH security recommendations available.")

    print()
    print("[+] SSH security audit completed.")

    return findings

