import os
import stat
import pwd
import shutil
import subprocess
from datetime import datetime


CRON_PATHS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False
        )
        return result.stdout.strip()
    except Exception:
        return ""


def file_info(path):
    try:
        st = os.stat(path)

        mode = stat.S_IMODE(st.st_mode)
        owner = pwd.getpwuid(st.st_uid).pw_name

        return {
            "mode": mode,
            "owner": owner,
            "uid": st.st_uid,
            "gid": st.st_gid,
            "world_writable": bool(mode & stat.S_IWOTH),
            "group_writable": bool(mode & stat.S_IWGRP),
        }

    except (FileNotFoundError, PermissionError):
        return None


def collect_cron_files():
    files = []

    for path in CRON_PATHS:

        if not os.path.exists(path):
            continue

        if os.path.isfile(path):
            files.append(path)
            continue

        for root, dirs, filenames in os.walk(path):

            # Avoid following dangerous symlinks
            dirs[:] = [
                d for d in dirs
                if not os.path.islink(os.path.join(root, d))
            ]

            for filename in filenames:

                full_path = os.path.join(root, filename)

                if os.path.islink(full_path):
                    continue

                if os.path.isfile(full_path):
                    files.append(full_path)

    return sorted(set(files))


def check_permissions(path):
    info = file_info(path)

    if not info:
        return None

    findings = []

    if info["world_writable"]:
        findings.append({
            "severity": "HIGH",
            "path": path,
            "issue": "World-writable cron file",
            "recommendation": "Remove write permission for others."
        })

    if info["group_writable"]:
        findings.append({
            "severity": "MEDIUM",
            "path": path,
            "issue": "Group-writable cron file",
            "recommendation": "Verify group ownership and remove unnecessary group write permission."
        })

    if info["owner"] != "root":
        findings.append({
            "severity": "HIGH",
            "path": path,
            "issue": f"Cron file is owned by {info['owner']}",
            "recommendation": "Cron system files should normally be owned by root."
        })

    return findings


def check_missing_targets(path):
    findings = []

    try:
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()

        for number, line in enumerate(lines, 1):

            line = line.strip()

            if not line or line.startswith("#"):
                continue

            parts = line.split()

            # Standard crontab:
            # minute hour day month weekday command
            if path == "/etc/crontab" or "/etc/cron.d/" in path:

                if len(parts) < 7:
                    continue

                command = " ".join(parts[6:])

            else:

                if len(parts) < 6:
                    continue

                command = " ".join(parts[5:])

            # Only perform basic executable/path analysis.
            command_path = command.split()[0]

            if command_path.startswith("/"):
                if not os.path.exists(command_path):

                    findings.append({
                        "severity": "MEDIUM",
                        "path": path,
                        "issue": f"Cron references missing path: {command_path}",
                        "line": number,
                        "recommendation": "Remove or correct obsolete cron entry."
                    })

    except (PermissionError, FileNotFoundError):
        pass

    return findings


def check_service():

    result = run_command(
        ["systemctl", "is-active", "cron"]
    )

    if result == "active":
        return "RUNNING"

    result = run_command(
        ["systemctl", "is-active", "crond"]
    )

    if result == "active":
        return "RUNNING"

    return "NOT RUNNING"


def check_cron_process():

    result = run_command(["pgrep", "-a", "cron"])

    if result:
        return result.splitlines()

    result = run_command(["pgrep", "-a", "crond"])

    if result:
        return result.splitlines()

    return []


def backup_file(path):

    backup_dir = "/var/backups/linuxsentinel/cron"

    try:
        os.makedirs(backup_dir, exist_ok=True)

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        safe_name = path.strip("/").replace("/", "_")

        backup_path = os.path.join(
            backup_dir,
            f"{safe_name}.{timestamp}.bak"
        )

        shutil.copy2(path, backup_path)

        return backup_path

    except Exception as e:
        print(f"[!] Backup failed for {path}: {e}")
        return None


def remediate_permissions(path):

    info = file_info(path)

    if not info:
        return False

    changed = False

    try:

        # Backup BEFORE modification
        backup = backup_file(path)

        if not backup:
            return False

        print(f"[BACKUP] {backup}")

        current_mode = info["mode"]

        # Remove world-write.
        new_mode = current_mode & ~stat.S_IWOTH

        # Remove group-write for system cron files.
        new_mode = new_mode & ~stat.S_IWGRP

        if new_mode != current_mode:

            os.chmod(path, new_mode)

            print(
                f"[FIXED] Permissions: {path} "
                f"{oct(current_mode)} -> {oct(new_mode)}"
            )

            changed = True

        # System cron files should normally belong to root.
        if info["uid"] == 0:
            return changed

        try:
            os.chown(path, 0, info["gid"])

            print(
                f"[FIXED] Ownership: {path} -> root"
            )

            changed = True

        except PermissionError:
            print(
                f"[!] Cannot change ownership: {path}"
            )

    except PermissionError:
        print(
            f"[!] Permission denied modifying {path}"
        )

    except Exception as e:
        print(
            f"[!] Remediation error for {path}: {e}"
        )

    return changed


def verify_permissions(path):

    info = file_info(path)

    if not info:
        return False

    if info["world_writable"]:
        return False

    if info["group_writable"]:
        return False

    return True


def remediation(findings):

    if not findings:
        print("\n[+] No automatic remediation required.")
        return

    print("\n" + "=" * 72)
    print("CONTROLLED CRON REMEDIATION")
    print("=" * 72)

    risky_files = sorted(
        set(
            finding["path"]
            for finding in findings
            if finding["issue"] in [
                "World-writable cron file"
            ]
            or finding["issue"].startswith(
                "Cron file is owned by"
            )
        )
    )

    if not risky_files:
        print(
            "[INFO] Findings require manual review."
        )
        return

    print(
        f"\n[!] {len(risky_files)} cron file(s) "
        "can be automatically hardened."
    )

    print("\nFiles:")

    for path in risky_files:
        print(f"  - {path}")

    print(
        "\n[WARNING] LinuxSentinel will:"
        "\n  1. Create a backup"
        "\n  2. Remove group/world write permissions"
        "\n  3. Correct ownership to root when possible"
        "\n  4. Verify the resulting permissions"
    )

    answer = input(
        "\nApply remediation? [y/N]: "
    ).strip().lower()

    if answer != "y":
        print("\n[INFO] Remediation cancelled.")
        return

    print("\n[*] Starting controlled remediation...")

    fixed = 0

    for path in risky_files:

        if remediate_permissions(path):

            if verify_permissions(path):

                print(
                    f"[VERIFIED] {path}"
                )

                fixed += 1

            else:

                print(
                    f"[WARNING] Verification failed: {path}"
                )

    print("\n" + "-" * 72)
    print(
        f"[+] Remediation completed: "
        f"{fixed}/{len(risky_files)}"
    )


def audit_cron(auto_fix=False):

    print("\n[*] LinuxSentinel Cron Security Audit")
    print("=" * 72)

    print("\n[1] CRON SERVICE STATUS")
    print("-" * 72)

    service_status = check_service()

    if service_status == "RUNNING":
        print("[+] Cron service is running")
    else:
        print("[MEDIUM] Cron service is not running")

    print("\n[2] CRON PROCESS")
    print("-" * 72)

    processes = check_cron_process()

    if processes:

        for process in processes:
            print(f"[PROCESS] {process}")

    else:
        print("[INFO] No cron process detected.")

    print("\n[3] CRON FILE INVENTORY")
    print("-" * 72)

    cron_files = collect_cron_files()

    print(
        f"[INFO] Cron files/directories discovered: "
        f"{len(cron_files)}"
    )

    findings = []

    for path in cron_files:

        info = file_info(path)

        if not info:
            continue

        print(
            f"{oct(info['mode']):<8} "
            f"{info['owner']:<12} "
            f"{path}"
        )

        permission_findings = check_permissions(path)

        if permission_findings:
            findings.extend(permission_findings)

        findings.extend(
            check_missing_targets(path)
        )

    print("\n[4] SECURITY FINDINGS")
    print("-" * 72)

    if not findings:

        print(
            "[+] No obvious cron security weaknesses detected."
        )

    else:

        for finding in findings:

            severity = finding["severity"]

            print(
                f"\n[{severity}] "
                f"{finding['issue']}"
            )

            print(
                f"Path          : "
                f"{finding['path']}"
            )

            if "line" in finding:
                print(
                    f"Line          : "
                    f"{finding['line']}"
                )

            print(
                f"Recommendation: "
                f"{finding['recommendation']}"
            )

    high = sum(
        1 for f in findings
        if f["severity"] == "HIGH"
    )

    medium = sum(
        1 for f in findings
        if f["severity"] == "MEDIUM"
    )

    low = sum(
        1 for f in findings
        if f["severity"] == "LOW"
    )

    print("\n[5] AUDIT SUMMARY")
    print("-" * 72)

    print(f"Cron files scanned : {len(cron_files)}")
    print(f"Security findings  : {len(findings)}")
    print(f"HIGH               : {high}")
    print(f"MEDIUM             : {medium}")
    print(f"LOW                : {low}")

    if high:
        print(
            "\n[CRITICAL] High-risk cron configuration detected."
        )

    elif medium:
        print(
            "\n[WARNING] Cron configuration requires review."
        )

    else:
        print(
            "\n[+] Cron configuration looks reasonable."
        )

    if auto_fix:
        remediation(findings)

    print(
        "\n[+] Cron security audit completed."
    )
