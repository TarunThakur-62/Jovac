import os
import stat
import pwd
import grp
import json
from datetime import datetime


# ============================================================
# LinuxSentinel - File Permission Security Auditor
# ============================================================

BACKUP_DIR = "/var/backups/linuxsentinel/permissions"

SENSITIVE_FILES = {
    "/etc/passwd": 0o644,
    "/etc/group": 0o644,
    "/etc/shadow": 0o640,
    "/etc/gshadow": 0o640,
    "/etc/sudoers": 0o440,
    "/etc/ssh/sshd_config": 0o600,
}

# Runtime/system directories that MUST NOT be blindly modified.
PROTECTED_DIRECTORIES = {
    "/tmp",
    "/var/tmp",
    "/run",
    "/dev",
    "/proc",
    "/sys",
    "/sys/fs",
}

PROTECTED_PREFIXES = (
    "/tmp/.X11-unix",
    "/tmp/.XIM-unix",
    "/tmp/.ICE-unix",
    "/tmp/.font-unix",
    "/tmp/systemd-private-",
    "/var/tmp/systemd-private-",
    "/run/systemd/",
)


# ============================================================
# Utility functions
# ============================================================

def ensure_backup_dir():
    try:
        os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
        return True
    except PermissionError:
        print("[!] Cannot create backup directory.")
        print("[!] Run remediation with sudo.")
        return False


def get_file_mode(path):
    try:
        return stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode)
    except (FileNotFoundError, PermissionError, OSError):
        return None


def get_permissions(path):
    mode = get_file_mode(path)

    if mode is None:
        return "N/A"

    return stat.filemode(mode)


def get_owner_group(path):
    try:
        st = os.stat(path, follow_symlinks=False)

        owner = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name

        return owner, group

    except (FileNotFoundError, PermissionError, KeyError, OSError):
        return "unknown", "unknown"


def is_protected_path(path):
    path = os.path.abspath(path)

    if path in PROTECTED_DIRECTORIES:
        return True

    for prefix in PROTECTED_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return True

    return False


def backup_metadata(path, old_mode):
    if not ensure_backup_dir():
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    safe_name = path.strip("/").replace("/", "_")
    backup_file = os.path.join(
        BACKUP_DIR,
        f"{safe_name}_{timestamp}.json"
    )

    owner, group = get_owner_group(path)

    data = {
        "path": path,
        "old_mode": oct(old_mode),
        "permissions": stat.filemode(old_mode),
        "owner": owner,
        "group": group,
        "timestamp": timestamp,
        "note": "LinuxSentinel permission remediation backup"
    }

    try:
        with open(backup_file, "w") as f:
            json.dump(data, f, indent=4)

        os.chmod(backup_file, 0o600)

        return backup_file

    except (PermissionError, OSError) as e:
        print(f"[!] Backup failed for {path}: {e}")
        return None


# ============================================================
# Sensitive system files
# ============================================================

def audit_sensitive_files(findings, auto_fix=False):

    print()
    print("## SENSITIVE SYSTEM FILES")
    print("-" * 90)

    print(
        f"{'FILE':<32}"
        f"{'PERMISSIONS':<16}"
        f"{'OWNER':<12}"
        f"{'GROUP':<12}"
        f"STATUS"
    )

    print("-" * 90)

    for path, recommended_mode in SENSITIVE_FILES.items():

        mode = get_file_mode(path)

        if mode is None:
            print(f"{path:<32}{'N/A':<16}{'unknown':<12}{'unknown':<12}MISSING")
            continue

        owner, group = get_owner_group(path)
        permissions = stat.filemode(mode)

        status = "OK"

        # Special handling for sensitive files.
        if mode != recommended_mode:

            severity = "HIGH"

            findings.append({
                "type": "sensitive_file_permission",
                "path": path,
                "current_mode": oct(mode),
                "recommended_mode": oct(recommended_mode),
                "severity": severity
            })

            status = "HIGH"

            if auto_fix:

                backup = backup_metadata(path, mode)

                if backup:

                    try:
                        os.chmod(path, recommended_mode)

                        new_mode = get_file_mode(path)

                        if new_mode == recommended_mode:

                            print(
                                f"[FIXED] {path} "
                                f"{oct(mode)} -> {oct(recommended_mode)}"
                            )

                            status = "FIXED"

                    except PermissionError:
                        print(f"[ERROR] Permission denied: {path}")

                    except OSError as e:
                        print(f"[ERROR] chmod failed for {path}: {e}")

        print(
            f"{path:<32}"
            f"{stat.filemode(get_file_mode(path)):<16}"
            f"{owner:<12}"
            f"{group:<12}"
            f"{status}"
        )


# ============================================================
# World writable files
# ============================================================

def scan_world_writable_files(findings, auto_fix=False):

    print()
    print("## WORLD-WRITABLE FILES")
    print("-" * 90)

    roots = [
        "/home",
        "/tmp",
        "/var/tmp"
    ]

    count = 0

    for root in roots:

        if not os.path.exists(root):
            continue

        for current_root, dirs, files in os.walk(
            root,
            topdown=True,
            followlinks=False
        ):

            # Never recursively inspect protected runtime trees.
            dirs[:] = [
                d for d in dirs
                if not is_protected_path(
                    os.path.join(current_root, d)
                )
            ]

            for filename in files:

                path = os.path.join(current_root, filename)

                try:
                    st = os.stat(path, follow_symlinks=False)
                    mode = stat.S_IMODE(st.st_mode)

                except (PermissionError, FileNotFoundError, OSError):
                    continue

                if not stat.S_ISREG(st.st_mode):
                    continue

                # Other/world write bit.
                if mode & stat.S_IWOTH:

                    count += 1

                    findings.append({
                        "type": "world_writable_file",
                        "path": path,
                        "current_mode": oct(mode),
                        "severity": "HIGH"
                    })

                    print(
                        f"[HIGH] {path:<60}"
                        f"{stat.filemode(mode)}"
                    )

                    if auto_fix:

                        backup = backup_metadata(path, mode)

                        if backup:

                            # Remove only WORLD write.
                            new_mode = mode & ~stat.S_IWOTH

                            try:
                                os.chmod(path, new_mode)

                                verify = get_file_mode(path)

                                if verify is not None and not (
                                    verify & stat.S_IWOTH
                                ):
                                    print(
                                        f"[FIXED] {path} "
                                        f"{oct(mode)} -> {oct(new_mode)}"
                                    )

                            except PermissionError:
                                print(
                                    f"[ERROR] Permission denied: {path}"
                                )

                            except OSError as e:
                                print(
                                    f"[ERROR] chmod failed: {path}: {e}"
                                )

    return count


# ============================================================
# World writable directories
# ============================================================

def scan_world_writable_directories(findings, auto_fix=False):

    print()
    print("## WORLD-WRITABLE DIRECTORIES")
    print("-" * 90)

    roots = [
        "/home",
        "/tmp",
        "/var/tmp"
    ]

    count = 0

    for root in roots:

        if not os.path.exists(root):
            continue

        for current_root, dirs, files in os.walk(
            root,
            topdown=True,
            followlinks=False
        ):

            # Protect runtime/system trees.
            safe_dirs = []

            for dirname in dirs:

                path = os.path.join(current_root, dirname)

                if is_protected_path(path):
                    continue

                safe_dirs.append(dirname)

            dirs[:] = safe_dirs

            for dirname in dirs:

                path = os.path.join(current_root, dirname)

                try:
                    st = os.stat(path, follow_symlinks=False)
                    mode = stat.S_IMODE(st.st_mode)

                except (PermissionError, FileNotFoundError, OSError):
                    continue

                if not stat.S_ISDIR(st.st_mode):
                    continue

                if mode & stat.S_IWOTH:

                    count += 1

                    # Sticky directories are normally intentional.
                    if mode & stat.S_ISVTX:

                        print(
                            f"[INFO] {path:<60}"
                            f"{stat.filemode(mode)} "
                            f"(sticky-bit protected)"
                        )

                        continue

                    findings.append({
                        "type": "world_writable_directory",
                        "path": path,
                        "current_mode": oct(mode),
                        "severity": "HIGH"
                    })

                    print(
                        f"[HIGH] {path:<60}"
                        f"{stat.filemode(mode)}"
                    )

                    if auto_fix:

                        backup = backup_metadata(path, mode)

                        if backup:

                            # Remove world-write only.
                            new_mode = mode & ~stat.S_IWOTH

                            try:
                                os.chmod(path, new_mode)

                                verify = get_file_mode(path)

                                if verify is not None and not (
                                    verify & stat.S_IWOTH
                                ):
                                    print(
                                        f"[FIXED] {path} "
                                        f"{oct(mode)} -> {oct(new_mode)}"
                                    )

                            except PermissionError:
                                print(
                                    f"[ERROR] Permission denied: {path}"
                                )

                            except OSError as e:
                                print(
                                    f"[ERROR] chmod failed: {path}: {e}"
                                )

    return count


# ============================================================
# Audit entry point
# ============================================================

def audit_permissions(auto_fix=False):

    findings = []

    print()
    print("=" * 90)
    print("[*] Linux File Permission Security Audit")
    print("=" * 90)

    if auto_fix:

        print()
        print("[!] AUTOMATIC REMEDIATION MODE ENABLED")
        print("[*] Only safe permission changes will be attempted.")
        print("[*] Original metadata will be backed up.")
        print("[*] Runtime/system directories are protected.")

    else:

        print()
        print("[*] Audit mode: NO permissions will be modified.")

    # --------------------------------------------------------
    # Sensitive files
    # --------------------------------------------------------

    audit_sensitive_files(
        findings,
        auto_fix=auto_fix
    )

    # --------------------------------------------------------
    # World writable directories
    # --------------------------------------------------------

    scan_world_writable_directories(
        findings,
        auto_fix=auto_fix
    )

    # --------------------------------------------------------
    # World writable files
    # --------------------------------------------------------

    scan_world_writable_files(
        findings,
        auto_fix=auto_fix
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    critical = sum(
        1 for f in findings
        if f.get("severity") == "CRITICAL"
    )

    high = sum(
        1 for f in findings
        if f.get("severity") == "HIGH"
    )

    medium = sum(
        1 for f in findings
        if f.get("severity") == "MEDIUM"
    )

    low = sum(
        1 for f in findings
        if f.get("severity") == "LOW"
    )

    print()
    print("=" * 90)
    print("SECURITY SUMMARY")
    print("=" * 90)

    print(f"Security findings      : {len(findings)}")
    print(f"CRITICAL findings     : {critical}")
    print(f"HIGH findings         : {high}")
    print(f"MEDIUM findings       : {medium}")
    print(f"LOW findings          : {low}")

    print()

    if auto_fix:
        print("[+] Automatic remediation completed where safe.")
        print(f"[*] Backup directory: {BACKUP_DIR}")

    if critical or high:
        print("[!] HIGH/CRITICAL permission issues remain.")
        print("[!] Review the findings before changing application permissions.")
    else:
        print("[+] No high-risk permission issues detected.")

    print()
    print("[+] File permission security audit completed.")

    # IMPORTANT:
    # Always return findings so the full audit does not get
    # "'NoneType' object is not iterable".
    return findings


# ============================================================
# Standalone execution
# ============================================================

if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(
        description="LinuxSentinel File Permission Security Auditor"
    )

    parser.add_argument(
        "--auto-fix",
        action="store_true",
        help="Safely remediate supported permission issues"
    )

    args = parser.parse_args()

    audit_permissions(
        auto_fix=args.auto_fix
    )

