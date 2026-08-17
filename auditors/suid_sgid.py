import os

from core.models import Finding


def find_files_by_permission(permission):

    results = []

    for root, dirs, files in os.walk("/"):
        dirs[:] = [
            d for d in dirs
            if d not in {"proc", "sys", "dev", "run"}
        ]

        for filename in files:

            filepath = os.path.join(root, filename)

            try:
                mode = os.stat(filepath).st_mode

                if mode & permission:
                    results.append(filepath)

            except (PermissionError, FileNotFoundError, OSError):
                continue

    return results


def audit_suid_sgid():

    findings = []

    print("\n[*] Starting SUID/SGID audit...")

    suid_files = find_files_by_permission(0o4000)
    sgid_files = find_files_by_permission(0o2000)

    print(f"\n    SUID files found: {len(suid_files)}")
    print(f"    SGID files found: {len(sgid_files)}")

    print("\n    SUID files:")

    for file in suid_files:
        print(f"      [SUID] {file}")

    print("\n    SGID files:")

    for file in sgid_files:
        print(f"      [SGID] {file}")

    findings.append(
        Finding(
            category="SUID/SGID",
            title="SUID/SGID files detected",
            severity="INFO",
            description=(
                f"Found {len(suid_files)} SUID files and "
                f"{len(sgid_files)} SGID files."
            ),
            recommendation=(
                "Review SUID/SGID binaries and remove "
                "unnecessary special permissions."
            )
        )
    )

    return findings
