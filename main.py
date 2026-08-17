from config import APP_NAME, VERSION
from utils.logger import setup_logger

from auditors.permissions import audit_permissions
from auditors.suid_sgid import audit_suid_sgid


def main():

    logger = setup_logger()

    print("=" * 60)
    print(f"        {APP_NAME} v{VERSION}")
    print("        Linux Security Audit Tool")
    print("=" * 60)

    logger.info("LinuxSentinel started")

    all_findings = []

    # File Permission Audit
    print("\n[*] Starting file permission audit...\n")

    permission_findings = audit_permissions()

    all_findings.extend(permission_findings)

    print("\n[*] Permission audit completed.")
    print(f"[*] Findings detected: {len(permission_findings)}")

    # SUID / SGID Audit
    suid_findings = audit_suid_sgid()

    all_findings.extend(suid_findings)

    # Summary
    print("\n" + "=" * 60)
    print("             AUDIT SUMMARY")
    print("=" * 60)

    print(f"Total findings: {len(all_findings)}")

    print("\n[+] Audit modules completed.")


if __name__ == "__main__":
    main()
