import os
import stat
import shutil
from datetime import datetime

BACKUP_ROOT = "/var/backups/linuxsentinel/permissions"

SAFE_TEMP_DIRS = {
    "/tmp",
    "/var/tmp",
    "/dev/shm",
}


def backup_file(path):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(BACKUP_ROOT, timestamp)

    os.makedirs(backup_dir, exist_ok=True)

    safe_name = path.strip("/").replace("/", "_")
    backup_path = os.path.join(backup_dir, safe_name)

    try:
        shutil.copy2(path, backup_path)
        return backup_path
    except Exception as e:
        print(f"[!] Backup failed: {path} -> {e}")
        return None


def remove_world_write_file(path):
    try:
        st = os.stat(path)
        old_mode = stat.S_IMODE(st.st_mode)

        # Remove group-write and other-write permissions.
        new_mode = old_mode & ~0o022

        if old_mode == new_mode:
            return False

        backup = backup_file(path)

        if not backup:
            return False

        os.chmod(path, new_mode)

        verified = stat.S_IMODE(os.stat(path).st_mode) == new_mode

        if verified:
            print(
                f"[FIXED] {path}: "
                f"{oct(old_mode)} -> {oct(new_mode)}"
            )
            print(f"        Backup: {backup}")
            return True

        print(f"[!] Verification failed: {path}")
        return False

    except PermissionError:
        print(f"[!] Permission denied: {path}")
        return False

    except Exception as e:
        print(f"[!] Could not fix {path}: {e}")
        return False


def remove_world_write_directory(path):
    if path in SAFE_TEMP_DIRS:
        print(f"[SKIP] Standard temporary directory: {path}")
        return False

    try:
        st = os.stat(path)
        old_mode = stat.S_IMODE(st.st_mode)

        # Preserve sticky bit while removing group/other write.
        new_mode = old_mode & ~0o022

        if old_mode == new_mode:
            return False

        backup = backup_file(path)

        if not backup:
            return False

        os.chmod(path, new_mode)

        verified = stat.S_IMODE(os.stat(path).st_mode) == new_mode

        if verified:
            print(
                f"[FIXED] {path}: "
                f"{oct(old_mode)} -> {oct(new_mode)}"
            )
            print(f"        Backup: {backup}")
            return True

        print(f"[!] Verification failed: {path}")
        return False

    except PermissionError:
        print(f"[!] Permission denied: {path}")
        return False

    except Exception as e:
        print(f"[!] Could not fix {path}: {e}")
        return False


def remediate_permissions(findings):
    print()
    print("=" * 72)
    print("LINUX SENTINEL - PERMISSION REMEDIATION")
    print("=" * 72)

    fixed = 0
    skipped = 0
    failed = 0

    for finding in findings:

        path = finding.get("path")
        finding_type = finding.get("type")

        if not path:
            continue

        if finding_type == "world_writable_file":
            if remove_world_write_file(path):
                fixed += 1
            else:
                failed += 1

        elif finding_type == "world_writable_directory":
            if path in SAFE_TEMP_DIRS:
                skipped += 1
                continue

            if remove_world_write_directory(path):
                fixed += 1
            else:
                failed += 1

        else:
            skipped += 1

    print()
    print("-" * 72)
    print(f"Fixed findings     : {fixed}")
    print(f"Skipped findings   : {skipped}")
    print(f"Failed remediation : {failed}")
    print("-" * 72)

    return {
        "fixed": fixed,
        "skipped": skipped,
        "failed": failed
    }
