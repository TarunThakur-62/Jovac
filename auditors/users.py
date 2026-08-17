import os
import pwd
import grp
import subprocess
import stat


def get_permissions(path):
    try:
        mode = os.stat(path).st_mode
        return oct(stat.S_IMODE(mode))
    except (FileNotFoundError, PermissionError):
        return "N/A"


def get_users():
    users = []

    try:
        for entry in pwd.getpwall():
            users.append({
                "username": entry.pw_name,
                "uid": entry.pw_uid,
                "gid": entry.pw_gid,
                "home": entry.pw_dir,
                "shell": entry.pw_shell
            })
    except Exception as e:
        print(f"[!] Unable to read user database: {e}")

    return users


def check_root_accounts(users):
    root_accounts = []

    for user in users:
        if user["uid"] == 0:
            root_accounts.append(user["username"])

    return root_accounts


def check_login_accounts(users):
    login_shells = [
        "/bin/bash",
        "/bin/sh",
        "/bin/zsh",
        "/bin/fish",
        "/usr/bin/bash",
        "/usr/bin/zsh",
        "/usr/bin/fish"
    ]

    accounts = []

    for user in users:
        if user["shell"] in login_shells:
            accounts.append(user)

    return accounts


def check_duplicate_uids(users):
    uid_map = {}

    for user in users:
        uid = user["uid"]

        if uid not in uid_map:
            uid_map[uid] = []

        uid_map[uid].append(user["username"])

    duplicates = {
        uid: names
        for uid, names in uid_map.items()
        if len(names) > 1
    }

    return duplicates


def check_empty_passwords():
    empty_passwords = []

    try:
        with open("/etc/shadow", "r") as shadow:

            for line in shadow:

                if not line.strip():
                    continue

                parts = line.split(":")

                if len(parts) > 1 and parts[1] == "":
                    empty_passwords.append(parts[0])

    except PermissionError:
        print("[!] Permission denied reading /etc/shadow")
        print("[*] Run LinuxSentinel with sudo for complete results.")

    except FileNotFoundError:
        print("[!] /etc/shadow not found")

    return empty_passwords


def check_locked_accounts():
    locked = []

    try:
        result = subprocess.run(
            ["passwd", "-Sa"],
            capture_output=True,
            text=True,
            check=False
        )

        for line in result.stdout.splitlines():

            parts = line.split()

            if len(parts) >= 2 and parts[1] == "L":
                locked.append(parts[0])

    except Exception:
        pass

    return locked


def audit_users():

    print()
    print("[*] Collecting Linux user account information...")
    print()

    users = get_users()

    if not users:
        print("[!] No user accounts found.")
        return

    print("-" * 72)
    print("USER ACCOUNTS")
    print("-" * 72)

    print(
        f"{'USERNAME':<20}"
        f"{'UID':<8}"
        f"{'GID':<8}"
        f"{'SHELL'}"
    )

    print("-" * 72)

    for user in users:

        print(
            f"{user['username']:<20}"
            f"{user['uid']:<8}"
            f"{user['gid']:<8}"
            f"{user['shell']}"
        )

    # --------------------------------------------------------
    # Root accounts
    # --------------------------------------------------------

    print()
    print("-" * 72)
    print("UID 0 ACCOUNTS")
    print("-" * 72)

    root_accounts = check_root_accounts(users)

    for username in root_accounts:
        print(f"[!] UID 0 account: {username}")

    if len(root_accounts) == 1:
        print("[+] Only the root account has UID 0.")

    # --------------------------------------------------------
    # Login accounts
    # --------------------------------------------------------

    print()
    print("-" * 72)
    print("ACCOUNTS WITH LOGIN SHELL")
    print("-" * 72)

    login_accounts = check_login_accounts(users)

    for user in login_accounts:
        print(
            f"[LOGIN] {user['username']}"
            f" -> {user['shell']}"
        )

    # --------------------------------------------------------
    # Duplicate UID
    # --------------------------------------------------------

    print()
    print("-" * 72)
    print("DUPLICATE UID CHECK")
    print("-" * 72)

    duplicate_uids = check_duplicate_uids(users)

    if duplicate_uids:

        for uid, names in duplicate_uids.items():
            print(
                f"[HIGH] UID {uid} is assigned to: "
                f"{', '.join(names)}"
            )

    else:
        print("[+] No duplicate UIDs detected.")

    # --------------------------------------------------------
    # Empty passwords
    # --------------------------------------------------------

    print()
    print("-" * 72)
    print("EMPTY PASSWORD CHECK")
    print("-" * 72)

    empty_passwords = check_empty_passwords()

    if empty_passwords:

        for username in empty_passwords:
            print(f"[CRITICAL] Empty password: {username}")

    else:
        print("[+] No empty-password accounts detected.")

    # --------------------------------------------------------
    # Locked accounts
    # --------------------------------------------------------

    print()
    print("-" * 72)
    print("LOCKED ACCOUNTS")
    print("-" * 72)

    locked_accounts = check_locked_accounts()

    if locked_accounts:

        for username in locked_accounts:
            print(f"[LOCKED] {username}")

    else:
        print("[INFO] No locked accounts detected.")

    # --------------------------------------------------------
    # Important file permissions
    # --------------------------------------------------------

    print()
    print("-" * 72)
    print("ACCOUNT DATABASE PERMISSIONS")
    print("-" * 72)

    passwd_perm = get_permissions("/etc/passwd")
    shadow_perm = get_permissions("/etc/shadow")
    group_perm = get_permissions("/etc/group")

    print(f"/etc/passwd    {passwd_perm}")
    print(f"/etc/shadow    {shadow_perm}")
    print(f"/etc/group     {group_perm}")

    print()
    print("[+] User Account Audit completed.")
