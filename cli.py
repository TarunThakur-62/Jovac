import argparse
import os
import shutil
import subprocess
import sys

from config import APP_NAME, VERSION


# ============================================================
# Banner
# ============================================================

def show_banner():
    os.system("clear")

    width = 70

    print("\033[1;36m")
    print("╔" + "═" * width + "╗")
    print("║" + " " * width + "║")

    title = "LINUX SENTINEL"
    left = (width - len(title)) // 2

    print(
        "║"
        + " " * left
        + "\033[1;37m" + title + "\033[1;36m"
        + " " * (width - left - len(title))
        + "║"
    )

    subtitle = "Linux Security Audit Tool"
    left = (width - len(subtitle)) // 2

    print(
        "║"
        + " " * left
        + "\033[1;33m" + subtitle + "\033[1;36m"
        + " " * (width - left - len(subtitle))
        + "║"
    )

    author = "by Tarun Thakur"

    print(
        "║"
        + " " * (width - len(author) - 3)
        + "\033[1;32m" + author + "\033[1;36m"
        + "   ║"
    )

    print("║" + " " * width + "║")
    print("╚" + "═" * width + "╝")
    print("\033[0m")

    print(f"Version: {VERSION}")
    print("=" * 72)


# ============================================================
# Utility
# ============================================================

def pause():
    input("\nPress ENTER to return to menu...")


# ============================================================
# Menu
# ============================================================

def menu():

    while True:

        show_banner()

        print("""
Select Security Audit

 [1] Full Security Audit
 [2] File Permissions
 [3] SUID / SGID
 [4] User Accounts
 [5] Running Services
 [6] Network Security
 [7] Firewall
 [8] SSH Security
 [9] Cron Jobs
 [10] System Security

 [0] Exit
""")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            full_audit()

        elif choice == "2":
            permission_audit()

        elif choice == "3":
            suid_sgid_audit()

        elif choice == "4":
            user_audit()

        elif choice == "5":
            service_audit()

        elif choice == "6":
            network_audit()

        elif choice == "7":
            firewall_audit()

        elif choice == "8":
            ssh_audit()

        elif choice == "9":
            cron_audit()

        elif choice == "10":
            system_audit()

        elif choice == "0":
            print("\nExiting LinuxSentinel...")
            break

        else:
            print("\n[!] Invalid choice")
            pause()


# ============================================================
# Full Audit
# ============================================================

def full_audit():

    show_banner()

    print("[INFO] Starting Full Security Audit")
    print("=" * 72)

    try:
        from main import main
        main()

    except Exception as e:
        print(f"\n[!] Full audit error: {e}")

    pause()


# ============================================================
# File Permissions
# ============================================================

def permission_audit():

    show_banner()

    print("[*] Starting File Permission Audit...")
    print("=" * 72)

    try:
        from auditors.permissions import audit_permissions
        audit_permissions()

    except Exception as e:
        print(f"\n[!] Permission audit error: {e}")

    pause()


# ============================================================
# SUID / SGID
# ============================================================

def suid_sgid_audit():

    show_banner()

    print("[*] Starting SUID / SGID Audit...")
    print("=" * 72)

    try:
        from auditors.suid_sgid import audit_suid_sgid
        audit_suid_sgid()

    except Exception as e:
        print(f"\n[!] SUID/SGID audit error: {e}")

    pause()


# ============================================================
# Future Modules
# ============================================================

def module_not_ready(name):

    show_banner()

    print(f"[*] {name}")
    print("=" * 72)
    print()
    print("[!] This audit module is not implemented yet.")
    print("[*] Module will be added in the next development stage.")

    pause()


def user_audit():
    show_banner()

    print("[*] User Account Audit")
    print("=" * 72)

    try:
        from auditors.users import audit_users
        audit_users()

    except Exception as e:
        print(f"\n[!] User account audit error: {e}")

    pause()

def service_audit():
    show_banner()

    print("[*] Running Service Audit")
    print("=" * 72)

    try:
        from auditors.services import audit_services
        audit_services()

    except Exception as e:
        print(f"\n[!] Service audit error: {e}")

    pause()


def network_audit():
    show_banner()

    print("[*] Network Security Audit")
    print("=" * 72)

    try:
        from auditors.network import audit_network
        audit_network()

    except Exception as e:
        print(f"\n[!] Network audit error: {e}")

    pause()


def firewall_audit():
    show_banner()

    print("[*] Firewall Security Audit")
    print("=" * 72)

    try:
        from auditors.firewall import audit_firewall
        audit_firewall()

    except Exception as e:
        print(f"\n[!] Firewall audit error: {e}")

    pause()
def ssh_audit():
    show_banner()

    print("[*] SSH Security Audit")
    print("=" * 72)

    try:
        from auditors.ssh import audit_ssh
        audit_ssh()

    except Exception as e:
        print(f"\n[!] SSH audit error: {e}")

    pause()

def cron_audit():
    show_banner()

    print("[*] Cron Security Audit")
    print("=" * 72)

    try:
        from auditors.cron import audit_cron

        audit_cron(auto_fix=True)

    except Exception as e:
        print(f"\n[!] Cron audit error: {e}")

    pause()

def system_audit():
    show_banner()

    print("[*] System Security Audit")
    print("=" * 72)

    try:
        from auditors.system import audit_system
        audit_system()

    except Exception as e:
        print(f"\n[!] System audit error: {e}")

    pause()

# ============================================================
# Open New Terminal
# ============================================================

def open_scan_terminal():

    env = os.environ.copy()

    # Tell child process to directly open menu
    env["LINUXSENTINEL_CHILD"] = "1"

    script = os.path.abspath(__file__)

    terminals = [

        # QTerminal - common on Kali
        (
            "qterminal",
            [
                "qterminal",
                "--title",
                "LinuxSentinel Security Audit",
                "-e",
                sys.executable,
                script,
                "scan"
            ]
        ),

        # XFCE Terminal
        (
            "xfce4-terminal",
            [
                "xfce4-terminal",
                "--title=LinuxSentinel Security Audit",
                "--maximize",
                "--",
                sys.executable,
                script,
                "scan"
            ]
        ),

        # GNOME Terminal
        (
            "gnome-terminal",
            [
                "gnome-terminal",
                "--title=LinuxSentinel Security Audit",
                "--",
                sys.executable,
                script,
                "scan"
            ]
        ),

        # KDE Konsole
        (
            "konsole",
            [
                "konsole",
                "--new-tab",
                "-e",
                sys.executable,
                script,
                "scan"
            ]
        ),
    ]

    for terminal_name, command in terminals:

        if shutil.which(terminal_name):

            print(f"[+] Opening {terminal_name}...")
            subprocess.Popen(command, env=env)

            return

    # No terminal found
    print("[!] No supported terminal emulator found.")
    print("[*] Starting LinuxSentinel in current terminal...")

    menu()


# ============================================================
# CLI
# ============================================================

def cli():

    parser = argparse.ArgumentParser(
        prog="linuxsentinel",
        description="Linux Security Audit Tool"
    )

    parser.add_argument(
        "command",
        nargs="?",
        choices=["scan", "version"],
        help="Command to execute"
    )

    args = parser.parse_args()

    # No command -> scan
    if args.command is None:
        args.command = "scan"

    # Version
    if args.command == "version":

        print(f"{APP_NAME} v{VERSION}")

        return

    # Scan
    if args.command == "scan":

        # First process opens a new terminal
        if os.environ.get("LINUXSENTINEL_CHILD") != "1":

            open_scan_terminal()

            return

        # Child process displays menu
        menu()

# ============================================================
# Program Entry Point
# ============================================================

if __name__ == "__main__":
    cli()
