import subprocess


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False
        )

        return result.stdout.strip(), result.returncode

    except Exception as e:
        return f"ERROR: {e}", 1


def audit_firewall():

    print()
    print("[*] Checking firewall configuration...")
    print()

    firewall_found = False

    # =========================================================
    # UFW
    # =========================================================

    print("-" * 72)
    print("UFW FIREWALL")
    print("-" * 72)

    ufw_output, ufw_code = run_command([
        "ufw",
        "status"
    ])

    if ufw_code == 0:
        firewall_found = True
        print(ufw_output)

    else:
        print("[INFO] UFW is not available or not enabled.")

    # =========================================================
    # NFTABLES
    # =========================================================

    print()
    print("-" * 72)
    print("NFTABLES FIREWALL")
    print("-" * 72)

    nft_output, nft_code = run_command([
        "nft",
        "list",
        "ruleset"
    ])

    if nft_code == 0 and nft_output:

        firewall_found = True

        print(nft_output[:5000])

        if len(nft_output) > 5000:
            print()
            print("[INFO] nftables output truncated.")

    else:
        print("[INFO] No active nftables ruleset detected.")

    # =========================================================
    # IPTABLES
    # =========================================================

    print()
    print("-" * 72)
    print("IPTABLES FIREWALL")
    print("-" * 72)

    iptables_output, iptables_code = run_command([
        "iptables",
        "-L",
        "-n"
    ])

    if iptables_code == 0:

        firewall_found = True

        print(iptables_output[:5000])

        if len(iptables_output) > 5000:
            print()
            print("[INFO] iptables output truncated.")

    else:
        print("[INFO] iptables unavailable or permission denied.")

    # =========================================================
    # SUMMARY
    # =========================================================

    print()
    print("-" * 72)
    print("FIREWALL SUMMARY")
    print("-" * 72)

    if firewall_found:
        print("[+] Firewall configuration detected.")
    else:
        print("[!] No active firewall configuration detected.")

    print()
    print("[+] Firewall audit completed.")
