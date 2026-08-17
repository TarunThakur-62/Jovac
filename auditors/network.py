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


def audit_network():

    print()
    print("[*] Checking network security...")
    print()

    findings = 0

    # =========================================================
    # Network Interfaces
    # =========================================================

    print("-" * 72)
    print("NETWORK INTERFACES")
    print("-" * 72)

    output, code = run_command([
        "ip",
        "-br",
        "addr"
    ])

    if code == 0:
        print(output)
    else:
        print("[!] Unable to read network interfaces.")

    # =========================================================
    # Listening Ports
    # =========================================================

    print()
    print("-" * 72)
    print("LISTENING PORTS")
    print("-" * 72)

    output, code = run_command([
        "ss",
        "-tuln"
    ])

    if code == 0:
        print(output)
    else:
        print("[!] Unable to read listening ports.")

    # =========================================================
    # Active Connections
    # =========================================================

    print()
    print("-" * 72)
    print("ACTIVE NETWORK CONNECTIONS")
    print("-" * 72)

    output, code = run_command([
        "ss",
        "-tun"
    ])

    if code == 0:
        print(output)
    else:
        print("[!] Unable to read active connections.")

    # =========================================================
    # Routing Table
    # =========================================================

    print()
    print("-" * 72)
    print("ROUTING TABLE")
    print("-" * 72)

    output, code = run_command([
        "ip",
        "route"
    ])

    if code == 0:
        print(output)
    else:
        print("[!] Unable to read routing table.")

    # =========================================================
    # DNS Configuration
    # =========================================================

    print()
    print("-" * 72)
    print("DNS CONFIGURATION")
    print("-" * 72)

    try:
        with open("/etc/resolv.conf", "r") as file:
            dns_config = file.read().strip()

        if dns_config:
            print(dns_config)
        else:
            print("[!] DNS configuration is empty.")

    except PermissionError:
        print("[!] Permission denied reading /etc/resolv.conf")

    except FileNotFoundError:
        print("[!] /etc/resolv.conf not found.")

    # =========================================================
    # IP Forwarding
    # =========================================================

    print()
    print("-" * 72)
    print("IP FORWARDING")
    print("-" * 72)

    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as file:
            forwarding = file.read().strip()

        if forwarding == "1":
            print("[!] IPv4 forwarding is ENABLED.")
            findings += 1
        else:
            print("[+] IPv4 forwarding is disabled.")

    except Exception as e:
        print(f"[!] Unable to check IP forwarding: {e}")

    # =========================================================
    # Reverse Path Filtering
    # =========================================================

    print()
    print("-" * 72)
    print("REVERSE PATH FILTERING")
    print("-" * 72)

    try:
        with open(
            "/proc/sys/net/ipv4/conf/all/rp_filter",
            "r"
        ) as file:
            rp_filter = file.read().strip()

        if rp_filter == "1":
            print("[+] Reverse path filtering is enabled.")
        else:
            print("[INFO] Reverse path filtering is not fully enabled.")

    except Exception as e:
        print(f"[!] Unable to check reverse path filtering: {e}")

    # =========================================================
    # Summary
    # =========================================================

    print()
    print("=" * 72)
    print("NETWORK SECURITY SUMMARY")
    print("=" * 72)

    print(f"Potential findings: {findings}")

    if findings == 0:
        print("[+] No obvious network configuration issues detected.")
    else:
        print("[!] Network configuration requires review.")

    print()
    print("[+] Network security audit completed.")
