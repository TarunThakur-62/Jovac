import re
import subprocess


# ============================================================
# Command Helper
# ============================================================

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


# ============================================================
# Running Services
# ============================================================

def get_running_services():

    output, code = run_command([
        "systemctl",
        "list-units",
        "--type=service",
        "--state=running",
        "--no-pager",
        "--no-legend"
    ])

    if code != 0:
        return []

    services = []

    for line in output.splitlines():

        parts = line.split(None, 4)

        if len(parts) >= 4:

            services.append({
                "unit": parts[0],
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": parts[4] if len(parts) >= 5 else ""
            })

    return services


# ============================================================
# Enabled Services
# ============================================================

def get_enabled_services():

    output, code = run_command([
        "systemctl",
        "list-unit-files",
        "--type=service",
        "--state=enabled",
        "--no-pager",
        "--no-legend"
    ])

    if code != 0:
        return []

    services = []

    for line in output.splitlines():

        parts = line.split()

        if len(parts) >= 2:
            services.append(parts[0])

    return services


# ============================================================
# Failed Services
# ============================================================

def get_failed_services():

    output, code = run_command([
        "systemctl",
        "--failed",
        "--type=service",
        "--no-pager",
        "--no-legend"
    ])

    if code != 0:
        return []

    services = []

    for line in output.splitlines():

        parts = line.split()

        if len(parts) >= 4:
            services.append(parts[0])

    return services


# ============================================================
# Listening Ports
# ============================================================

def get_listening_ports():

    output, code = run_command([
        "ss",
        "-lntupH"
    ])

    if code != 0:
        return []

    entries = []

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        parts = line.split()

        if len(parts) < 5:
            continue

        protocol = parts[0]
        local_address = parts[4]

        process_info = "N/A"

        if len(parts) >= 7:
            process_info = " ".join(parts[6:])

        # Extract port
        port = "unknown"

        if local_address.startswith("["):

            match = re.search(r"\]:(\d+)$", local_address)

            if match:
                port = match.group(1)

        else:

            match = re.search(r":(\d+)$", local_address)

            if match:
                port = match.group(1)

        # Detect public binding
        public = False

        if (
            local_address.startswith("0.0.0.0:")
            or local_address.startswith("*:")
            or local_address.startswith("[::]:")
        ):
            public = True

        # Extract process
        process_name = "unknown"
        pid = "unknown"

        match = re.search(
            r'\(\("([^"]+)",pid=(\d+)',
            process_info
        )

        if match:

            process_name = match.group(1)
            pid = match.group(2)

        entries.append({
            "protocol": protocol,
            "local": local_address,
            "port": port,
            "process": process_name,
            "pid": pid,
            "public": public,
            "raw": line
        })

    return entries


# ============================================================
# Process Information
# ============================================================

def get_process_info(pid):

    if pid == "unknown":
        return {
            "user": "unknown",
            "command": "unknown"
        }

    output, code = run_command([
        "ps",
        "-p",
        pid,
        "-o",
        "user=,comm=,args="
    ])

    if code != 0 or not output:
        return {
            "user": "unknown",
            "command": "unknown"
        }

    parts = output.split(None, 2)

    user = parts[0] if len(parts) >= 1 else "unknown"
    command = parts[2] if len(parts) >= 3 else (
        parts[1] if len(parts) >= 2 else "unknown"
    )

    return {
        "user": user,
        "command": command
    }


# ============================================================
# Risky Ports
# ============================================================

RISKY_PORTS = {
    "21": ("FTP", "MEDIUM"),
    "23": ("Telnet", "HIGH"),
    "25": ("SMTP", "LOW"),
    "69": ("TFTP", "HIGH"),
    "110": ("POP3", "LOW"),
    "139": ("NetBIOS", "MEDIUM"),
    "445": ("SMB", "MEDIUM"),
    "512": ("rexec", "HIGH"),
    "513": ("rlogin", "HIGH"),
    "514": ("rsh", "HIGH"),
    "1433": ("MSSQL", "MEDIUM"),
    "1521": ("Oracle", "MEDIUM"),
    "3306": ("MySQL", "MEDIUM"),
    "5432": ("PostgreSQL", "MEDIUM"),
    "6379": ("Redis", "HIGH"),
    "27017": ("MongoDB", "HIGH")
}


# ============================================================
# Analyze Listening Services
# ============================================================

def analyze_listening_services(entries):

    findings = []

    for entry in entries:

        port = entry["port"]
        process = entry["process"]

        # ----------------------------------------------------
        # Publicly exposed service
        # ----------------------------------------------------

        if entry["public"]:

            severity = "LOW"

            if port in RISKY_PORTS:
                service_name, severity = RISKY_PORTS[port]
            else:
                service_name = process

            findings.append({
                "severity": severity,
                "title": f"Network service exposed on port {port}",
                "details": (
                    f"{service_name} is listening on "
                    f"{entry['local']} "
                    f"using process {process}."
                ),
                "recommendation": (
                    "Verify that this service is intentionally "
                    "exposed and restrict access when possible."
                )
            })

        # ----------------------------------------------------
        # Risky service even if not public
        # ----------------------------------------------------

        if port in RISKY_PORTS:

            service_name, severity = RISKY_PORTS[port]

            findings.append({
                "severity": severity,
                "title": f"{service_name} detected on port {port}",
                "details": (
                    f"Process {process} is associated with "
                    f"port {port}."
                ),
                "recommendation": (
                    f"Verify whether {service_name} is required. "
                    "Disable or restrict it if unnecessary."
                )
            })

    return findings


# ============================================================
# Analyze Processes
# ============================================================

def analyze_processes(entries):

    findings = []

    checked_pids = set()

    for entry in entries:

        pid = entry["pid"]

        if pid == "unknown":
            continue

        if pid in checked_pids:
            continue

        checked_pids.add(pid)

        info = get_process_info(pid)

        entry["user"] = info["user"]
        entry["command"] = info["command"]

        # ----------------------------------------------------
        # Root network process
        # ----------------------------------------------------

        if (
            entry["public"]
            and info["user"] == "root"
        ):

            findings.append({
                "severity": "MEDIUM",
                "title": "Root-owned network service exposed",
                "details": (
                    f"Process {entry['process']} "
                    f"(PID {pid}) is running as root and "
                    f"listening on {entry['local']}."
                ),
                "recommendation": (
                    "Verify that root privileges are required "
                    "and restrict network exposure."
                )
            })

    return findings


# ============================================================
# Audit Services
# ============================================================

def audit_services():

    print()
    print("[*] Collecting Linux service security information...")
    print()

    # ========================================================
    # Running Services
    # ========================================================

    print("=" * 80)
    print("RUNNING SERVICES")
    print("=" * 80)

    running_services = get_running_services()

    if running_services:

        print(
            f"{'SERVICE':<40}"
            f"{'STATUS':<12}"
            f"DESCRIPTION"
        )

        print("-" * 80)

        for service in running_services:

            print(
                f"{service['unit']:<40}"
                f"{service['sub']:<12}"
                f"{service['description']}"
            )

    else:

        print("[!] Unable to retrieve running services.")

    # ========================================================
    # Enabled Services
    # ========================================================

    print()
    print("=" * 80)
    print("SERVICES ENABLED AT BOOT")
    print("=" * 80)

    enabled_services = get_enabled_services()

    if enabled_services:

        for service in enabled_services:
            print(f"[ENABLED] {service}")

    else:

        print("[INFO] No enabled services found.")

    # ========================================================
    # Failed Services
    # ========================================================

    print()
    print("=" * 80)
    print("FAILED SERVICES")
    print("=" * 80)

    failed_services = get_failed_services()

    if failed_services:

        for service in failed_services:
            print(f"[FAILED] {service}")

    else:

        print("[+] No failed services detected.")

    # ========================================================
    # Listening Services
    # ========================================================

    print()
    print("=" * 80)
    print("NETWORK-LISTENING SERVICES")
    print("=" * 80)

    listening_services = get_listening_ports()

    if listening_services:

        print(
            f"{'PROTO':<8}"
            f"{'ADDRESS':<25}"
            f"{'PORT':<8}"
            f"{'PROCESS':<20}"
            f"{'PID':<8}"
        )

        print("-" * 80)

        for entry in listening_services:

            print(
                f"{entry['protocol']:<8}"
                f"{entry['local']:<25}"
                f"{entry['port']:<8}"
                f"{entry['process']:<20}"
                f"{entry['pid']:<8}"
            )

    else:

        print("[INFO] No listening services detected.")

    # ========================================================
    # Security Analysis
    # ========================================================

    print()
    print("=" * 80)
    print("SERVICE SECURITY ANALYSIS")
    print("=" * 80)

    findings = []

    findings.extend(
        analyze_listening_services(listening_services)
    )

    findings.extend(
        analyze_processes(listening_services)
    )

    # Failed services
    for service in failed_services:

        findings.append({
            "severity": "MEDIUM",
            "title": "Failed system service",
            "details": f"{service} is currently in a failed state.",
            "recommendation": (
                "Investigate service logs and determine "
                "whether the service is required."
            )
        })

    # ========================================================
    # Findings
    # ========================================================

    if findings:

        for index, finding in enumerate(findings, 1):

            print()
            print(
                f"[{finding['severity']}] "
                f"{finding['title']}"
            )

            print(
                f"    Details: "
                f"{finding['details']}"
            )

            print(
                f"    Recommendation: "
                f"{finding['recommendation']}"
            )

    else:

        print()
        print("[+] No obvious service security issues detected.")

    # ========================================================
    # Severity Summary
    # ========================================================

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

    # ========================================================
    # Final Summary
    # ========================================================

    print()
    print("=" * 80)
    print("SERVICE SECURITY SUMMARY")
    print("=" * 80)

    print(f"Running services       : {len(running_services)}")
    print(f"Enabled services       : {len(enabled_services)}")
    print(f"Failed services        : {len(failed_services)}")
    print(f"Listening services     : {len(listening_services)}")
    print(f"Security findings      : {len(findings)}")

    print()
    print(f"HIGH findings          : {high}")
    print(f"MEDIUM findings        : {medium}")
    print(f"LOW findings           : {low}")

    # ========================================================
    # Security Status
    # ========================================================

    print()

    if high > 0:

        print(
            "[CRITICAL] High-risk service exposure detected."
        )

    elif medium > 0:

        print(
            "[WARNING] Service configuration requires review."
        )

    elif low > 0:

        print(
            "[INFO] Minor service security issues detected."
        )

    else:

        print(
            "[+] Service configuration appears reasonable."
        )

    print()
    print("[+] Service security audit completed.")
