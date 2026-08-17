import os
import platform
import subprocess
import shutil


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )

        return result.stdout.strip()

    except Exception as e:
        return f"ERROR: {e}"


def get_os_info():
    info = {
        "OS": platform.system(),
        "Hostname": platform.node(),
        "Kernel": platform.release(),
        "Architecture": platform.machine(),
    }

    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                if "=" in line:
                    key, value = line.strip().split("=", 1)

                    if key in ["PRETTY_NAME", "VERSION_ID"]:
                        info[key] = value.strip('"')

    except (FileNotFoundError, PermissionError):
        pass

    return info


def get_uptime():
    try:
        with open("/proc/uptime", "r") as f:
            seconds = float(f.read().split()[0])

        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)

        return f"{days}d {hours}h {minutes}m"

    except Exception:
        return "Unknown"


def get_memory():
    try:
        memory = {}

        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split()

                if len(parts) >= 2:
                    key = parts[0].rstrip(":")
                    value = int(parts[1]) // 1024

                    memory[key] = value

        total = memory.get("MemTotal", 0)
        available = memory.get("MemAvailable", 0)

        used = total - available

        return total, used, available

    except Exception:
        return 0, 0, 0


def get_disk_usage():
    try:
        usage = shutil.disk_usage("/")

        total = usage.total // (1024 ** 3)
        used = usage.used // (1024 ** 3)
        free = usage.free // (1024 ** 3)

        percent = (usage.used / usage.total) * 100

        return total, used, free, percent

    except Exception:
        return 0, 0, 0, 0


def check_aslr():
    path = "/proc/sys/kernel/randomize_va_space"

    try:
        with open(path, "r") as f:
            value = f.read().strip()

        if value == "2":
            return "ENABLED", None

        return "WEAK", {
            "severity": "HIGH",
            "title": "ASLR is not fully enabled",
            "details": f"kernel.randomize_va_space = {value}",
            "recommendation": "Enable full ASLR using kernel.randomize_va_space=2."
        }

    except Exception:
        return "UNKNOWN", None


def check_ip_forwarding():
    findings = []

    ipv4 = "/proc/sys/net/ipv4/ip_forward"

    try:
        with open(ipv4, "r") as f:
            value = f.read().strip()

        if value == "1":
            findings.append({
                "severity": "MEDIUM",
                "title": "IPv4 packet forwarding enabled",
                "details": "net.ipv4.ip_forward = 1",
                "recommendation": "Disable IP forwarding if this machine is not intended to be a router."
            })

    except Exception:
        pass

    return findings


def check_core_dumps():
    value = run_command(
        ["bash", "-c", "ulimit -c"]
    )

    if value == "unlimited":
        return {
            "severity": "LOW",
            "title": "Unlimited core dumps enabled",
            "details": "Current shell core dump limit is unlimited.",
            "recommendation": "Restrict or disable core dumps where they are not required."
        }

    return None


def check_failed_services():
    if not shutil.which("systemctl"):
        return None

    output = run_command(
        ["systemctl", "--failed", "--no-legend", "--no-pager"]
    )

    if output and "0 loaded units listed" not in output:
        return {
            "severity": "MEDIUM",
            "title": "Failed system services detected",
            "details": output[:1000],
            "recommendation": "Investigate failed services using systemctl status <service>."
        }

    return None


def check_disk_space():
    total, used, free, percent = get_disk_usage()

    if percent >= 90:
        return {
            "severity": "HIGH",
            "title": "Root filesystem critically full",
            "details": f"{percent:.1f}% disk usage",
            "recommendation": "Free disk space immediately and investigate large files/logs."
        }

    if percent >= 80:
        return {
            "severity": "MEDIUM",
            "title": "Root filesystem usage is high",
            "details": f"{percent:.1f}% disk usage",
            "recommendation": "Monitor and clean unnecessary files before the filesystem becomes full."
        }

    return None


def audit_system():

    print()
    print("[*] Collecting Linux system security information...")
    print("=" * 72)

    findings = []

    # --------------------------------------------------
    # SYSTEM INFORMATION
    # --------------------------------------------------

    info = get_os_info()

    print()
    print("SYSTEM INFORMATION")
    print("-" * 72)

    print(f"Operating System : {info.get('PRETTY_NAME', 'Unknown')}")
    print(f"Hostname         : {info.get('Hostname', 'Unknown')}")
    print(f"Kernel           : {info.get('Kernel', 'Unknown')}")
    print(f"Architecture     : {info.get('Architecture', 'Unknown')}")
    print(f"Uptime           : {get_uptime()}")

    # --------------------------------------------------
    # MEMORY
    # --------------------------------------------------

    total, used, available = get_memory()

    print()
    print("MEMORY")
    print("-" * 72)

    print(f"Total Memory     : {total} MB")
    print(f"Used Memory      : {used} MB")
    print(f"Available Memory : {available} MB")

    # --------------------------------------------------
    # DISK
    # --------------------------------------------------

    disk_total, disk_used, disk_free, disk_percent = get_disk_usage()

    print()
    print("ROOT FILESYSTEM")
    print("-" * 72)

    print(f"Total Space      : {disk_total} GB")
    print(f"Used Space       : {disk_used} GB")
    print(f"Free Space       : {disk_free} GB")
    print(f"Usage            : {disk_percent:.1f}%")

    disk_finding = check_disk_space()

    if disk_finding:
        findings.append(disk_finding)

    # --------------------------------------------------
    # ASLR
    # --------------------------------------------------

    print()
    print("KERNEL SECURITY")
    print("-" * 72)

    aslr_status, aslr_finding = check_aslr()

    if aslr_status == "ENABLED":
        print("[+] ASLR                : ENABLED")

    elif aslr_status == "WEAK":
        print("[HIGH] ASLR             : WEAK")

    else:
        print("[INFO] ASLR             : UNKNOWN")

    if aslr_finding:
        findings.append(aslr_finding)

    # --------------------------------------------------
    # IP FORWARDING
    # --------------------------------------------------

    forwarding_findings = check_ip_forwarding()

    if forwarding_findings:
        print("[MEDIUM] IPv4 forwarding  : ENABLED")
        findings.extend(forwarding_findings)

    else:
        print("[+] IPv4 forwarding     : DISABLED")

    # --------------------------------------------------
    # CORE DUMP
    # --------------------------------------------------

    core_finding = check_core_dumps()

    if core_finding:
        print("[LOW] Core dumps         : UNLIMITED")
        findings.append(core_finding)

    else:
        print("[+] Core dumps           : RESTRICTED")

    # --------------------------------------------------
    # FAILED SERVICES
    # --------------------------------------------------

    service_finding = check_failed_services()

    print()
    print("SERVICE HEALTH")
    print("-" * 72)

    if service_finding:
        print("[MEDIUM] Failed services detected")
        findings.append(service_finding)

    else:
        print("[+] No failed system services detected")

    # --------------------------------------------------
    # SUMMARY
    # --------------------------------------------------

    print()
    print("=" * 72)
    print("SYSTEM SECURITY SUMMARY")
    print("=" * 72)

    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")

    print(f"Security findings : {len(findings)}")
    print(f"HIGH              : {high}")
    print(f"MEDIUM            : {medium}")
    print(f"LOW               : {low}")

    if findings:
        print()
        print("FINDINGS")
        print("-" * 72)

        for finding in findings:
            print(f"[{finding['severity']}] {finding['title']}")
            print(f"    Details       : {finding['details']}")
            print(f"    Recommendation: {finding['recommendation']}")
            print()

    else:
        print()
        print("[+] No obvious system security issues detected.")

    print("[+] System security audit completed.")
