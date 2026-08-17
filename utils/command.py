import subprocess


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30
        )

        return result.stdout.strip()

    except subprocess.TimeoutExpired:
        return ""

    except FileNotFoundError:
        return ""

    except Exception:
        return ""
