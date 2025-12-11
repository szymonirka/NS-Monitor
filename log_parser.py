import subprocess

def get_logs():
    cmd = ["journalctl", "--since", "5 minutes ago", "-o", "short"]
    logs = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
    return logs.stdout.splitlines()
