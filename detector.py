import re
from collections import Counter, defaultdict


def is_network_error_line(line: str) -> bool:

    l = line.lower()
    keywords = [
                "link is down",
        "link down",
        "network unreachable",
        "no route to host",
        "destination host unreachable",
        "connection refused",
        "connection timed out",
        "temporary failure in name resolution",
        "network is unreachable",
        "dns failure",
        "network error",
        "net-error-test", # test
    ]
    return any(k in l for k in keywords)

def detect_anomalies(logs):
    alerts = []

    # pomocnicze liczniki

    failed_ssh = []
    sudo_failures = []
    sudo_failure_count = 0  
    firewall_blocks = []
    iface_errors = []
    connection_attempts = defaultdict(int)

    for line in logs:

        #SSH
        if "Failed password" in line:
            failed_ssh.append(line)

            # wglad w ip IP
            match = re.search(r"from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
            if match:
                ip = match.group(1)
                connection_attempts[ip] += 1
        
        #Sudo failure
        if "sudo" in line:
            # Case 1: summary line like "sudo: 3 incorrect password attempts"
            if "incorrect password attempts" in line:
                m = re.search(r"(\d+)\s+incorrect password attempts", line)
                n = int(m.group(1)) if m else 1
                sudo_failure_count += n
                sudo_failures.append(f"{line} [counted {n} attempts]")


        #firewall 
        if "UFW BLOCK" in line or "Denied" in line or "iptables" in line:
            firewall_blocks.append(line)
        
        #network error
        if is_network_error_line(line):
            iface_errors.append(line)

    #--------rules------------
    #1. to many failed ssh attempts

    if len(failed_ssh) > 5:
        alerts.append({
            "type" : "Brute Force",
            "message": f"{len(failed_ssh)} failed SSH login attempts detected"
        })

    #2 Repeated attempts from a single IP
    for ip, count in connection_attempts.items():
        if count > 3:
            alerts.append({
                "type": "Suspicious IP activity",
                "message": f"IP {ip} attempted {count} failed logins"
            })
    #3 too many sudo failures
    if len(sudo_failures) > 2:
        alerts.append({
            "type": "Privilege Escalation Attempt",
            "message": f"{len(sudo_failures)} failed sudo authentication attempts"    
        })

  # 4. Firewall blocked packets
    if len(firewall_blocks) > 0:
        alerts.append({
            "type": "Firewall Blocks",
            "message": f"{len(firewall_blocks)} packets blocked by firewall"
        })

    # 5. Network interface errors
    if len(iface_errors) > 0:
        alerts.append({
            "type": "Network Interface Errors",
            "message": f"{len(iface_errors)} network errors detected"
        })   




    return alerts
