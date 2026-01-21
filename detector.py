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

    #--------zasady------------

    #1. zbyt dużo prób połączenia ssh
    if len(failed_ssh) > 5:
        alerts.append({
            "type" : "Brute Force",
            "message": f"{len(failed_ssh)} failed SSH login attempts detected"
        })

    #2 powtórzone próby z adresu IP
    for ip, count in connection_attempts.items():
        if count > 3:
            alerts.append({
                "type": "Suspicious IP activity",
                "message": f"IP {ip} attempted {count} failed logins"
            })
    #3 zbyt dużo prób logowań na root
    if len(sudo_failures) > 2:
        alerts.append({
            "type": "Privilege Escalation Attempt",
            "message": f"{len(sudo_failures)} failed sudo authentication attempts"    
        })

  # 4. blokwane pakiety przez firewall
    if len(firewall_blocks) > 0:
        alerts.append({
            "type": "Firewall Blocks",
            "message": f"{len(firewall_blocks)} packets blocked by firewall"
        })

    # 5. problemy z interfejsem sieciowym
    if len(iface_errors) > 0:
        alerts.append({
            "type": "Network Interface Errors",
            "message": f"{len(iface_errors)} network errors detected"
        })   




    return alerts
