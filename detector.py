def detect_anomalies(logs):
    alerts = []
    failed = [l for l in logs if "Failed password" in l]

    if len(failed) > 5:
        alerts.append({
            "type": "Brute Force",
            "message": f"{len(failed)} failed SSH logins detected"
        })

    return alerts
