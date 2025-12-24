import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def export_json(alerts, filename="incident_report.json"):
    """
    Export alerts to a JSON file.
    """
    data = {
        "generated_at": datetime.now().isoformat(),
        "alert_count": len(alerts),
        "alerts": alerts,
    }

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)



def export_pdf(alerts, filename="incident_report.pdf"):
    """
    Export alerts to a simple PDF report.
    """
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 40, "Incident Report")

    c.setFont("Helvetica", 12)
    c.drawString(50, height - 60, f"Generated: {datetime.now().isoformat()}")

    y = height - 100
    for alert in alerts:
        line = f"- {alert.get('type', 'Unknown')}: {alert.get('message', '')}"
        c.drawString(50, y, line)
        y -= 20
        if y < 50:  # new page if needed
            c.showPage()
            c.setFont("Helvetica", 12)
            y = height - 50

    c.save()

def export_json_logs(logs, filename="logs.json"):
    data = {
        "generated_at": datetime.now().isoformat(),
        "log_count": len(logs),
        "logs": logs
    }

    with open(filename, "w") as f:
        json.dump(data, f, indent=4)


def export_pdf_logs(logs, filename="logs.pdf"):
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 40, "System Logs Report")

    c.setFont("Helvetica", 12)
    c.drawString(50, height - 60, f"Generated: {datetime.now().isoformat()}")

    y = height - 100

    for line in logs:
        c.drawString(50, y, line[:90])  # 90 chars per line
        y -= 15
        if y < 50:
            c.showPage()
            c.setFont("Helvetica", 12)
            y = height - 50

    c.save()
