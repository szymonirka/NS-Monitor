import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# ---- JSON EXPORT ----
def export_json(alerts, filename="incident_report.json"):
    with open(filename, "w") as f:
        json.dump({
            "timestamp": str(datetime.now()),
            "alerts": alerts
        }, f, indent=4)


# ---- PDF EXPORT ----
def export_pdf(alerts, filename="incident_report.pdf"):
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 40, "Incident Report")

    c.setFont("Helvetica", 12)
    c.drawString(50, height - 60, f"Generated: {datetime.now()}")

    y = height - 100
    for alert in alerts:
        c.drawString(50, y, f"- {alert['type']}: {alert['message']}")
        y -= 20
        if y < 50:  # new page
            c.showPage()
            c.setFont("Helvetica", 12)
            y = height - 50

    c.save()

