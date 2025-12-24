from PyQt5.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout,QHBoxLayout, QLabel, QTextEdit, QPushButton
from PyQt5.QtCore import QTimer
from log_parser import get_logs
from detector import detect_anomalies

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Local Network Security Monitoring System")
        self.resize(900, 600)

        tabs = QTabWidget()
        tabs.addTab(self.dashboard_tab(), "Dashboard")
        tabs.addTab(self.alerts_tab(), "Alerts")
        tabs.addTab(self.logs_tab(), "Logs")

        self.setCentralWidget(tabs)

        #timer
        self.auto_refresh_interval_ms = 5000 
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.auto_refresh)
        self.timer.start(self.auto_refresh_interval_ms)


    def dashboard_tab(self):
        w = QWidget()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("<h2>System Monitoring Dashboard</h2>"))

        self.failed_label = QLabel("Failed SSH Attempts: 0")
        self.sudo_label = QLabel("Sudo Failures: 0")
        self.firewall_label = QLabel("Firewall Blocks: 0")
        self.network_label = QLabel("Network Errors: 0")

        layout.addWidget(self.failed_label)
        layout.addWidget(self.sudo_label)
        layout.addWidget(self.firewall_label)
        layout.addWidget(self.network_label)

        refresh_btn = QPushButton("Refresh Stats")
        refresh_btn.clicked.connect(self.refresh_stats)
        layout.addWidget(refresh_btn)

        w.setLayout(layout)
        return w


    def alerts_tab(self):
        w = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Detected Alerts:"))

        self.alerts_text = QTextEdit()
        layout.addWidget(self.alerts_text)

        btn_layout = QHBoxLayout()

        refresh_btn = QPushButton("Refresh Alerts")
        refresh_btn.clicked.connect(self.refresh_alerts)
        btn_layout.addWidget(refresh_btn)

        export_json_btn = QPushButton("Export JSON Report")
        export_json_btn.clicked.connect(self.export_json_report)
        btn_layout.addWidget(export_json_btn)

        export_pdf_btn = QPushButton("Export PDF Report")
        export_pdf_btn.clicked.connect(self.export_pdf_report)
        btn_layout.addWidget(export_pdf_btn)

        layout.addLayout(btn_layout)

        w.setLayout(layout)
        return w


    def logs_tab(self):
        w = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("System Logs:"))
        self.logs_text = QTextEdit()
        layout.addWidget(self.logs_text)
        refresh_btn = QPushButton("Refresh Logs")
        refresh_btn.clicked.connect(self.refresh_logs)
        layout.addWidget(refresh_btn)
        w.setLayout(layout)
        return w

    def refresh_logs(self):
        logs = get_logs()
        self.logs_text.setText("\n".join(logs))

    def refresh_alerts(self):
        logs = get_logs()
        alerts = detect_anomalies(logs)
        lines = [f"{a['type']}: {a['message']}" for a in alerts]
        self.alerts_text.setText("\n".join(lines))

        #if label exist
        if hasattr(self, "alert_count_label"):
            self.alert_count_label.setText(str(len(alerts)))
    
    def refresh_stats(self):
        logs = get_logs()
        alerts = detect_anomalies(logs)

        # Updatable stats
        failed = sum("Failed password" in line for line in logs)
        sudo = sum(
        ("sudo" in line and "authentication failure" in line) or
        ("sudo" in line and "incorrect password" in line)
        for line in logs)
        firewall = sum("UFW BLOCK" in line or "iptables" in line for line in logs)
        network = sum("error" in line.lower() for line in logs)

        self.failed_label.setText(f"Failed SSH Attempts: {failed}")
        self.sudo_label.setText(f"Sudo Failures: {sudo}")
        self.firewall_label.setText(f"Firewall Blocks: {firewall}")
        self.network_label.setText(f"Network Errors: {network}")

    def auto_refresh(self):
        """
        Periodically refresh logs, alerts and stats.
        Called automatically by QTimer.
        """
        try:
            self.refresh_logs()
            self.refresh_alerts()
            self.refresh_stats()
        except Exception as e:
            # Optional: show simple error info in alerts tab instead of crashing
            if hasattr(self, "alerts_text"):
                self.alerts_text.append(f"\n[auto-refresh error] {e}")



    def export_json_report(self):
        try:
            from report_exporter import export_json
            logs = get_logs()
            alerts = detect_anomalies(logs)
            export_json(alerts)
            self.alerts_text.append("\n[+] JSON report exported")
        except Exception as e:
            self.alerts_text.append(f"\n[ERROR exporting PDF] {e}")


    def export_pdf_report(self):
        try:
            from report_exporter import export_pdf
            logs = get_logs()
            alerts = detect_anomalies(logs)
            export_pdf(alerts)
            self.alerts_text.append("\n[+] PDF report exported")
        except Exception as e:
            self.alerts_text.append(f"\n[ERROR exporting PDF] {e}")

