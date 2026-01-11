from PyQt5.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout,QHBoxLayout, QLabel, QDialog, QTextEdit, QPushButton, QFileDialog
from PyQt5.QtCore import QTimer
import re
from collections import defaultdict
from log_parser import get_logs
from detector import detect_anomalies, is_network_error_line
from datetime import datetime 

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setStyleSheet("""
            QMainWindow {
                background-color: #121212;
            }

            QWidget {
                background-color: #121212;
                color: #e0e0e0;
                font-family: Segoe UI, Arial;
                font-size: 13px;
            }

            QLabel {
                color: #e0e0e0;
                font-size: 14px;
            }

            QTabWidget::pane {
                border: 1px solid #333333;
                background: #181818;
            }

            QTabBar::tab {
                background: #1f1f1f;
                color: #b0b0b0;
                padding: 6px 18px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                margin-right: 3px;
            }

            QTabBar::tab:selected {
                background: #2c89d9;
                color: #ffffff;
            }

            QTabBar::tab:hover {
                background: #2f2f2f;
            }

            QPushButton {
                background-color: #2c89d9;
                color: #ffffff;
                border-radius: 6px;
                padding: 6px 12px;
                border: 1px solid #1b6fb8;
            }

            QPushButton:hover {
                background-color: #1b6fb8;
            }

            QPushButton:pressed {
                background-color: #155a96;
            }

            QTextEdit {
                background: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #333333;
                border-radius: 6px;
                padding: 6px;
            }

            QLineEdit {
                background: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #333333;
                border-radius: 4px;
                padding: 4px;
            }

            QDialog {
                background-color: #121212;
            }

            QScrollBar:vertical {
                background: #1e1e1e;
                width: 10px;
                margin: 2px 0 2px 0;
            }

            QScrollBar::handle:vertical {
                background: #444444;
                min-height: 20px;
                border-radius: 4px;
            }

            QScrollBar::handle:vertical:hover {
                background: #555555;
            }

            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                height: 0;
            }
        """)

        # Keep timestamps for alerts so they don't "refresh" every second
        self.alert_first_seen = {}   # key -> timestamp string
        self.last_alert_keys = set() # used to detect changes

        self.setWindowTitle("Local Network Security Monitoring System")
        self.resize(900, 600)


        tabs = QTabWidget()
        tabs.addTab(self.dashboard_tab(), "Dashboard")
        tabs.addTab(self.alerts_tab(), "Alerts")
        tabs.addTab(self.logs_tab(), "Logs")

        self.setCentralWidget(tabs)

        #timer
        self.auto_refresh_interval_ms = 1000 
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.auto_refresh)
        self.timer.start(self.auto_refresh_interval_ms)


    def dashboard_tab(self):
        w = QWidget()
        layout = QVBoxLayout()

        layout.addWidget(QLabel("<h2>System Monitoring Dashboard</h2>"))

        card_style = """
            background-color: #1b1b1b;
            border: 1px solid #333333;
            border-radius: 10px;
            padding: 12px 16px;
            margin-bottom: 12px;
            font-size: 15px;
            font-weight: 500;
        """


        # Counters
        self.failed_label = QLabel("Failed SSH Attempts: 0")
        self.failed_label.setStyleSheet(card_style)

        self.sudo_label = QLabel("Sudo Failures: 0")
        self.sudo_label.setStyleSheet(card_style)

        self.firewall_label = QLabel("Firewall Blocks: 0")
        self.firewall_label.setStyleSheet(card_style)

        self.network_label = QLabel("Network Errors: 0")
        self.network_label.setStyleSheet(card_style)
        
        layout.addWidget(self.failed_label)
        layout.addWidget(self.sudo_label)
        layout.addWidget(self.firewall_label)
        layout.addWidget(self.network_label)


        # --- Details buttons row ---
        btn_layout = QHBoxLayout()

        ssh_btn = QPushButton("Show SSH Failures")
        ssh_btn.clicked.connect(self.show_ssh_failures)
        btn_layout.addWidget(ssh_btn)

        sudo_btn = QPushButton("Show Sudo Failures")
        sudo_btn.clicked.connect(self.show_sudo_failures)
        btn_layout.addWidget(sudo_btn)

        fw_btn = QPushButton("Show Firewall Blocks")
        fw_btn.clicked.connect(self.show_firewall_blocks)
        btn_layout.addWidget(fw_btn)

        net_btn = QPushButton("Show Network Errors")
        net_btn.clicked.connect(self.show_network_errors)
        btn_layout.addWidget(net_btn)

        layout.addLayout(btn_layout)
        # ---------------------------


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

        btn_layout = QHBoxLayout()

        export_logs_json_btn = QPushButton("Export Logs (JSON)")
        export_logs_json_btn.clicked.connect(self.export_logs_json)
        btn_layout.addWidget(export_logs_json_btn)

        export_logs_pdf_btn = QPushButton("Export Logs (PDF)")
        export_logs_pdf_btn.clicked.connect(self.export_logs_pdf)
        btn_layout.addWidget(export_logs_pdf_btn)

        layout.addLayout(btn_layout)
        w.setLayout(layout)
        return w

    def refresh_logs(self):
        logs = get_logs()
        self.logs_text.setText("\n".join(logs))

    def refresh_alerts(self):
        logs = get_logs()
        alerts = detect_anomalies(logs)

        # Build stable keys (same alert = same key)
        current_keys = set()
        for a in alerts:
            key = (a.get("type", ""), a.get("message", ""))
            current_keys.add(key)

            # Assign timestamp only the first time we see this alert key
            if key not in self.alert_first_seen:
                self.alert_first_seen[key] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Remove timestamps for alerts that disappeared (optional)
        # If you want to keep history, comment this block out.
        for old_key in list(self.alert_first_seen.keys()):
            if old_key not in current_keys:
                del self.alert_first_seen[old_key]

        # If nothing changed, don't update the UI (prevents flicker)
        if current_keys == self.last_alert_keys:
            return
        self.last_alert_keys = current_keys

        # Format output
        lines = []
        for key in sorted(current_keys, key=lambda k: self.alert_first_seen[k]):
            ts = self.alert_first_seen[key]
            alert_type, msg = key
            lines.append(f"[{ts}] {alert_type}: {msg}")

        self.alerts_text.setText("\n".join(lines))

    
    def refresh_stats(self):
        logs = get_logs()
        alerts = detect_anomalies(logs)

        # Updatable stats
        failed = sum("Failed password" in line for line in logs) #ssh
        sudo = 0
        for line in logs:
            if "sudo" in line:
                if "incorrect password attempts" in line:
                    m = re.search(r"(\d+)\s+incorrect password attempts", line) # sudo
                    n = int(m.group(1)) if m else 1
                    sudo += 1
        firewall = sum("UFW BLOCK" in line or "iptables" in line for line in logs) #firewall
        network = sum(is_network_error_line(line) for line in logs) #network errors

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
            
            if hasattr(self, "alerts_text"):
                self.alerts_text.append(f"\n[auto-refresh error] {e}")



    def export_json_report(self):
        
        from report_exporter import export_json
        logs = get_logs()
        alerts = detect_anomalies(logs)

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save JSON Report",
            "",
            "JSON Files (*.json);;All Files (*)"
        )

        if not path:  #cancelled
            return

        try:
            export_json(alerts, filename=path)
            self.alerts_text.append(f"\n[+] JSON report exported to: {path}")
        except Exception as e:
            self.alerts_text.append(f"\n[ERROR exporting PDF] {e}")


    def export_pdf_report(self):
        
        from report_exporter import export_pdf
        logs = get_logs()
        alerts = detect_anomalies(logs)

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save PDF Report",
            "",
            "PDF Files (*.pdf);;All Files (*)"
        )

        if not path:  #cancelled
            return
        try:
            export_pdf(alerts, filename=path)
            self.alerts_text.append(f"\n[+] PDF report exported to: {path}")
        except Exception as e:
            self.alerts_text.append(f"\n[ERROR exporting PDF] {e}")

    def export_logs_json(self):
       from report_exporter import export_json_logs

       logs = get_logs() 

       path, _ = QFileDialog.getSaveFileName(
           self,
            "Save Logs (JSON)",
            "",
            "JSON Files (*.json);;All Files (*)"

       )

       if not path:
           return
       
       try:
           export_json_logs(logs, filename=path)
           self.logs_text.append(f"\n[+] Logs exported to JSON: {path}")
       except Exception as e:
           self.logs_text.append(f"\n[ERROR exporting logs JSON] {e}")

    def export_logs_pdf(self):
        from report_exporter import export_pdf_logs

        logs = get_logs()

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Logs (PDF)",
            "",
            "PDF Files (*.pdf);;All Files (*)"
        )

        if not path:
            return

        try:
            export_pdf_logs(logs, filename=path)
            self.logs_text.append(f"\n[+] Logs exported to PDF: {path}")
        except Exception as e:
            self.logs_text.append(f"\n[ERROR exporting logs PDF] {e}")

    def show_details(self, title, lines):
        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        dlg.resize(700, 500)

        layout = QVBoxLayout()
        text = QTextEdit()
        text.setReadOnly(True)
        text.setText("\n".join(lines))
        layout.addWidget(text)

        dlg.setLayout(layout)
        dlg.exec_()

           
    def show_ssh_failures(self):
        logs = get_logs()
        lines = [l for l in logs if "Failed password" in l]
        self.show_details("Failed SSH Attempts", lines)

    def show_sudo_failures(self):
        logs = get_logs()
        lines = [l for l in logs if "sudo" in l and ("authentication failure" in l or "incorrect password attempts" in l)]
        self.show_details("Sudo Authentication Failures", lines)

    def show_firewall_blocks(self):
        logs = get_logs()
        lines = [l for l in logs if "UFW BLOCK" in l or "iptables" in l or "Denied" in l]
        self.show_details("Firewall Block Events", lines)

    def show_network_errors(self):
        logs = get_logs()
        lines = [l for l in logs if is_network_error_line(l)]
        self.show_details("Network Errors", lines)



