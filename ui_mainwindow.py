from PyQt5.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton
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

    def dashboard_tab(self):
        w = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Dashboard Overview (Simple Version)"))
        layout.addWidget(QLabel("Alerts detected:"))
        self.alert_count_label = QLabel("0")
        layout.addWidget(self.alert_count_label)
        w.setLayout(layout)
        return w

    def alerts_tab(self):
        w = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Detected Alerts:"))
        self.alerts_text = QTextEdit()
        layout.addWidget(self.alerts_text)
        refresh_btn = QPushButton("Refresh Alerts")
        refresh_btn.clicked.connect(self.refresh_alerts)
        layout.addWidget(refresh_btn)
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
        self.alerts_text.setText("\n".join([str(a) for a in alerts]))
        self.alert_count_label.setText(str(len(alerts)))
