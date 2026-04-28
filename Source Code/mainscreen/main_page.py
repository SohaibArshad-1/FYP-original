"""
main_page.py
────────────────────────────────────────────────────────────────────────
Fixes applied:
  • live_detection signal from MonitoringController now wired to
    NotificationCenter.add_live_detection() so attack cards appear live
  • No .ui widget names or layouts changed
"""

from PyQt5 import QtWidgets, uic, QtGui
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QMainWindow, QApplication,
 QPushButton, QMessageBox, QListView, QGridLayout)
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtMultimedia import QSoundEffect
from PyQt5.QtCore import QUrl, QObject, pyqtSignal, QThread
from PyQt5 import QtCore
import sys
import json
import os
from monitoring_controller import MonitoringController
import images
import resources
from graph import LiveGraph

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.txt")


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi(os.path.join(BASE_DIR, "frontpage.ui"), self)

        self.header_widget.setStyleSheet("""
            QWidget { background-color: #780606; color: White; font-family: Georgia; }
        """)
        self.label_21.setText("AI Based IDPS")
        self.label_21.setAlignment(QtCore.Qt.AlignCenter)
        self.label_21.setStyleSheet("""
            QLabel { color: white; font: bold 30px "Times New Roman"; }
        """)

        self.current_font_size, self.current_sensitivity, \
            self.popup_enabled, self.sound_enabled = self.load_settings()

        self.monitoring_controller = MonitoringController(self)
        self.monitoring_controller.alert_triggered.connect(self.handle_alert)
        self.monitoring_controller.status_updated.connect(self.update_status)
        self._status_model = None  # cached model for listView_2

        self.apply_font_size(self.load_font_size())
        self.setup_ui()

    def setup_ui(self):
        self.stackedWidget.setCurrentIndex(0)
        self.icon_text_widget.hide()
        self.menu_btn.setChecked(True)
        self.connect_navigation()
        self.setup_dynamic_pages()
        self.setup_monitoring_button()
        self.setup_graph()
        self.apply_home_fonts()

    def connect_navigation(self):
        self.home.clicked.connect(lambda: self.show_page(0))
        self.home_icon.clicked.connect(lambda: self.show_page(0))
        self.dashboard.clicked.connect(lambda: self.show_page(2))
        self.monitoring_bar.clicked.connect(lambda: self.show_page(2))
        self.dashboard_icon.clicked.connect(lambda: self.show_page(2))
        self.Notifications.clicked.connect(lambda: self.show_page(3))
        self.notification_bar.clicked.connect(lambda: self.show_page(3))
        self.notification_icon.clicked.connect(lambda: self.show_page(3))
        self.Reports.clicked.connect(lambda: self.show_page(4))
        self.reports_bar.clicked.connect(lambda: self.show_page(4))
        self.reports_icon.clicked.connect(lambda: self.show_page(4))
        self.Setting.clicked.connect(lambda: self.show_page(1))
        self.setting_bar.clicked.connect(lambda: self.show_page(1))
        self.setting_icon.clicked.connect(lambda: self.show_page(1))

    def setup_monitoring_button(self):
        self.btnMonitor = self.findChild(QPushButton, 'btnMonitor')
        if self.btnMonitor:
            self.btnMonitor.clicked.connect(self.toggle_monitoring)
            self.update_button_state()

    def toggle_monitoring(self):
        if self.monitoring_controller.is_running:
            self.monitoring_controller.stop_monitoring()
        else:
            self.monitoring_controller.start_monitoring()
        self.update_button_state()

    def update_button_state(self):
        if hasattr(self, 'btnMonitor') and self.btnMonitor:
            self.btnMonitor.setChecked(self.monitoring_controller.is_running)
            self.btnMonitor.setText(
                "Stop Monitoring" if self.monitoring_controller.is_running
                else "Start Monitoring"
            )

    def handle_alert(self, attack_type, preventions):
        self.current_font_size, self.current_sensitivity, \
            self.popup_enabled, self.sound_enabled = self.load_settings()

        if self.sound_enabled:
            sound = QSoundEffect()
            sound.setSource(QUrl.fromLocalFile("alert.wav"))
            sound.setLoopCount(1)
            sound.setVolume(1.0)
            sound.play()

        if self.popup_enabled:
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Warning)
            msg.setWindowTitle("⚠️ IDPS Alert")
            prevention_text = (
                "\n".join(f"  • {p[0]}" for p in preventions)
                if preventions else "  No prevention data available"
            )
            msg.setText(
                f"<b>Attack Detected: {attack_type}</b><br><br>"
                f"<b>Prevention Measures:</b><br>{prevention_text.replace(chr(10), '<br>')}"
            )
            msg.exec_()

        self.update_status(f"ALERT: {attack_type} detected")

    def update_status(self, message):
        # Only show alerts and important messages — skip normal packet spam
        if not any(kw in message for kw in ("🟢", "🔴", "ALERT", "⚠️", "Attack")):
            return
        if self._status_model is None:
            status_list = self.findChild(QtWidgets.QListView, "listView_2")
            if not status_list:
                return
            self._status_model = QStandardItemModel(status_list)
            status_list.setModel(self._status_model)
        item = QStandardItem(message)
        item.setEditable(False)
        self._status_model.appendRow(item)
        # Keep the list from growing unboundedly
        if self._status_model.rowCount() > 100:
            self._status_model.removeRow(0)

    def setup_dynamic_pages(self):
        from notifications import NotificationCenter
        from report import ReportsPage
        from setting import SettingsPage

        self.notification_page = NotificationCenter()
        self.reports_page      = ReportsPage()
        self.setting_page      = SettingsPage()

        self.stackedWidget.addWidget(self.notification_page)
        self.stackedWidget.addWidget(self.reports_page)
        self.stackedWidget.addWidget(self.setting_page)

        # Prevention actions → notification live card
        self.monitoring_controller.prevention.prevention_done.connect(
            self.notification_page.add_live_prevention
        )

        # Attack detections → notification live card (NEW)
        self.monitoring_controller.live_detection.connect(
            self.notification_page.add_live_detection,
            QtCore.Qt.QueuedConnection
        )

        # Navigation buttons → correct pages
        self.Notifications.clicked.connect(
            lambda: self.stackedWidget.setCurrentWidget(self.notification_page))
        self.notification_bar.clicked.connect(
            lambda: self.stackedWidget.setCurrentWidget(self.notification_page))
        self.notification_icon.clicked.connect(
            lambda: self.stackedWidget.setCurrentWidget(self.notification_page))
        self.Reports.clicked.connect(
            lambda: self.stackedWidget.setCurrentWidget(self.reports_page))
        self.reports_bar.clicked.connect(
            lambda: self.stackedWidget.setCurrentWidget(self.reports_page))
        self.reports_icon.clicked.connect(
            lambda: self.stackedWidget.setCurrentWidget(self.reports_page))
        self.Setting.clicked.connect(
            lambda: self.stackedWidget.setCurrentWidget(self.setting_page))
        self.setting_bar.clicked.connect(
            lambda: self.stackedWidget.setCurrentWidget(self.setting_page))
        self.setting_icon.clicked.connect(
            lambda: self.stackedWidget.setCurrentWidget(self.setting_page))

    def setup_graph(self):
        graph_container = self.findChild(QWidget, "graph_widget")
        if not graph_container:
            return
        self.live_graph = LiveGraph(self)
        layout = QVBoxLayout(graph_container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.live_graph)
        self.monitoring_controller.data_updated.connect(
            self.live_graph.update_graph, QtCore.Qt.QueuedConnection
        )

    def apply_home_fonts(self):
        tf = QtGui.QFont("Georgia", 11, QtGui.QFont.Bold)
        df = QtGui.QFont("Georgia", 9)
        for lbl in [self.label, self.label_3, self.label_13, self.label_15]:
            lbl.setFont(tf)
        for lbl in [self.label_2, self.label_10, self.label_14, self.label_16]:
            lbl.setFont(df)

    def apply_font_size(self, font_size):
        sizes = {"Small": 11, "Medium": 12, "Large": 13}
        font  = QtGui.QFont()
        font.setPointSize(sizes.get(font_size, 12))
        self.setFont(font)
        for w in self.findChildren(QWidget):
            w.setFont(font)

    def load_font_size(self):
        if not os.path.exists(CONFIG_FILE):
            return "Medium"
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f).get("font_size", "Medium")
        except (json.JSONDecodeError, FileNotFoundError):
            return "Medium"

    def load_settings(self):
        if not os.path.exists(CONFIG_FILE):
            return "Medium", "Medium", True, True
        try:
            with open(CONFIG_FILE, "r") as f:
                s = json.load(f)
                return (
                    s.get("font_size", "Medium"),
                    s.get("sensitivity", "Medium"),
                    bool(s.get("popup_notifications", True)),
                    bool(s.get("sound_alerts", True))
                )
        except (json.JSONDecodeError, FileNotFoundError):
            return "Medium", "Medium", True, True

    def save_settings(self):
        settings = {
            "font_size"           : self.current_font_size,
            "sensitivity"         : self.current_sensitivity,
            "popup_notifications" : self.popup_enabled,
            "sound_alerts"        : self.sound_enabled,
        }
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(settings, f)
        except Exception as e:
            print(f"Error saving settings: {e}")

    def closeEvent(self, event):
        if hasattr(self.monitoring_controller, "close"):
            self.monitoring_controller.close()
        event.accept()

    def show_page(self, index):
        self.stackedWidget.setCurrentIndex(index)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    window.showMaximized()
    sys.exit(app.exec_())