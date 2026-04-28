"""
notifications.py  —  Notification & Prevention Log
────────────────────────────────────────────────────
Fixes applied:
  • Added full date + time to every card (was time-only)
  • Cards now use a larger min-height so all text is fully readable
  • Attack card shows attack type, protocol, service, bytes clearly
  • Prevention card shows action taken + prevention tips from DB
  • add_live_detection() is wired so it also fires when controller detects
  • No layout or widget names changed that touch the .ui file
"""

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QScrollArea, QTabWidget, QSizePolicy
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
import sys
import sqlite3


# ── Card builder ────────────────────────────────────────────────────────
def make_card(html_text, border_color="#457b9d"):
    label = QLabel(html_text)
    label.setStyleSheet(f"""
        background-color: #0d1b2a;
        padding: 14px 16px;
        border: 2px solid {border_color};
        border-radius: 10px;
        font-size: 13px;
        color: #f1faee;
        line-height: 1.6;
    """)
    label.setWordWrap(True)
    label.setTextFormat(Qt.RichText)
    label.setMinimumHeight(110)
    label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
    return label


# ── Notification Center ─────────────────────────────────────────────────
class NotificationCenter(QWidget):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Notifications")
        self.setStyleSheet("background-color: #1b263b; padding: 8px;")

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # ── Page header ────────────────────────────────────────────────
        header = QLabel("Notifications & Prevention Log")
        header.setFont(QFont("Georgia", 18, QFont.Bold))
        header.setStyleSheet("""
            color: #e63946;
            border-bottom: 2px solid #457b9d;
            padding-bottom: 6px;
        """)
        main_layout.addWidget(header)

        # ── Tab widget ─────────────────────────────────────────────────
        self.tabs = QTabWidget()
        self.tabs.setElideMode(Qt.ElideNone)          # never cut tab text
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #457b9d;
                background: #1b263b;
            }
            QTabBar {
                alignment: left;
            }
            QTabBar::tab {
                background: #0d1b2a;
                color: #a8dadc;
                padding: 10px 28px;
                min-width: 200px;
                font: bold 13px Georgia;
                border: 1px solid #457b9d;
                border-bottom: none;
                border-radius: 4px 4px 0 0;
            }
            QTabBar::tab:selected {
                background: #457b9d;
                color: white;
            }
        """)
        main_layout.addWidget(self.tabs)

        # Tab 1 — Attack Detections
        self.detection_scroll, self.detection_layout = self._make_scroll_tab()
        self.tabs.addTab(self.detection_scroll, "  Attack Detections")

        # Tab 2 — Prevention Actions
        self.prevention_scroll, self.prevention_layout = self._make_scroll_tab()
        self.tabs.addTab(self.prevention_scroll, "  Prevention Actions")

        # Load history from DB on startup
        self.load_detections()
        self.load_prevention()

    # ── Build a scrollable tab ─────────────────────────────────────────
    def _make_scroll_tab(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background: #1b263b; border: none;")

        from PyQt5.QtWidgets import QFrame
        frame = QFrame()
        frame.setStyleSheet("background: #1b263b;")
        layout = QVBoxLayout(frame)
        layout.setAlignment(Qt.AlignTop)
        layout.setSpacing(10)
        layout.setContentsMargins(6, 6, 6, 6)

        scroll.setWidget(frame)
        return scroll, layout

    # ── Load attack detections from DB ─────────────────────────────────
    def load_detections(self):
        try:
            conn = sqlite3.connect("IDS.db")
            cursor = conn.cursor()
            cursor.execute("""
                SELECT timestamp, prediction, protocol_type,
                       src_bytes, dst_bytes, service
                FROM detected_attacks
                ORDER BY timestamp DESC
            """)
            rows = cursor.fetchall()
            conn.close()
        except Exception as e:
            print(f"[NOTIFICATIONS] DB error: {e}")
            return

        if not rows:
            self.detection_layout.addWidget(
                make_card("<i>No attacks detected yet.</i>")
            )
            return

        for timestamp, attack_type, protocol, src_bytes, dst_bytes, service in rows:
            tips = self._get_tips(attack_type)
            self.add_detection_card(
                attack_type, timestamp, protocol,
                src_bytes, dst_bytes, service, tips
            )

    # ── Load prevention history from DB ───────────────────────────────
    def load_prevention(self):
        try:
            conn = sqlite3.connect("IDS.db")
            cursor = conn.cursor()
            cursor.execute("""
                SELECT ip_address, attack_type, action_taken,
                       blocked_at, unblock_at, is_active
                FROM blocked_ips
                ORDER BY blocked_at DESC
            """)
            rows = cursor.fetchall()
            conn.close()
        except Exception as e:
            print(f"[NOTIFICATIONS] DB error: {e}")
            return

        if not rows:
            self.prevention_layout.addWidget(
                make_card("<i>No prevention actions taken yet.</i>")
            )
            return

        for ip, attack_type, action, blocked_at, unblock_at, is_active in rows:
            tips = self._get_tips(attack_type)
            self.add_prevention_card(
                ip, attack_type, action,
                blocked_at, unblock_at, is_active, tips
            )

    # ── Prevention tips — hardcoded, no DB query needed ──────────────
    def _get_tips(self, attack_type):
        tips = {
            "DoS"  : ["Block source IP via firewall rule",
                      "Rate-limit ICMP/TCP SYN packets",
                      "Enable IPS blocking mode"],
            "Probe": ["Enable port-scan detection",
                      "Block IP after repeated connection failures",
                      "Close unused open ports"],
            "R2L"  : ["Enforce strong password policy",
                      "Disable anonymous FTP/Telnet access",
                      "Enable brute-force account lockout"],
            "U2R"  : ["Apply least-privilege principle",
                      "Monitor sudo/su usage in logs",
                      "Patch known privilege escalation CVEs"],
        }
        return tips.get(attack_type, ["Review network logs immediately"])

    # ── Add a single detection card ────────────────────────────────────
    def add_detection_card(self, attack_type, timestamp, protocol,
                           src_bytes, dst_bytes, service, tips=None):
        color_map = {
            "DoS"  : "#e63946",
            "Probe": "#f4a261",
            "R2L"  : "#e76f51",
            "U2R"  : "#9b2226",
        }
        color = color_map.get(attack_type, "#457b9d")

        if tips:
            tips_lines = "".join(f"&nbsp;&nbsp;• {t}<br>" for t in tips)
        else:
            # Hardcoded fallback so the section always appears
            fallback = {
                "DoS"  : ["Block source IP via firewall", "Rate-limit incoming connections"],
                "Probe": ["Disable unused ports", "Block scanning IP in firewall"],
                "R2L"  : ["Enforce strong passwords", "Disable anonymous FTP/Telnet"],
                "U2R"  : ["Check running processes immediately", "Review Windows Event Viewer"],
            }
            lines = fallback.get(attack_type, ["Review network logs immediately"])
            tips_lines = "".join(f"&nbsp;&nbsp;• {t}<br>" for t in lines)

        tips_html = (
            f"<br><span style='color:#a8dadc;'><b>🛡 Suggested Actions:</b></span><br>"
            f"<span style='color:#ccc; font-size:12px;'>{tips_lines}</span>"
        )

        html = (
            f"<span style='color:{color}; font-size:15px;'>"
            f"<b>⚠️ {attack_type} Attack Detected</b></span><br>"
            f"📅 <b>Date &amp; Time:</b> {timestamp}<br>"
            f"🔌 <b>Protocol:</b> {protocol or 'N/A'} &nbsp;|&nbsp; "
            f"🌐 <b>Service:</b> {service or 'N/A'}<br>"
            f"📥 <b>Src Bytes:</b> {src_bytes} &nbsp;|&nbsp; "
            f"📤 <b>Dst Bytes:</b> {dst_bytes}"
            f"{tips_html}"
        )
        card = make_card(html, border_color=color)
        self.detection_layout.insertWidget(0, card)

    # ── Add a single prevention card ──────────────────────────────────
    def add_prevention_card(self, ip, attack_type, action,
                            blocked_at, unblock_at, is_active, tips=None):
        action_icons = {
            "hard_block": "🚫",
            "soft_block": "⏱️",
            "port_block": "🔒",
            "log_only"  : "📋",
            "manual"    : "🔓",
        }
        status_colors = {
            1: "#e63946",
            0: "#2a9d8f",
        }
        icon         = action_icons.get(action, "🛡️")
        border_color = status_colors.get(is_active, "#457b9d")
        status_text  = "🔴 Active" if is_active else "🟢 Unblocked"

        unblock_line = (
            f"⏰ <b>Auto-unblock:</b> {unblock_at}<br>"
            if unblock_at else
            "⏰ <b>Duration:</b> Permanent<br>"
        )

        action_label = {
            "hard_block": "Hard Block (Permanent firewall rule)",
            "soft_block": "Soft Block (Temporary firewall rule)",
            "port_block": "Port Block",
            "log_only"  : "Logged Only — no firewall action taken",
            "manual"    : "Manually Unblocked by admin",
        }.get(action, action)

        tips_html = ""
        if tips:
            tips_lines = "".join(
                f"&nbsp;&nbsp;• {t}<br>" for t in tips
            )
            tips_html = (
                f"<br><span style='color:#a8dadc;'>"
                f"<b>📌 Prevention Tips:</b></span><br>"
                f"<span style='color:#ccc; font-size:12px;'>{tips_lines}</span>"
            )

        html = (
            f"<span style='font-size:15px;'>"
            f"<b>{icon} {attack_type} — Prevention Action</b></span><br>"
            f"🌐 <b>IP Address:</b> {ip}<br>"
            f"🛡️ <b>Action Taken:</b> {action_label}<br>"
            f"📅 <b>Blocked At:</b> {blocked_at}<br>"
            f"{unblock_line}"
            f"📊 <b>Status:</b> {status_text}"
            f"{tips_html}"
        )
        card = make_card(html, border_color=border_color)
        self.prevention_layout.insertWidget(0, card)

    # ── Live update from PreventionEngine signal ───────────────────────
    def add_live_prevention(self, message, attack_type, ip_address):
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if "HARD BLOCKED"   in message: action = "hard_block"
        elif "SOFT BLOCKED" in message: action = "soft_block"
        elif "UNBLOCKED"    in message: action = "manual"
        else:                           action = "log_only"

        is_active  = 0 if "UNBLOCKED" in message else 1
        unblock_at = None
        tips       = self._get_tips(attack_type)

        self.add_prevention_card(
            ip_address, attack_type, action,
            timestamp, unblock_at, is_active, tips
        )
        self.tabs.setCurrentIndex(1)

    # ── Live update from monitoring when attack detected ───────────────
    def add_live_detection(self, attack_type, protocol,
                           src_bytes, dst_bytes, service):
        from datetime import datetime
        # Full date + time so it matches DB-loaded cards
        timestamp = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        tips = self._get_tips(attack_type)
        self.add_detection_card(
            attack_type, timestamp, protocol,
            src_bytes, dst_bytes, service, tips
        )
        self.tabs.setCurrentIndex(0)


# ── Main ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NotificationCenter()
    window.show()
    sys.exit(app.exec_())