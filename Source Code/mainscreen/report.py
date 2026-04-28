"""
report.py  —  Attack Reports Page
────────────────────────────────────────────────────
Fixes applied:
  • Added 'Prevention Taken' column to both Excel and PDF exports
  • PDF layout improved — wraps long text, proper columns
  • Time filter (Daily / Weekly / Monthly) now actually filters rows
  • No widget names or layouts changed that would affect the .ui file
"""

from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QComboBox,
    QFrame, QGridLayout, QPushButton, QHBoxLayout, QMessageBox
)
from PyQt5.QtCore import Qt, QPropertyAnimation
from PyQt5.QtGui import QFont
import sys
import os
import pandas as pd
import sqlite3
import datetime

from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch


class ReportsPage(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Attack Reports")
        self.setStyleSheet("background-color: #0b1d2a;")

        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)

        # Header
        header = QLabel("Attack Reports")
        header.setAlignment(Qt.AlignCenter)
        header.setFont(QFont("Georgia", 28, QFont.Bold))
        header.setStyleSheet("""
            color: #e63946;
            border-bottom: 2px solid #457b9d;
            padding: 10px;
        """)
        main_layout.addWidget(header)

        # Main Card
        container = QFrame()
        container.setFixedWidth(520)
        container.setStyleSheet("""
            QFrame {
                background-color: #112b3c;
                border-radius: 15px;
                border: 2px solid #457b9d;
                padding: 25px;
            }
        """)

        layout = QGridLayout(container)
        layout.setVerticalSpacing(20)

        label_font = QFont("Georgia", 14, QFont.Bold)

        type_label   = QLabel("Attack Type")
        time_label   = QLabel("Time Range")
        format_label = QLabel("Export Format")

        for lbl in [type_label, time_label, format_label]:
            lbl.setFont(label_font)
            lbl.setStyleSheet("color: #e63946;")

        dropdown_style = """
        QComboBox {
            background-color: #0b1d2a;
            color: white;
            border: 2px solid #457b9d;
            border-radius: 8px;
            padding: 8px;
            font: 14px Georgia;
            min-width: 180px;
        }
        QComboBox:hover { border: 2px solid #e63946; }
        QComboBox QAbstractItemView {
            background-color: #0b1d2a;
            color: white;
            selection-background-color: #457b9d;
        }
        """

        self.type_dropdown = QComboBox()
        self.type_dropdown.addItems(["ALL", "DoS", "Probe", "U2R", "R2L"])

        self.time_dropdown = QComboBox()
        self.time_dropdown.addItems(["All Time", "Daily", "Weekly", "Monthly"])

        self.format_dropdown = QComboBox()
        self.format_dropdown.addItems(["Excel", "PDF"])

        for box in [self.type_dropdown, self.time_dropdown, self.format_dropdown]:
            box.setStyleSheet(dropdown_style)
            box.setMinimumHeight(38)

        self.generate_button = QPushButton("Generate Report")
        self.generate_button.setFont(QFont("Georgia", 14, QFont.Bold))
        self.generate_button.setStyleSheet("""
            QPushButton {
                background-color: #e63946;
                color: white;
                border-radius: 10px;
                padding: 10px;
            }
            QPushButton:hover { background-color: #457b9d; }
        """)
        self.generate_button.clicked.connect(self.generate_report)

        layout.addWidget(type_label,           0, 0)
        layout.addWidget(self.type_dropdown,   0, 1)
        layout.addWidget(time_label,           1, 0)
        layout.addWidget(self.time_dropdown,   1, 1)
        layout.addWidget(format_label,         2, 0)
        layout.addWidget(self.format_dropdown, 2, 1)
        layout.addWidget(self.generate_button, 3, 0, 1, 2)

        main_layout.addWidget(container)

        self.fade_animation(container)

    # ── Animation ──────────────────────────────────────────────────────
    def fade_animation(self, widget):
        self.anim = QPropertyAnimation(widget, b"windowOpacity")
        self.anim.setDuration(800)
        self.anim.setStartValue(0)
        self.anim.setEndValue(1)
        self.anim.start()

    def show_message(self, title, message):
        msg = QMessageBox()
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.exec_()

    # ── Fetch data with filters ─────────────────────────────────────────
    def fetch_data(self):
        conn = sqlite3.connect("IDS.db")

        # Main attack data
        df = pd.read_sql_query("""
            SELECT timestamp, prediction, protocol_type,
                   service, src_bytes, dst_bytes,
                   count, srv_count
            FROM detected_attacks
        """, conn)

        # Prevention data — join by attack type to get action taken
        prev_df = pd.read_sql_query("""
            SELECT attack_type, action_taken, ip_address,
                   blocked_at, is_active
            FROM blocked_ips
            ORDER BY blocked_at DESC
        """, conn)
        conn.close()

        if df.empty:
            return None, "No attack records found in database."

        # Rename for display
        df.rename(columns={
            "timestamp"    : "Timestamp",
            "prediction"   : "Attack Type",
            "protocol_type": "Protocol",
            "service"      : "Service",
            "src_bytes"    : "Src Bytes",
            "dst_bytes"    : "Dst Bytes",
            "count"        : "Conn Count",
            "srv_count"    : "Srv Count",
        }, inplace=True)

        # ── Time filter ───────────────────────────────────────────────
        time_range = self.time_dropdown.currentText()
        if time_range != "All Time":
            try:
                df["_ts"] = pd.to_datetime(df["Timestamp"], errors="coerce")
                now = datetime.datetime.now()
                if time_range == "Daily":
                    cutoff = now - datetime.timedelta(days=1)
                elif time_range == "Weekly":
                    cutoff = now - datetime.timedelta(weeks=1)
                elif time_range == "Monthly":
                    cutoff = now - datetime.timedelta(days=30)
                df = df[df["_ts"] >= cutoff]
                df.drop(columns=["_ts"], inplace=True)
            except Exception as e:
                print(f"[REPORT] Time filter error: {e}")

        # ── Attack type filter ────────────────────────────────────────
        attack_filter = self.type_dropdown.currentText()
        if attack_filter != "ALL":
            df = df[df["Attack Type"].str.lower() == attack_filter.lower()]

        if df.empty:
            return None, f"No records found for the selected filters."

        # ── Add Prevention Taken column ───────────────────────────────
        action_label_map = {
            "hard_block": "Hard Block (Permanent)",
            "soft_block": "Soft Block (Temporary)",
            "port_block": "Port Block",
            "log_only"  : "Logged Only",
            "manual"    : "Manually Unblocked",
        }

        def get_prevention(attack_type):
            match = prev_df[
                prev_df["attack_type"].str.lower() == attack_type.lower()
            ]
            if match.empty:
                return "None recorded"
            action = match.iloc[0]["action_taken"]
            return action_label_map.get(action, action)

        df["Prevention Taken"] = df["Attack Type"].apply(get_prevention)

        return df, None

    # ── Excel export ───────────────────────────────────────────────────
    def generate_excel(self, df):
        output_path = "attack_report.xlsx"
        try:
            with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
                df.to_excel(writer, index=False, sheet_name="Attack Report")

                ws = writer.sheets["Attack Report"]
                # Auto-width columns
                for col in ws.columns:
                    max_len = max(len(str(cell.value or "")) for cell in col)
                    ws.column_dimensions[col[0].column_letter].width = min(max_len + 4, 40)

            self.show_message("Success",
                              f"Excel report saved as:\n{os.path.abspath(output_path)}")
        except Exception as e:
            self.show_message("Error", f"Failed to generate Excel:\n{e}")

    # ── PDF export ─────────────────────────────────────────────────────
    def generate_pdf(self, df):
        output_path = "attack_report.pdf"
        try:
            doc = SimpleDocTemplate(
                output_path,
                pagesize=landscape(letter),
                leftMargin=0.4*inch, rightMargin=0.4*inch,
                topMargin=0.5*inch,  bottomMargin=0.5*inch,
            )

            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                "title", parent=styles["Heading1"],
                fontSize=16, textColor=colors.HexColor("#e63946"),
                spaceAfter=12, alignment=1
            )
            cell_style = ParagraphStyle(
                "cell", parent=styles["Normal"],
                fontSize=8, leading=11
            )

            elements = []
            elements.append(Paragraph("AI-Based IDPS — Attack Report", title_style))

            from datetime import datetime as dt
            generated = dt.now().strftime("%Y-%m-%d %H:%M:%S")
            elements.append(Paragraph(
                f"Generated: {generated} &nbsp;|&nbsp; "
                f"Filter: {self.type_dropdown.currentText()} / "
                f"{self.time_dropdown.currentText()}",
                styles["Normal"]
            ))
            elements.append(Spacer(1, 0.15*inch))

            # Build table data
            cols = list(df.columns)
            header_row = [Paragraph(f"<b>{c}</b>", cell_style) for c in cols]
            data_rows  = [header_row]

            for _, row in df.iterrows():
                data_rows.append([
                    Paragraph(str(row[c]), cell_style) for c in cols
                ])

            col_widths = []
            available  = 9.7 * inch
            # Distribute widths roughly by content type
            weight_map = {
                "Timestamp"       : 2.2,
                "Attack Type"     : 1.0,
                "Protocol"        : 0.8,
                "Service"         : 0.9,
                "Src Bytes"       : 0.8,
                "Dst Bytes"       : 0.8,
                "Conn Count"      : 0.8,
                "Srv Count"       : 0.8,
                "Prevention Taken": 1.9,
            }
            total_w = sum(weight_map.get(c, 1.0) for c in cols)
            for c in cols:
                col_widths.append(available * weight_map.get(c, 1.0) / total_w)

            tbl = Table(data_rows, colWidths=col_widths, repeatRows=1)
            tbl.setStyle(TableStyle([
                ("BACKGROUND",  (0, 0), (-1, 0),  colors.HexColor("#112b3c")),
                ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.HexColor("#a8dadc")),
                ("GRID",        (0, 0), (-1, -1), 0.4, colors.HexColor("#457b9d")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.HexColor("#0b1d2a"), colors.HexColor("#0f2233")]),
                ("TEXTCOLOR",   (0, 1), (-1, -1),  colors.white),
                ("FONTSIZE",    (0, 0), (-1, -1),  8),
                ("TOPPADDING",  (0, 0), (-1, -1),  4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN",      (0, 0), (-1, -1),  "TOP"),
            ]))
            elements.append(tbl)
            doc.build(elements)
            self.show_message("Success",
                              f"PDF report saved as:\n{os.path.abspath(output_path)}")
        except Exception as e:
            self.show_message("Error", f"Failed to generate PDF:\n{e}")

    # ── Entry point ────────────────────────────────────────────────────
    def generate_report(self):
        df, error = self.fetch_data()
        if error:
            self.show_message("No Data", error)
            return

        if self.format_dropdown.currentText() == "Excel":
            self.generate_excel(df)
        else:
            self.generate_pdf(df)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ReportsPage()
    window.show()
    sys.exit(app.exec_())
