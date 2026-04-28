import os
import json
from PyQt5 import QtWidgets, QtGui, QtCore
import sys
import session
import sqlite3

conn = sqlite3.connect("IDS.db")
cursor = conn.cursor()
cursor.execute("SELECT username, password FROM session")
row = cursor.fetchone()
conn.close()

if row:
    session.session.username = row[0]
    session.session.password = row[1]
else:
    session.session.username = None
    session.session.password = None

print(f"Loaded Session: {session.session.username}, {session.session.password}")  # Debugging
CONFIG_FILE = "config.txt"

class SettingsPage(QtWidgets.QWidget):
    font_size_changed = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Settings")
        self.setGeometry(100, 100, 1000, 700)

        # Define default values BEFORE calling load_settings()
        self.current_font_size = "Medium"  
        self.current_sensitivity = "Medium"
        self.popup_enabled = True
        self.sound_enabled = True

        # Load settings
        self.current_font_size, self.current_sensitivity, self.popup_enabled, self.sound_enabled = self.load_settings()

        self.initUI()

        self.popup_toggle.setChecked(self.popup_enabled)
        self.sound_toggle.setChecked(self.sound_enabled)

        
        self.apply_font_size(self.current_font_size)

    def initUI(self):
        main_layout = QtWidgets.QVBoxLayout(self)
        
        # **Scroll Area Setup (Full Page Height)**
        self.scroll = QtWidgets.QScrollArea(self)
        self.scroll.setWidgetResizable(True)  
        self.scroll.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)  
        self.scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)  
        self.scroll.verticalScrollBar().setStyleSheet("width: 15px;")  # Wider scrollbar

        # **Main Container (Inside Scroll)**
        self.container = QtWidgets.QFrame()
        self.container.setStyleSheet("background: white; border-radius: 12px; padding: 30px;")
        self.container.setMinimumWidth(800)  # Adjust width, but height is flexible

        container_layout = QtWidgets.QVBoxLayout(self.container)

        # **Username & Password**
        info_layout = QtWidgets.QFormLayout()
        username_label = QtWidgets.QLabel("Username:")
        username_label.setStyleSheet("font-weight: bold; ")
        self.username_display = QtWidgets.QLabel(f"{session.session.username}")

        password_label = QtWidgets.QLabel("Password:")
        password_label.setStyleSheet("font-weight: bold;")
        # Password Field (QLineEdit instead of QLabel)
        self.password_display = QtWidgets.QLineEdit()
        self.password_display.setText(session.session.password)
        self.password_display.setEchoMode(QtWidgets.QLineEdit.Password)  # Hide password by default
        self.password_display.setReadOnly(True)  # Prevent editing

        # Toggle Password Button
        self.toggle_button = QtWidgets.QPushButton("👁")
        self.toggle_button.setCheckable(True)
        self.toggle_button.setFixedSize(30, 30)  # Adjust button size
        self.toggle_button.clicked.connect(self.toggle_password_visibility)

        # Create a horizontal layout for password and toggle button
        info_layout.addRow(username_label, self.username_display)
        password_layout = QtWidgets.QHBoxLayout()
        password_layout.addWidget(self.password_display)
        password_layout.addWidget(self.toggle_button)
        info_layout.addRow(password_label, password_layout)  # Password with button


        # **Forgot Password**
        self.forgot_password_label = QtWidgets.QLabel("<a href='#'>Update username/password?</a>", self.container)
        self.forgot_password_label.setStyleSheet("""
            QLabel {
                font-size: 16px;
                padding: 5px;
            }
            QLabel::link {
                color: #007BFF;           /* Normal link color */
                text-decoration: none;     /* Remove underline if you want */
            }
            QLabel::link:hover {
                color: #FF4500;            /* Hover color */
            }
            """)
        self.forgot_password_label.setAlignment(QtCore.Qt.AlignCenter)
        self.forgot_password_label.linkActivated.connect(self.forgot_password_clicked)

        # **Dropdown for Font Size**
        font_layout = QtWidgets.QHBoxLayout()
        self.font_size = QtWidgets.QComboBox()
        self.font_size.addItems(["Small", "Medium", "Large"])
        self.font_size.setCurrentText(self.current_font_size)
        self.font_size.currentTextChanged.connect(self.onFontSizeChanged)

        font_label = QtWidgets.QLabel("Font Size:")
        font_layout.addWidget(font_label)
        font_layout.addWidget(self.font_size)

        # **Dropdown for Threat Sensitivity**
        sensitivity_layout = QtWidgets.QHBoxLayout()
        self.sensitivity_dropdown = QtWidgets.QComboBox()
        self.sensitivity_dropdown.addItems(["Low", "Medium", "High"])
        self.sensitivity_dropdown.setCurrentText(self.current_sensitivity)
        self.sensitivity_dropdown.currentTextChanged.connect(self.onSensitivityChanged)

        sensitivity_label = QtWidgets.QLabel("Threat Sensitivity:")
        sensitivity_layout.addWidget(sensitivity_label)
        sensitivity_layout.addWidget(self.sensitivity_dropdown)

        # **Toggles**
        self.popup_toggle = QtWidgets.QCheckBox("Enable Pop-up Notifications")
        self.popup_toggle.setChecked(self.popup_enabled)  # Ensure checkbox reflects saved state
        self.popup_toggle.stateChanged.connect(self.save_settings)  # Save when changed

        self.sound_toggle = QtWidgets.QCheckBox("Enable Sound Alerts")
        self.sound_toggle.setChecked(self.sound_enabled)
        self.sound_toggle.stateChanged.connect(self.save_settings)

        # **Buttons**
        buttons_layout = QtWidgets.QHBoxLayout()
        self.clear_logs_btn = QtWidgets.QPushButton("Clear Logs")
        self.styleButton(self.clear_logs_btn, is_primary=False)
        self.clear_logs_btn.clicked.connect(self.clearLogs)

        self.about_btn = QtWidgets.QPushButton("About")
        self.styleButton(self.about_btn)
        self.about_btn.clicked.connect(self.showAbout)

        buttons_layout.addWidget(self.clear_logs_btn)
        buttons_layout.addWidget(self.about_btn)

        # **Restart Notice Label**
        self.restart_label = QtWidgets.QLabel("**Restart to Save Changes**")
        self.restart_label.setStyleSheet("font-size: 16px; font-weight: bold; color: red;")
        self.restart_label.setAlignment(QtCore.Qt.AlignCenter)
        
        # **Add All Elements**
        container_layout.addLayout(info_layout)
        container_layout.addWidget(self.forgot_password_label)
        container_layout.addLayout(font_layout)
        container_layout.addLayout(sensitivity_layout)
        container_layout.addWidget(self.popup_toggle)
        self.popup_toggle.setChecked(True)
        container_layout.addWidget(self.sound_toggle)
        self.sound_toggle.setChecked(True)
        container_layout.addLayout(buttons_layout)
        container_layout.addWidget(self.restart_label)

        # **Set Container as Scrollable Widget**
        self.scroll.setWidget(self.container)

        # **Add Scroll to Layout**
        main_layout.addWidget(self.scroll)

    def toggle_password_visibility(self):
        """Toggle password visibility between hidden and shown."""
        if self.toggle_button.isChecked():
            self.password_display.setEchoMode(QtWidgets.QLineEdit.Normal)  # Show password
            self.toggle_button.setText("🙈")  # Hide icon
        else:
            self.password_display.setEchoMode(QtWidgets.QLineEdit.Password)  # Hide password
            self.toggle_button.setText("👁")  # Show icon



    def onFontSizeChanged(self, font_size):
        self.current_font_size = font_size
        self.apply_font_size(font_size)
        self.save_settings()
        self.font_size_changed.emit(font_size)

    def onSensitivityChanged(self, sensitivity):
        self.current_sensitivity = sensitivity
        self.save_settings()

    def apply_font_size(self, font_size):
        font_sizes = {"Small": 11, "Medium": 12, "Large": 13}
        font = QtGui.QFont()
        font.setPointSize(font_sizes.get(font_size, 14))

        self.setFont(font)
        for widget in self.findChildren(QtWidgets.QWidget):
            widget.setFont(font)

    def save_settings(self):
        """Save all settings to config.txt"""
        settings = {
            "font_size": self.current_font_size,
            "sensitivity": self.current_sensitivity,
            "popup_notifications": self.popup_toggle.isChecked(),
            "sound_alerts": self.sound_toggle.isChecked()
            }
        try:
            with open(CONFIG_FILE, "w") as file:
                json.dump(settings, file)
        except Exception as e:
            print(f"Error saving settings: {e}")

    def load_settings(self):
        """Load settings from config.txt or set defaults if missing"""
        if not os.path.exists(CONFIG_FILE):
            self.save_settings()  # Create config file if it doesn’t exist
            return "Medium", "Medium", True, True  # Default values

        try:
            with open(CONFIG_FILE, "r") as file:
                settings = json.load(file)
                return (
                    settings.get("font_size", "Medium"),
                    settings.get("sensitivity", "Medium"),
                    bool(settings.get("popup_notifications", True)),
                    bool(settings.get("sound_alerts", True))
                )
        except (json.JSONDecodeError, FileNotFoundError):
            return "Medium", "Medium", True, True
    
    def forgot_password_clicked(self):
        os.system("python forget.py")

    def clearLogs(self):
        try:
            conn = sqlite3.connect("IDS.db")
            cursor = conn.cursor()

            # Delete all records from detected_attacks table
            cursor.execute("DELETE FROM detected_attacks")
            conn.commit()
            conn.close()

            QtWidgets.QMessageBox.information(self, "Logs", "All detected attacks have been cleared!")

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Failed to clear logs: {e}")


    def showAbout(self):
        QtWidgets.QMessageBox.information(self, "About", "We infer that a change in detection and prevention of cybercrime needs to start at the system level and use more intelligent methods of attack detection and prevention such as “Neural Networks and Artificial Intelligence”.\nOur goal is to create IDS that addresses vulnerable attacks and focuses on the study of different intrusion detection mechanisms that can alert network administrators by detecting all known attacks. AI-based Intrusion Detection Systems (IDS) for personal networks are designed to protect home or small office environments, which typically have fewer devices and less traffic than large enterprise networks.")

    def styleButton(self, button, is_primary=True):
        button.setCursor(QtCore.Qt.PointingHandCursor)
        button.setStyleSheet(f"""
            QPushButton {{
                background-color: {"#007BFF" if is_primary else "#6c757d"};
                color: white;
                font-weight: bold;
                border-radius: 8px;
                padding: 10px;
            }}
            QPushButton:hover {{ background-color: {"#0056b3" if is_primary else "#5a6268"}; }}
        """)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = SettingsPage()
    window.show()
    sys.exit(app.exec_())
