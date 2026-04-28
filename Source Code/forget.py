import sys
import sqlite3
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, 
    QDialog, QDialogButtonBox, QMessageBox, QHBoxLayout, QRadioButton
)
from PyQt5.QtCore import Qt

# Database Setup
def initialize_database():
    """Ensures the user table exists in IDS.db"""
    connection = sqlite3.connect("IDS.db")
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            password TEXT
        )
    """)
    connection.commit()
    connection.close()

# Confirmation Dialog
class ConfirmDialog(QDialog):
    def __init__(self, parent=None, message="Confirm Changes?"):
        super().__init__(parent)
        self.setWindowTitle("Confirm Changes")
        self.setFixedSize(250, 120)
        self.setStyleSheet("background-color: #2C2F33; color: #FFFFFF; border-radius: 10px;")

        self.buttonBox = QDialogButtonBox(QDialogButtonBox.Yes | QDialogButtonBox.No)
        self.buttonBox.button(QDialogButtonBox.Yes).setStyleSheet("background-color: #4CAF50; color: white; padding: 5px; border-radius: 5px;")
        self.buttonBox.button(QDialogButtonBox.No).setStyleSheet("background-color: #F44336; color: white; padding: 5px; border-radius: 5px;")
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)

        layout = QVBoxLayout()
        label = QLabel(message)
        label.setStyleSheet("font-size: 16px; padding: 10px;")
        layout.addWidget(label, alignment=Qt.AlignCenter)
        layout.addWidget(self.buttonBox)
        self.setLayout(layout)

# Main Window
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Forgot Credentials")
        self.resize(500, 500)
        self.setStyleSheet("background-color: #23272A; color: #FFFFFF;")

        container = QWidget()
        self.setCentralWidget(container)
        mainLayout = QHBoxLayout()
        container.setLayout(mainLayout)

        centralWidget = QWidget()
        centralWidget.setFixedSize(600, 400)
        centralWidget.setStyleSheet("background-color: #2C2F33; border-radius: 10px; padding: 20px;")
        mainLayout.addWidget(centralWidget, alignment=Qt.AlignCenter)

        layout = QVBoxLayout()
        centralWidget.setLayout(layout)

        header = QLabel("Forgot Credentials?")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("font-size: 22px; font-weight: bold; padding-bottom: 15px;")
        layout.addWidget(header)

        # Options in Horizontal Layout
        options_layout = QHBoxLayout()
        self.radio_change_username = QRadioButton("Change Username")
        self.radio_change_password = QRadioButton("Reset Password")
        self.radio_change_username.setStyleSheet("color: white; font-size: 14px;")
        self.radio_change_password.setStyleSheet("color: white; font-size: 14px;")
        self.radio_change_password.setChecked(True)

        options_layout.addWidget(self.radio_change_username)
        options_layout.addWidget(self.radio_change_password)
        layout.addLayout(options_layout)

        self.usernameInput = QLineEdit()
        self.usernameInput.setPlaceholderText("Enter current username")
        self.usernameInput.setStyleSheet("padding: 8px; border: 1px solid #7289DA; border-radius: 5px; background-color: #2C2F33; color: white; margin-bottom: 10px;")
        layout.addWidget(self.usernameInput)

        self.newUsernameInput = QLineEdit()
        self.newUsernameInput.setPlaceholderText("Enter new username")
        self.newUsernameInput.setStyleSheet("padding: 8px; border: 1px solid #7289DA; border-radius: 5px; background-color: #2C2F33; color: white; margin-bottom: 10px;")
        self.newUsernameInput.hide()
        layout.addWidget(self.newUsernameInput)

        self.passwordInput = QLineEdit()
        self.passwordInput.setPlaceholderText("Enter new password")
        self.passwordInput.setEchoMode(QLineEdit.Password)
        self.passwordInput.setStyleSheet("padding: 8px; border: 1px solid #7289DA; border-radius: 5px; background-color: #2C2F33; color: white; margin-bottom: 10px;")
        layout.addWidget(self.passwordInput)

        self.confirmPasswordInput = QLineEdit()
        self.confirmPasswordInput.setPlaceholderText("Confirm new password")
        self.confirmPasswordInput.setEchoMode(QLineEdit.Password)
        self.confirmPasswordInput.setStyleSheet("padding: 8px; border: 1px solid #7289DA; border-radius: 5px; background-color: #2C2F33; color: white; margin-bottom: 20px;")
        layout.addWidget(self.confirmPasswordInput)

        saveButton = QPushButton("CONFIRM CHANGES")
        saveButton.setStyleSheet("padding: 10px; font-size: 16px; background-color: #7289DA; color: white; border-radius: 8px;")
        saveButton.clicked.connect(self.showConfirmDialog)
        layout.addWidget(saveButton, alignment=Qt.AlignCenter)

        self.radio_change_username.toggled.connect(self.toggle_fields)
        self.radio_change_password.toggled.connect(self.toggle_fields)

    def toggle_fields(self):
        """Toggles between changing username or password."""
        if self.radio_change_username.isChecked():
            self.newUsernameInput.show()
            self.passwordInput.hide()
            self.confirmPasswordInput.hide()
        else:
            self.newUsernameInput.hide()
            self.passwordInput.show()
            self.confirmPasswordInput.show()

    def showConfirmDialog(self):
        """Handles the confirmation dialog before saving changes."""
        dialog = ConfirmDialog(self, message="Are you sure?")
        if dialog.exec() == QDialog.Accepted:
            if self.radio_change_username.isChecked():
                self.changeUsername()
            else:
                self.updatePassword()
        else:
            QMessageBox.information(self, "Info", "Action cancelled.", QMessageBox.Ok)

    def changeUsername(self):
        """Updates the username in the database."""
        old_username = self.usernameInput.text().strip()
        new_username = self.newUsernameInput.text().strip()

        if not old_username or not new_username:
            QMessageBox.warning(self, "Error", "All fields are required.", QMessageBox.Ok)
            return

        connection = sqlite3.connect("IDS.db")
        cursor = connection.cursor()

        cursor.execute("SELECT * FROM user WHERE name = ?", (old_username,))
        user_exists = cursor.fetchone()

        if user_exists:
            cursor.execute("UPDATE user SET name = ? WHERE name = ?", (new_username, old_username))
            connection.commit()
            connection.close()
            QMessageBox.information(self, "Success", "Username changed successfully!", QMessageBox.Ok)
        else:
            connection.close()
            QMessageBox.warning(self, "Error", "Username not found!", QMessageBox.Ok)

    def updatePassword(self):
        """Updates the password in the database."""
        username = self.usernameInput.text().strip()
        new_password = self.passwordInput.text().strip()
        confirm_password = self.confirmPasswordInput.text().strip()

        if not username or not new_password or not confirm_password:
            QMessageBox.warning(self, "Error", "All fields are required.", QMessageBox.Ok)
            return

        if new_password != confirm_password:
            QMessageBox.warning(self, "Error", "Passwords do not match!", QMessageBox.Ok)
            return

        connection = sqlite3.connect("IDS.db")
        cursor = connection.cursor()

        cursor.execute("SELECT * FROM user WHERE name = ?", (username,))
        user_exists = cursor.fetchone()

        if user_exists:
            cursor.execute("UPDATE user SET password = ? WHERE name = ?", (new_password, username))
            connection.commit()
            connection.close()
            QMessageBox.information(self, "Success", "Password updated successfully!", QMessageBox.Ok)
        else:
            connection.close()
            QMessageBox.warning(self, "Error", "Username not found!", QMessageBox.Ok)

if __name__ == '__main__':
    initialize_database()
    app = QApplication(sys.argv)
    window = MainWindow()
    window.showMaximized()
    window.show()
    sys.exit(app.exec_())
