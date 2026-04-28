from PyQt5 import QtWidgets, QtGui, QtCore
import sqlite3
import os
from PyQt5.QtGui import QRegularExpressionValidator
from PyQt5.QtCore import QRegularExpression
from PyQt5.QtWidgets import QMessageBox

import re


class SignUpWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("AI Based IDPS - Sign Up")

        # Get screen size and set the window size accordingly
        screen = QtWidgets.QDesktopWidget().screenGeometry()
        self.setGeometry(0, 0, screen.width(), screen.height())

        # Background Image
        self.background_label = QtWidgets.QLabel(self)
        self.background_label.setPixmap(QtGui.QPixmap("mainscreen/background_su.jpg"))  # Replace with your image
        self.background_label.setScaledContents(True)

        opacity_effect = QtWidgets.QGraphicsOpacityEffect()
        opacity_effect.setOpacity(0.5)  # Transparency Level
        self.background_label.setGraphicsEffect(opacity_effect)

        # Main Header
        self.main_label = QtWidgets.QLabel("IDPS Signup", self)
        self.main_label.setFont(QtGui.QFont("Times New Roman", 30, QtGui.QFont.Bold))
        self.main_label.setStyleSheet("""
        color: white;
        font-family: Georgia;
        border-bottom: 2px solid black;
        padding-top: 100px;
        """)
        self.main_label.setAlignment(QtCore.Qt.AlignCenter)

        # Sign Up Container
        self.container = QtWidgets.QFrame(self)

        # Username
        self.username = QtWidgets.QLineEdit(self.container)
        self.username.setPlaceholderText("USERNAME")
        self.username.setStyleSheet("""
            QLineEdit{
                background: #ffffff;
                border: 3px solid #e5e5e5;
                border-radius: 12px;
                padding-left: 14px;
                padding-top: 8px;
                padding-bottom: 8px;
                font-size: 16px;
                font-family: "Times New Roman";
                font-weight: bold;
            }

            QLineEdit:focus{
                border: 3px solid #FFD43B;
            }
            """)
        # Password
        self.password = QtWidgets.QLineEdit(self.container)
        self.password.setPlaceholderText("PASSWORD")
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password.setStyleSheet("""
            QLineEdit{
                background: #ffffff;
                border: 3px solid #e5e5e5;
                border-radius: 12px;
                padding-left: 14px;
                padding-top: 8px;
                padding-bottom: 8px;
                font-size: 16px;
                font-family: "Times New Roman";
                font-weight: bold;
            }

            QLineEdit:focus{
                border: 3px solid #FFD43B;
            }
            """)
        # Confirm Password
        self.confirm_password = QtWidgets.QLineEdit(self.container)
        self.confirm_password.setPlaceholderText("CONFIRM PASSWORD")
        self.confirm_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.confirm_password.setStyleSheet("""
            QLineEdit{
                background: #ffffff;
                border: 3px solid #e5e5e5;
                border-radius: 12px;
                padding-left: 14px;
                padding-top: 8px;
                padding-bottom: 8px;
                font-size: 16px;
                font-family: "Times New Roman";
                font-weight: bold;
            }

            QLineEdit:focus{
                border: 3px solid #FFD43B;
            }
            """)
        # Sign Up Button
        self.signup_button = QtWidgets.QPushButton("SIGN UP", self.container)
        self.signup_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.signup_button.setStyleSheet("""
            QPushButton {
                background-color: #F5F5DC;
                color: black;
                border: 2px solid #E6C200;
                border-radius: 12px;
                padding: 10px 16px;
                font: bold 18px "Times New Roman";
            }

            QPushButton:hover {
                background-color: #FFE680;
                border: 2px solid #D4AF37;
            }

            QPushButton:pressed {
                background-color: #E6C200;
                border: 2px solid #B38F00;
                padding-top: 12px;
                padding-bottom: 8px;
            }
            """)
        self.signup_button.clicked.connect(self.create_account)

        # Already have an account
        self.already_account = QtWidgets.QLabel(self.container)

        self.already_account.setTextFormat(QtCore.Qt.RichText)
        self.already_account.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
        self.already_account.setOpenExternalLinks(False)
        self.already_account.setAlignment(QtCore.Qt.AlignCenter)

        self.already_account.setText('<a href="#" style="color:#F5F5DC; text-decoration:none;">Already have an account? Login</a>')

        self.already_account.setStyleSheet("""
            QLabel{
                font: bold 16px "Times New Roman";
                padding-left: 6px;
            }

            QLabel:hover{
                color:#FFD43B;
                text-decoration: underline;
            }
            """)

        self.already_account.linkActivated.connect(self.redirect_to_login)
        self.resizeUI()

    def resizeUI(self):
        width, height = self.width(), self.height()

        # Background Full-Screen
        self.background_label.setGeometry(0, 0, width, height)

        # Main Header at the Top
        self.main_label.setGeometry(int(width * 0.2), int(height * 0.1), int(width * 0.6), 200)

        # Centering Sign Up Container
        container_width, container_height = int(width * 0.3), int(height * 0.5)
        self.container.setGeometry(int((width - container_width) / 2), int(height * 0.3), container_width, container_height)

        # Adjust Child Widgets inside Container
        padding_x, padding_y = 30, 20
        input_width, input_height = container_width - 2 * padding_x, 40
        button_width, button_height = input_width, 50

        self.username.setGeometry(padding_x, 50, input_width, input_height)
        self.password.setGeometry(padding_x, 110, input_width, input_height)
        self.confirm_password.setGeometry(padding_x, 170, input_width, input_height)
        self.signup_button.setGeometry(padding_x, 230, button_width, button_height)
        self.already_account.setGeometry(padding_x, 290, button_width, button_height)

    def resizeEvent(self, event):
        self.resizeUI()

    def check_username_exists(self, username):
        conn = sqlite3.connect("IDS.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user WHERE name = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        return result is not None

    def create_account(self):
        username = self.username.text()
        password = self.password.text()
        confirm_password = self.confirm_password.text()

        username_pattern = r"^(?=.*[@#$%^&+=!])[A-Za-z][A-Za-z0-9@#$%^&+=!]{5,}$"

   
        password_pattern = r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@#$%^&+=!]{6,}$"


            # Validate Username
        if not re.match (username_pattern, username):
            QMessageBox.warning(self, "Invalid Username",
                    "Username must:\n"
                    "- Start with a letter\n"
                    "- Be at least 6 characters long\n"
                    "- Contain at least one special character (@#$%^&+=!)")
            return False

            # Validate Password
        if not re.match(password_pattern, password):
            QMessageBox.warning(self, "Invalid Password",
                    "Password must:\n"
                    "- Be at least 6 characters long\n"
                    "- Contain at least one letter\n"
                    "- Contain at least one number")
            return False
        
        if password != confirm_password:
            QtWidgets.QMessageBox.warning(self, "Error", "Passwords do not match!")
            return
        if password == "" or username =="" or confirm_password =="":
            QtWidgets.QMessageBox.warning(self, "Error", "Fill all the fields")
            return
        

        if self.check_username_exists(username):
            QtWidgets.QMessageBox.warning(self, "Error", "Username already exists!")
            return

        conn = sqlite3.connect("IDS.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO user (name, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()

        QtWidgets.QMessageBox.information(self, "Success", "Account created successfully!")
        self.redirect_to_login()

    def redirect_to_login(self):
        window.close()
        os.system("python mainscreen/login_page.py")

if __name__ == "__main__":
    app = QtWidgets.QApplication([])
    window = SignUpWindow()
    window.showMaximized()
    app.exec_()
