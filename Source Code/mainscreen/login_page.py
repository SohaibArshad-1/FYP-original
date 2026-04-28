from PyQt5 import QtWidgets, QtGui, QtCore
import sqlite3
import os
import session
from PyQt5.QtWidgets import QMessageBox
import re

class LoginWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("AI Based IDPS")

        # Get screen size and set the window size accordingly
        screen = QtWidgets.QDesktopWidget().screenGeometry()
        self.setGeometry(0, 0, screen.width(), screen.height())

        # Background Image
        self.background_label = QtWidgets.QLabel(self)
        self.background_label.setPixmap(QtGui.QPixmap("mainscreen/background.jpg"))  # Replace with your image
        self.background_label.setScaledContents(True)

        # opacity_effect = QtWidgets.QGraphicsOpacityEffect()
        # opacity_effect.setOpacity(2)  # Transparency Level
        # self.background_label.setGraphicsEffect(opacity_effect)


        # Main Header
        self.main_label = QtWidgets.QLabel("AI Based IDPS", self)
        self.main_label.setFont(QtGui.QFont("Times new roman", 30, QtGui.QFont.Bold))
        self.main_label.setStyleSheet("color: White; font-family: Georgia; border-bottom: 2px solid black; padding-top: 100px;")
        self.main_label.setAlignment(QtCore.Qt.AlignCenter)

        # Login Container
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
        # Login Button
        self.login_button = QtWidgets.QPushButton("LOGIN", self.container)
        self.login_button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.login_button.setStyleSheet("""
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
        self.login_button.clicked.connect(self.check_login)

        # Forgot Password Link
        self.forgot_password_label = QtWidgets.QLabel(self.container)

        self.forgot_password_label.setTextFormat(QtCore.Qt.RichText)
        self.forgot_password_label.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
        self.forgot_password_label.setOpenExternalLinks(False)
        self.forgot_password_label.setAlignment(QtCore.Qt.AlignCenter)

        self.forgot_password_label.setText('<a href="#" style="color:#F5F5DC; text-decoration:none;">Forgot Password?</a>')

        self.forgot_password_label.setStyleSheet("""
            QLabel{
                font: bold 16px "Times New Roman";
                padding-left: 6px;
            }

            QLabel:hover{
                color:#FFD43B;
                text-decoration: underline;
            }
            """)
        self.forgot_password_label.linkActivated.connect(self.forgot_password_clicked)

       
        # Signup Link
        self.signup_label = QtWidgets.QLabel(self.container)

        self.signup_label.setTextFormat(QtCore.Qt.RichText)
        self.signup_label.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
        self.signup_label.setOpenExternalLinks(False)
        self.signup_label.setAlignment(QtCore.Qt.AlignCenter)

        self.signup_label.setText('<a href="#" style="color:#F5F5DC; text-decoration:none;">Do not have an account?</a>')

        self.signup_label.setStyleSheet("""
            QLabel{
                font: bold 16px "Times New Roman";
                padding-left: 6px;
            }

            QLabel:hover{
                color:#FFD43B;
                text-decoration: underline;
            }
            """)

        self.signup_label.linkActivated.connect(self.signup_clicked)
        self.resizeUI()

    def resizeUI(self):
        """Adjusts the UI dynamically based on window size"""
        width, height = self.width(), self.height()

    # This makes the label always match the current window size
        self.background_label.setGeometry(0, 0, self.width(), self.height())
        

        # Main Header at the Top
        self.main_label.setGeometry(int(width * 0.2), int(height * 0.1), int(width * 0.6), 200)

        # Centering Login Container
        container_width, container_height = int(width * 0.3), int(height * 0.4)
        self.container.setGeometry(int((width - container_width) / 2), int(height * 0.3), container_width, container_height)

        # Adjust Child Widgets inside Container
        padding_x, padding_y = 30, 20
        input_width, input_height = container_width - 2 * padding_x, 40
        button_width, button_height = input_width, 50  

        self.username.setGeometry(padding_x, 50, input_width, input_height)
        self.password.setGeometry(padding_x, 110, input_width, input_height)
        self.login_button.setGeometry(padding_x, 170, button_width, button_height)
        self.forgot_password_label.setGeometry(padding_x, 225, button_width, button_height)
        self.signup_label.setGeometry(padding_x, 250, button_width, button_height)

    def resizeEvent(self, event):
        """Triggers UI update when window is resized"""
        self.resizeUI()

    def check_login(self):
        """Verify user login details"""
        username = self.username.text()
        password = self.password.text()

        if self.authenticate_user(username, password):
            """Validate input format and check username and password in the database"""

            username_pattern = r"^(?=.*[@#$%^&+=!])[A-Za-z][A-Za-z0-9@#$%^&+=!]{5,}$"

            password_pattern = r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@#$%^&+=!]{6,}$"
           
            # Validate Username
            if not re.match(username_pattern, username):
                QMessageBox.warning(self, "Error", "Invalid Username")
                return

            # Validate Password
            if not re.match(password_pattern, password):
                QMessageBox.warning(self, "Error", "Invalid Password")
                return 
            
        # ✅ Save session in the database
            conn = sqlite3.connect(os.path.join(os.getcwd(),"IDS.db"))
            cursor = conn.cursor()
            cursor.execute("DELETE FROM session")  # Clear old session
            cursor.execute("INSERT INTO session (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()

            print(f"Session Updated: {session.session.username}")

            self.open_main_dashboard()
        else:
            QtWidgets.QMessageBox.warning(self, "Login Failed", "Invalid username or password!")

    def authenticate_user(self, username, password):
        """Check username and password in the database"""
        conn = sqlite3.connect( "IDS.db")
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM user WHERE name = ? AND password = ?", (username, password))
        result = cursor.fetchone()
        conn.close()

        session.session.username = username
        session.session.password = password
        return result

    def open_main_dashboard(self):
        """Open the main IDPS dashboard"""
        self.close()
        os.system("python mainscreen/main_page.py")

    def forgot_password_clicked(self):
        os.system("python forget.py")

    def signup_clicked(self):
        self.close()
        os.system("python mainscreen/signup.py")

if __name__ == "__main__":
    app = QtWidgets.QApplication([])
    window = LoginWindow()
    window.showMaximized()
    app.exec_()
