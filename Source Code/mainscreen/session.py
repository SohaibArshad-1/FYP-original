# session.py
class Session:
    def __init__(self):
        self.username = None
        self.password = None  # Optional, but storing passwords in memory is insecure!

session = Session()  # Global session instance
