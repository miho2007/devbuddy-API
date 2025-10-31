# user.py
from enum import Enum
import bcrypt

class AccountType(Enum):
    PRIVATE = "private"
    CORPORATE = "corporate"

class User:
    def __init__(self, email, password, stack=None, photo=None,
                 swipe_rate=0, wanted_stack=None, account_type=AccountType.PRIVATE):
        self.email = email
        self.password = self.hash_password(password)
        self.stack = stack if stack is not None else []
        self.photo = photo
        self.swipe_rate = swipe_rate
        self.wanted_stack = wanted_stack if wanted_stack is not None else []
        self.account_type = account_type

    def hash_password(self, password: str) -> bytes:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def check_password(self, password: str) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), self.password)
