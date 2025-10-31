# user.py
import bcrypt
from sqlalchemy import Column, Integer, String, Float, JSON
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    stack = Column(JSON)
    wanted_stack = Column(JSON)
    photo = Column(String, nullable=True)
    swipe_rate = Column(Float, default=0.0)
    account_type = Column(String)

    # Hash password before saving
    def set_password(self, plain_password: str):
        hashed_pw = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt())
        self.password = hashed_pw.decode("utf-8")

    # Check password
    def check_password(self, plain_password: str) -> bool:
        return bcrypt.checkpw(plain_password.encode("utf-8"), self.password.encode("utf-8"))
