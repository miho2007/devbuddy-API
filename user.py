# user.py
import os
from enum import Enum
from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, Float, JSON, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt

DB_URL = f"postgresql://{os.environ['DB_USER']}:{os.environ['DB_PASSWORD']}@" \
         f"{os.environ['DB_HOST']}:{os.environ['DB_PORT']}/{os.environ['DB_NAME']}"

engine = create_engine(DB_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class AccountType(str, Enum):
    PRIVATE = "private"
    CORPORATE = "corporate"

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

    def set_password(self, plain_password: str):
        self.password = bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()

    def check_password(self, plain_password: str) -> bool:
        return bcrypt.checkpw(plain_password.encode(), self.password.encode())

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    stack: list[str] = []
    photo: str | None = None
    swipe_rate: float = 0.0
    wanted_stack: list[str] = []
    account_type: AccountType = AccountType.PRIVATE

class Token(BaseModel):
    access_token: str
    token_type: str

# Create tables
Base.metadata.create_all(bind=engine)
