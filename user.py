# main.py
import os
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from enum import Enum
from sqlalchemy import Column, Integer, String, Float, JSON, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import jwt
import bcrypt

# -----------------------------
# Environment Variables / DB
# -----------------------------
DB_URL = f"postgresql://{os.environ['DB_USER']}:{os.environ['DB_PASSWORD']}@" \
         f"{os.environ['DB_HOST']}:{os.environ['DB_PORT']}/{os.environ['DB_NAME']}"

engine = create_engine(DB_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# -----------------------------
# JWT Settings
# -----------------------------
SECRET_KEY = "your-secret-key"  # Change this to a secure random key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# -----------------------------
# Models
# -----------------------------
class AccountType(str, Enum):
    PRIVATE = "private"
    CORPORATE = "corporate"

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

# SQLAlchemy User model
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

    def check_password(self, plain_password: str):
        return bcrypt.checkpw(plain_password.encode(), self.password.encode())

# Create tables
Base.metadata.create_all(bind=engine)

# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# -----------------------------
# Helper functions
# -----------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str, db: Session):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# -----------------------------
# Routes
# -----------------------------
@app.post("/users/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_pw = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt()).decode()
    new_user = User(
        email=user.email,
        password=hashed_pw,
        stack=user.stack,
        wanted_stack=user.wanted_stack,
        photo=user.photo,
        swipe_rate=user.swipe_rate,
        account_type=user.account_type.value
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully", "email": new_user.email}

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not user.check_password(form_data.password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/profile")
def read_profile(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user = verify_token(token, db)
    return {
        "email": user.email,
        "stack": user.stack,
        "wanted_stack": user.wanted_stack,
        "photo": user.photo,
        "swipe_rate": user.swipe_rate,
        "account_type": user.account_type
    }

@app.get("/")
def home():
    return {"message": "FastAPI User Service with JWT + Postgres is running 🚀"}
