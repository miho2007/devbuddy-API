from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from enum import Enum
from user import User  # ← import your User class from user.py

app = FastAPI()

# -----------------------------
# Pydantic model for validation
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

# -----------------------------
# In-memory "database"
# -----------------------------
users_db = {}

# -----------------------------
# Routes
# -----------------------------
@app.post("/users/register")
def register_user(user: UserCreate):
    """Register a new user"""
    if user.email in users_db:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        email=user.email,
        password=user.password,
        stack=user.stack,
        photo=user.photo,
        swipe_rate=user.swipe_rate,
        wanted_stack=user.wanted_stack,
        account_type=user.account_type
    )

    users_db[user.email] = new_user
    return {"message": "User created successfully", "email": user.email}


@app.post("/users/login")
def login_user(email: EmailStr, password: str):
    """Authenticate user by email and password"""
    user = users_db.get(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.check_password(password):
        raise HTTPException(status_code=401, detail="Invalid password")

    return {"message": "Login successful", "email": email}

# -----------------------------
# Test endpoint
# -----------------------------
@app.get("/")
def home():
    return {"message": "FastAPI User Service is running 🚀"}
