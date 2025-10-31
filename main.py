from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from enum import Enum
from user import User
import jwt
from datetime import datetime, timedelta

app = FastAPI()

# -----------------------------
# Secret key & JWT settings
# -----------------------------
SECRET_KEY = "your-secret-key"  # change this to something random & secure
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# -----------------------------
# Pydantic models
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

# -----------------------------
# In-memory DB
# -----------------------------
users_db = {}

# -----------------------------
# OAuth2
# -----------------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# -----------------------------
# Helper functions
# -----------------------------
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return users_db.get(email)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# -----------------------------
# Routes
# -----------------------------
@app.post("/users/register")
def register_user(user: UserCreate):
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


@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or not user.check_password(form_data.password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/profile")
def read_profile(token: str = Depends(oauth2_scheme)):
    user = verify_token(token)
    return {
        "email": user.email,
        "stack": user.stack,
        "wanted_stack": user.wanted_stack,
        "photo": user.photo,
        "swipe_rate": user.swipe_rate,
        "account_type": user.account_type.value
    }

# -----------------------------
# Test endpoint
# -----------------------------
@app.get("/")
def home():
    return {"message": "FastAPI User Service with JWT is running 🚀"}
