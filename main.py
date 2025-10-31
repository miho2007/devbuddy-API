from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import jwt
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware

from user import User, UserCreate, Token, AccountType, SessionLocal  # ✅ correct import

# FastAPI & CORS
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

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
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

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

@app.post("/users/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    new_user = User(
        email=user.email,
        stack=user.stack,
        wanted_stack=user.wanted_stack,
        photo=user.photo,
        swipe_rate=user.swipe_rate,
        account_type=user.account_type.value
    )
    new_user.set_password(user.password)
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
