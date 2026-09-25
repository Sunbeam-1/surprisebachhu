import os
from datetime import datetime, timedelta, timezone
from typing import Annotated
import jwt
from fastapi import Cookie, Depends, FastAPI, HTTPException, Response, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pwdlib import PasswordHash
from pydantic import BaseModel

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is required")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "15"))
REFRESH_TOKEN_DAYS = int(os.getenv("REFRESH_TOKEN_DAYS", "7"))
ALGORITHM = "HS256"
app = FastAPI(title="Surprise Bachhu Auth API")
password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
users: dict[str, dict] = {}

class RegisterRequest(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    email: str

def create_token(subject: str, token_type: str, lifetime: timedelta) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": subject, "type": token_type, "iat": now, "exp": now + lifetime}, JWT_SECRET, algorithm=ALGORITHM)

def decode_token(token: str, expected_type: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        if payload.get("type") != expected_type or not payload.get("sub"):
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload["sub"]
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> dict:
    email = decode_token(token, "access")
    if email not in users:
        raise HTTPException(status_code=401, detail="User not found")
    return users[email]

@app.post("/auth/register", response_model=UserResponse, status_code=201)
def register(data: RegisterRequest):
    email = data.email.strip().lower()
    if not email or len(data.password) < 8:
        raise HTTPException(status_code=400, detail="Valid email and password (8+ chars) required")
    if email in users:
        raise HTTPException(status_code=409, detail="Account already exists")
    users[email] = {"email": email, "password_hash": password_hash.hash(data.password)}
    return {"email": email}

@app.post("/auth/login")
def login(response: Response, form: Annotated[OAuth2PasswordRequestForm, Depends()]):
    email = form.username.strip().lower()
    user = users.get(email)
    if not user or not password_hash.verify(form.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token = create_token(email, "access", timedelta(minutes=ACCESS_TOKEN_MINUTES))
    refresh_token = create_token(email, "refresh", timedelta(days=REFRESH_TOKEN_DAYS))
    response.set_cookie("refresh_token", refresh_token, httponly=True, secure=True, samesite="lax", max_age=REFRESH_TOKEN_DAYS*86400, path="/auth")
    return {"access_token": access_token, "token_type": "bearer", "expires_in": ACCESS_TOKEN_MINUTES*60}

@app.post("/auth/refresh")
def refresh(refresh_token: Annotated[str | None, Cookie()] = None):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")
    email = decode_token(refresh_token, "refresh")
    if email not in users:
        raise HTTPException(status_code=401, detail="User not found")
    return {"access_token": create_token(email, "access", timedelta(minutes=ACCESS_TOKEN_MINUTES)), "token_type": "bearer", "expires_in": ACCESS_TOKEN_MINUTES*60}

@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie("refresh_token", path="/auth")
    return {"message": "Logged out"}

@app.get("/auth/me", response_model=UserResponse)
def me(current_user: Annotated[dict, Depends(get_current_user)]):
    return {"email": current_user["email"]}
