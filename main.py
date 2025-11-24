from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta
import pymysql
import os

app = FastAPI(title="EduCenter Backend", version="2.0")

# === GET MYSQL URL FROM RAILWAY (AUTO-INJECTED) ===
DATABASE_URL = os.getenv("MYSQL_URL") or os.getenv("MYSQLURL")
if not DATABASE_URL:
    raise Exception("No MySQL URL found! Deploy on Railway")

# Parse MySQL URL
import re
match = re.match(r"mysql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", DATABASE_URL)
if not match:
    raise Exception("Invalid MySQL URL format")
username, password, host, port, database = match.groups()

# Create connection
conn = pymysql.connect(
    host=host,
    port=int(port),
    user=username,
    password=password,
    database=database,
    cursorclass=pymysql.cursors.DictCursor,
    autocommit=True
)

# JWT Settings
SECRET_KEY = "your-super-secret-key-change-in-production-256-bit"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours
REFRESH_TOKEN_EXPIRE_DAYS = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class FirebaseToken(BaseModel):
    id_token: str

class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    name: str
    phone: str

def create_jwt(data: dict, minutes: int = None, days: int = None):
    expire = datetime.utcnow()
    if minutes: expire += timedelta(minutes=minutes)
    if days: expire += timedelta(days=days)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

@app.get("/")
async def root():
    return {"message": "EduCenter Backend LIVE & FREE!", "time": datetime.now().isoformat()}

@app.post("/auth/firebase", response_model=AuthResponse)
async def login_firebase(token: FirebaseToken):
    # In production: verify Firebase ID token here
    # For demo, we accept any token and create user
    phone = "9449244215"  # Replace with real phone from Firebase token
    name = "Demo Student"

    with conn.cursor() as cur:
        cur.execute("SELECT * FROM students WHERE phone = %s", (phone,))
        user = cur.fetchone()

        if not user:
            cur.execute("""
                INSERT INTO students (name, phone, class_name, pending_fees) 
                VALUES (%s, %s, %s, %s)
            """, (name, phone, "Class 12th", 25000))
            user_id = cur.lastrowid
        else:
            user_id = user['id']

    access_token = create_jwt({"sub": str(user_id)}, minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token = create_jwt({"sub": str(user_id)}, days=REFRESH_TOKEN_EXPIRE_DAYS)

    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        name=name,
        phone=phone
    )

@app.get("/profile")
async def profile(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        with conn.cursor() as cur:
            cur.execute("SELECT name, phone, class_name, pending_fees FROM students WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user:
                raise HTTPException(404, "User not found")
            return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
