from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta
import pymysql
import os
import re

app = FastAPI(title="EduCenter Backend", version="2.0")

# === GET MYSQL URL FROM RAILWAY (AUTO-INJECTED) ===
DATABASE_URL = os.getenv("MYSQL_URL") or os.getenv("MYSQLURL")

conn = None
if DATABASE_URL:
    try:
        match = re.match(r"mysql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", DATABASE_URL)
        if not match:
            print("Invalid MySQL URL format")
        else:
            username, password, host, port, database = match.groups()
            conn = pymysql.connect(
                host=host,
                port=int(port),
                user=username,
                password=password,
                database=database,
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=True
            )
            print("MySQL Connected Successfully!")
    except Exception as e:
        print(f"MySQL Connection Failed: {e}")
        conn = None
else:
    print("No MYSQL_URL found – Running in DEMO MODE (no database)")

# JWT Settings
SECRET_KEY = "your-super-secret-key-change-in-production-256-bit"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440
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

@app.get("/helloworld")
async def helloworld():
    return {
        "message": "Hello World from Sujay's EduCenter Backend!",
        "status": "working perfectly",
        "owner": "sujayabraham",
        "time": datetime.utcnow().isoformat() + "Z"
    }    

@app.post("/auth/firebase", response_model=AuthResponse)
async def login_firebase(token: FirebaseToken):
    phone = "9999999999"
    name = "Demo Student"

    user_id = 1
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM students WHERE phone = %s", (phone,))
                user = cur.fetchone()
                if not user:
                    cur.execute("INSERT INTO students (name, phone, class_name, pending_fees) VALUES (%s, %s, %s, %s)",
                                (name, phone, "Class 12th", 25000))
                    user_id = cur.lastrowid
                else:
                    user_id = user['id']
        except Exception as e:
            print(f"DB Error: {e}")

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
        if conn:
            with conn.cursor() as cur:
                cur.execute("SELECT name, phone, class_name, pending_fees FROM students WHERE id = %s", (user_id,))
                user = cur.fetchone()
                if user:
                    return user
        return {"name": "Demo Student", "phone": "9999999999", "class_name": "Class 12th", "pending_fees": 25000}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
