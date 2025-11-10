from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
import redis.asyncio as redis
from passlib.context import CryptContext
import os
import jwt
from datetime import datetime, timedelta

app = FastAPI()

# 配置
JWT_SECRET = os.getenv("JWT_SECRET", "fallback-secret-change-in-production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

# Redis
redis_client = redis.from_url(f"redis://{os.getenv('REDIS_HOST', 'redis')}:6379")

# 密码哈希
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 模型
class User(BaseModel):
    username: str
    disabled: Optional[bool] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class ServerInfo(BaseModel):
    ip: str
    port: int
    hostname: str
    players: int
    max_players: int
    map: str
    game: str

# 用户数据库（延迟初始化）
fake_users_db = {}

# 辅助函数
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = fake_users_db.get(username)
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return User(**user)

# 路由
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/health")
async def health():
    try:
        await redis_client.ping()
        return {"status": "ok", "redis": "connected"}
    except:
        return {"status": "error", "redis": "failed"}

@app.get("/servers", response_model=List[ServerInfo])
async def get_servers(user: User = Depends(get_current_user)):
    raw = await redis_client.lrange("servers", 0, -1)
    servers = []
    for item in raw:
        data = eval(item.decode())
        servers.append(ServerInfo(**data))
    return servers

# 启动事件：延迟初始化 admin 用户
@app.on_event("startup")
async def startup():
    if "admin" not in fake_users_db:
        fake_users_db["admin"] = {
            "username": "admin",
            "hashed_password": get_password_hash("admin123"),
            "disabled": False,
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
