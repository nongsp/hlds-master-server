#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import redis
import os
import asyncio
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptPasswordHasher
from prometheus_client import Counter, Gauge, generate_latest

app = FastAPI(title="HLDS Master API v4", version="4.0")

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-prod")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

r = redis.Redis(host=REDIS_HOST, port=6379, db=0, decode_responses=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptPasswordHasher(schemes=["bcrypt"], deprecated="auto")

REQUEST_COUNT = Counter('api_requests_total', 'Total API requests', ['method', 'endpoint', 'status'])
SERVER_COUNT = Gauge('hlds_servers_total', 'Active game servers')
PLAYER_COUNT = Gauge('hlds_players_total', 'Total players online')

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class User(BaseModel):
    username: str
    disabled: Optional[bool] = False

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class ServerInfo(BaseModel):
    ip: str
    port: int
    protocol: int
    players: int
    max_players: int
    bots: int
    gamedir: str
    map: str
    password: bool
    os: str
    secure: bool
    lan: bool
    version: str
    region: int

class BlacklistEntry(BaseModel):
    ip: str
    port: Optional[int] = None
    reason: str
    added_by: str
    added_at: datetime

def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)
def get_password_hash(password): return pwd_context.hash(password)
def create_access_token(data: dict, expires_delta: timedelta = None):
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if not username: raise HTTPException(status_code=401)
        return UserInDB(username=username, hashed_password=get_user(username) or "")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_user(username: str) -> Optional[str]:
    pwd = r.get(f"user:{username}")
    return pwd.decode() if pwd else None

@app.on_event("startup")
async def init_admin():
    if not r.exists("user:admin"):
        r.set("user:admin", get_password_hash("admin123"))
        print("Default admin created: admin / admin123")

@app.post("/login", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends()):
    hashed = get_user(form.username)
    if not hashed or not verify_password(form.password, hashed):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": form.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

@app.middleware("http")
async def prometheus_middleware(request: Request, call_next):
    method = request.method
    endpoint = request.url.path
    response = await call_next(request)
    REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=response.status_code).inc()
    return response

@app.get("/metrics")
async def metrics():
    update_metrics()
    return generate_latest()

def update_metrics():
    keys = r.keys("server:*")
    blacklist = {k.decode().split(":", 2)[1] for k in r.keys("blacklist:*")}
    count = 0
    players = 0
    for key in keys:
        ip_port = key.decode().split(":", 2)[1]
        if ip_port in blacklist: continue
        data = r.hgetall(key)
        if data:
            count += 1
            players += int(data.get(b'players', b'0').decode())
    SERVER_COUNT.set(count)
    PLAYER_COUNT.set(players)

def get_servers_from_redis() -> List[ServerInfo]:
    keys = r.keys("server:*")
    blacklist = {k.decode().split(":", 2)[1] for k in r.keys("blacklist:*")}
    servers = []
    for key in keys:
        ip_port = key.decode().split(":", 2)[1]
        if ip_port in blacklist: continue
        data = r.hgetall(key)
        if not data: continue
        d = {k.decode(): v.decode() if isinstance(v, bytes) else v for k, v in data.items()}
        d["password"] = bool(int(d.get("password", 0)))
        d["secure"] = bool(int(d.get("secure", 0)))
        d["lan"] = bool(int(d.get("lan", 0)))
        servers.append(ServerInfo(**d))
    return servers

@app.get("/servers", response_model=List[ServerInfo])
async def get_servers(
    gamedir: Optional[str] = None,
    map: Optional[str] = None,
    region: Optional[int] = None,
    user: User = Depends(get_current_user)
):
    servers = get_servers_from_redis()
    if gamedir: servers = [s for s in servers if s.gamedir == gamedir]
    if map: servers = [s for s in servers if s.map == map]
    if region is not None: servers = [s for s in servers if s.region == region]
    return servers

@app.get("/stats")
async def get_stats(user: User = Depends(get_current_user)):
    servers = get_servers_from_redis()
    total_players = sum(s.players for s in servers)
    games = {}
    for s in servers:
        games[s.gamedir] = games.get(s.gamedir, 0) + 1
    return {"total_servers": len(servers), "total_players": total_players, "games": games}

@app.post("/blacklist")
async def add_blacklist(entry: BlacklistEntry, user: User = Depends(get_current_user)):
    key = f"blacklist:{entry.ip}:{entry.port or '0'}"
    r.hset(key, mapping={
        "reason": entry.reason,
        "added_by": entry.added_by,
        "added_at": entry.added_at.isoformat()
    })
    r.expire(key, 60*60*24*30)
    return {"status": "added"}

@app.delete("/blacklist/{ip}")
async def remove_blacklist(ip: str, port: Optional[int] = None, user: User = Depends(get_current_user)):
    key = f"blacklist:{ip}:{port or '0'}"
    r.delete(key)
    return {"status": "removed"}

@app.get("/blacklist", response_model=List[BlacklistEntry])
async def list_blacklist(user: User = Depends(get_current_user)):
    keys = r.keys("blacklist:*")
    entries = []
    for key in keys:
        data = r.hgetall(key)
        ip_port = key.decode().split(":", 2)[1]
        ip, port_str = ip_port.rsplit(":", 1)
        entries.append(BlacklistEntry(
            ip=ip,
            port=int(port_str) if port_str != '0' else None,
            reason=data.get(b"reason", b"").decode(),
            added_by=data.get(b"added_by", b"").decode(),
            added_at=datetime.fromisoformat(data.get(b"added_at", b"").decode())
        ))
    return entries

import socketio
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
sio_app = socketio.ASGIApp(sio)
app.mount("/ws", sio_app)

@sio.event
async def connect(sid, environ): await sio.emit('stats', await get_stats(User(username="system")))

async def broadcast_loop():
    while True:
        await asyncio.sleep(10)
        try:
            stats = await get_stats(User(username="system"))
            await sio.emit('stats', stats)
        except: pass

@app.on_event("startup")
async def startup(): asyncio.create_task(broadcast_loop())
