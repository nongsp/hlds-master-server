#!/usr/bin/env python3
"""
HLDS Master Server with Redis (v4)
"""

import asyncio
import struct
import logging
import time
import os
import socket
from typing import Tuple
import redis

# Config
SERVER_PORT = int(os.getenv("SERVER_PORT", 27011))
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
HEARTBEAT_TTL = 600
BATCH_SIZE = 50

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HLDSMasterServer:
    def __init__(self):
        self.redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=False)
        self.sock = None
        self.redis.ping()

    async def start(self, host='0.0.0.0', port=SERVER_PORT):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        logger.info(f"Master listening on {host}:{port} (Redis: {REDIS_HOST})")
        asyncio.create_task(self._cleanup())
        while True:
            data, addr = await asyncio.get_event_loop().sock_recv(self.sock, 2048)
            asyncio.create_task(self.handle_packet(data, addr))

    async def handle_packet(self, data: bytes, addr: Tuple[str, int]):
        if len(data) < 1: return
        cmd = data[0]
        if cmd == 0x71:  # Challenge
            await self._challenge(addr)
        elif data.startswith(b'\xff\xff\xff\xffgetservers'):  # Query
            await self._query(data, addr)
        elif data.startswith(b'b\x0A'):  # Quit
            self._quit(addr)
        else:  # Response
            await self._register(data, addr)

    async def _challenge(self, addr):
        challenge = int(time.time() * 1000) % 0xFFFFFFFF
        self.redis.setex(f"pending:{addr[0]}:{addr[1]}", 60, challenge)
        resp = b'\xff\xff\xff\xffs\x0a' + struct.pack('!I', challenge)
        self.sock.sendto(resp, addr)

    async def _register(self, data: bytes, addr: Tuple[str, int]):
        text = data.decode('ascii', errors='ignore')
        parts = text.split('\\')[1:]
        info = {parts[i]: parts[i+1] for i in range(0, len(parts)-1, 2)}
        pending = self.redis.get(f"pending:{addr[0]}:{addr[1]}")
        if not pending or int(pending) != int(info.get('challenge', 0)): return
        self.redis.delete(f"pending:{addr[0]}:{addr[1]}")
        port = int(info.get('port', 27015))
        server_key = f"server:{addr[0]}:{port}"
        self.redis.hmset(server_key, {
            b'ip': addr[0].encode(),
            b'port': str(port).encode(),
            b'protocol': info.get('protocol', b'48'),
            b'players': info.get('players', b'0').encode(),
            b'max_players': info.get('max', b'16').encode(),
            b'bots': info.get('bots', b'0').encode(),
            b'gamedir': info.get('gamedir', b'valve').encode(),
            b'map': info.get('map', b'crossfire').encode(),
            b'password': info.get('password', b'0').encode(),
            b'os': info.get('os', b'l').encode(),
            b'secure': info.get('secure', b'0').encode(),
            b'lan': info.get('lan', b'0').encode(),
            b'version': info.get('version', b'1.1.2.7').encode(),
            b'region': info.get('region', b'-1').encode(),
        })
        self.redis.expire(server_key, HEARTBEAT_TTL)
        logger.info(f"Registered {addr[0]}:{port} [{info.get('gamedir')}/{info.get('map')}]")

    async def _query(self, data: bytes, addr: Tuple[str, int]):
        keys = self.redis.keys("server:*")
        blacklist = {k.decode().split(":", 2)[1] for k in self.redis.keys("blacklist:*")}
        resp = b'\xff\xff\xff\xfff\x0a'
        count = 0
        for key in keys:
            ip_port = key.decode().split(":", 2)[1]
            if ip_port in blacklist: continue
            data = self.redis.hgetall(key)
            if b'ip' in data and b'port' in data:
                ip = socket.inet_aton(data[b'ip'].decode())
                port = struct.pack('!H', int(data[b'port'].decode()))
                resp += ip + port
                count += 1
                if count >= BATCH_SIZE:
                    self.sock.sendto(resp, addr)
                    resp = b'\xff\xff\xff\xfff\x0a'
                    count = 0
        if count > 0:
            resp += b'\x00\x00\x00\x00\x00\x00'
            self.sock.sendto(resp, addr)

    def _quit(self, addr):
        keys = self.redis.keys(f"server:{addr[0]}:*")
        for k in keys:
            self.redis.delete(k)
        logger.info(f"Server quit: {addr}")

    async def _cleanup(self):
        while True:
            await asyncio.sleep(300)
            count = len(self.redis.keys("server:*"))
            logger.info(f"Active servers: {count}")

if __name__ == '__main__':
    server = HLDSMasterServer()
    asyncio.run(server.start())
