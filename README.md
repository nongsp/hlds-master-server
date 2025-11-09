# HLDS Master Server v4.0 - Full-Stack Edition

Open-source Half-Life Dedicated Server Master with:
- UDP Heartbeat/Query (Valve Protocol)
- Redis Persistence
- FastAPI REST + WebSocket
- React Web Panel (Login + Real-time)
- JWT Auth + Blacklist
- Prometheus Metrics

## Quick Start

1. Clone: `git clone https://github.com/yourusername/hlds-master-server-v4`
2. Start: `docker-compose up -d --build`
3. Access:
   - Web Panel: http://localhost:3000 (admin/admin123 → Change password!)
   - API Docs: http://localhost:8000/docs
   - Metrics: http://localhost:8000/metrics
   - Prometheus: http://localhost:9090
   - UDP: your-ip:27011

## Multi-Arch Images (GHCR)

After push, Actions builds:
- `ghcr.io/yourusername/hlds-master-server-v4-master:latest` (arm64/amd64)
- `ghcr.io/yourusername/hlds-master-server-v4-api:latest`
- `ghcr.io/yourusername/hlds-master-server-v4-web:latest`

Pull arm64: `docker pull --platform linux/arm64 ghcr.io/yourusername/hlds-master-server-v4-api:latest`

## Security

- JWT_SECRET: Change in env!
- Default Admin: admin / admin123 (changes on first login)

## Testing

`python -m unittest discover tests/`
