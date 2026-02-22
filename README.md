# iFilter Socket Server

Real-time WebSocket server for live admin–client sessions.
Built with Node.js + Express + Socket.IO.

---

## Requirements

- Node.js 18+
- npm

---

## Setup

```bash
# 1. Copy and fill in environment variables
cp .env.example .env
nano .env

# 2. Install dependencies
npm install
```

### `.env` values

| Variable | Description | Example |
|----------|-------------|---------|
| `PORT` | Port the server listens on | `3001` |
| `JWT_SECRET` | Must match `AuthMiddleware.php` → `$secretKey` | `iFilter_Secret_Key_2025` |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | `https://ikosher.me,http://localhost:5173` |

---

## Run

### Development
```bash
npm run dev
```

### Production (PM2)
```bash
# Install PM2 globally (once)
npm install -g pm2

# Start
pm2 start ecosystem.config.js

# Auto-start on server reboot
pm2 save
pm2 startup

# Useful commands
pm2 status
pm2 logs ifilter-socket
pm2 restart ifilter-socket
pm2 stop ifilter-socket
```

---

## HTTP Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Server health + active session count |
| GET | `/session/:clientId/status` | Check if a session exists for a client |

---

## Socket Events

### Client → Server
| Event | Payload | Description |
|-------|---------|-------------|
| `message` | `{ text }` | Send a chat message |
| `session:end` | — | End the session |

### Server → Client
| Event | Payload | Description |
|-------|---------|-------------|
| `session:waiting` | — | Waiting for the other side to connect |
| `session:active` | — | Both sides connected, chat is live |
| `session:client_disconnected` | — | Client dropped, still waiting |
| `session:ended` | `{ reason }` | Session is over |
| `message` | `{ from, text, timestamp }` | Relayed message |

### Socket Auth (handshake)
```json
{
  "token": "<JWT from PHP login>",
  "clientId": "<client_unique_id>",
  "role": "admin"
}
```
For the Android client, use `"role": "client"`.

---

## Firewall

Open the port you configured (default `3001`) on your server:
```bash
# UFW example
ufw allow 3001/tcp
```
"# iFilterSocketServer" 
