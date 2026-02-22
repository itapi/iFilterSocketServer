require('dotenv').config();
const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'iFilter_Secret_Key_2025';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:5173')
  .split(',')
  .map((o) => o.trim());

// ---------------------------------------------------------------------------
// Express + HTTP server
// ---------------------------------------------------------------------------
const app = express();
app.use(cors({ origin: ALLOWED_ORIGINS }));
app.use(express.json());

const httpServer = createServer(app);

// ---------------------------------------------------------------------------
// In-memory session store  (ephemeral — no DB)
// Map<clientId, SessionInfo>
// SessionInfo: { adminSocketId, clientSocketId, status, startedAt }
// ---------------------------------------------------------------------------
const sessions = new Map();

// ---------------------------------------------------------------------------
// Helper — validate iFilter JWT (HS256, shared secret with PHP backend)
// ---------------------------------------------------------------------------
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// HTTP endpoints
// ---------------------------------------------------------------------------
app.get('/health', (_req, res) => {
  res.json({ ok: true, sessions: sessions.size });
});

app.get('/session/:clientId/status', (req, res) => {
  const session = sessions.get(req.params.clientId);
  if (!session) return res.json({ status: 'none' });
  res.json({ status: session.status, startedAt: session.startedAt });
});

// ---------------------------------------------------------------------------
// Socket.IO — Authentication middleware
// ---------------------------------------------------------------------------
const io = new Server(httpServer, {
  cors: {
    origin: ALLOWED_ORIGINS,
    methods: ['GET', 'POST'],
  },
});

io.use((socket, next) => {
  const { token, clientId, role } = socket.handshake.auth;

  if (!token || !clientId || !role) {
    return next(new Error('Missing auth fields: token, clientId, role'));
  }

  if (!['admin', 'client'].includes(role)) {
    return next(new Error('Invalid role'));
  }

  // Admin connections must carry a valid dashboard JWT
  if (role === 'admin') {
    const payload = verifyToken(token);
    if (!payload) return next(new Error('Invalid or expired token'));
    socket.adminId = payload.user_id || payload.id;
    socket.adminName = payload.username || 'Admin';
  }

  // Client connections: the token is validated separately (later phase)
  // For now, clients are trusted via a simple shared secret check
  if (role === 'client') {
    if (token !== JWT_SECRET) {
      return next(new Error('Invalid client token'));
    }
  }

  socket.clientId = clientId;
  socket.role = role;
  next();
});

// ---------------------------------------------------------------------------
// Socket.IO — Connection handler
// ---------------------------------------------------------------------------
io.on('connection', (socket) => {
  const { clientId, role } = socket;
  const room = `session:${clientId}`;

  socket.join(room);
  console.log(`[connect] ${role} joined room ${room} (socket ${socket.id})`);

  // ── Admin joined ──────────────────────────────────────────────────────────
  if (role === 'admin') {
    const existing = sessions.get(clientId);

    // Allow admin to rejoin an existing session (e.g. page refresh)
    if (existing && existing.status !== 'ended') {
      existing.adminSocketId = socket.id;
      socket.emit('session:status', { status: existing.status });
    } else {
      sessions.set(clientId, {
        adminSocketId: socket.id,
        clientSocketId: null,
        status: 'waiting',
        startedAt: Date.now(),
      });
      socket.emit('session:status', { status: 'waiting' });
    }

    // Notify admin if client is already in the room (rare but possible)
    const session = sessions.get(clientId);
    if (session.clientSocketId) {
      session.status = 'active';
      io.to(room).emit('session:active');
    } else {
      socket.emit('session:waiting');
    }
  }

  // ── Client joined ─────────────────────────────────────────────────────────
  if (role === 'client') {
    const session = sessions.get(clientId);

    if (!session) {
      // No admin has opened a session yet — client waits too
      sessions.set(clientId, {
        adminSocketId: null,
        clientSocketId: socket.id,
        status: 'waiting',
        startedAt: Date.now(),
      });
      socket.emit('session:waiting');
    } else {
      session.clientSocketId = socket.id;
      session.status = 'active';
      // Notify both sides
      io.to(room).emit('session:active');
    }
  }

  // ── Message relay ─────────────────────────────────────────────────────────
  socket.on('message', (data) => {
    const session = sessions.get(clientId);
    if (!session || session.status !== 'active') return;

    const payload = {
      from: role,
      text: String(data.text || '').slice(0, 2000), // cap length
      timestamp: Date.now(),
    };

    io.to(room).emit('message', payload);
  });

  // ── End session ───────────────────────────────────────────────────────────
  socket.on('session:end', () => {
    endSession(clientId, room, 'manual');
  });

  // ── Disconnect ────────────────────────────────────────────────────────────
  socket.on('disconnect', (reason) => {
    console.log(`[disconnect] ${role} left room ${room} — ${reason}`);
    const session = sessions.get(clientId);
    if (!session) return;

    if (role === 'admin') {
      // Admin disconnected — end the session immediately
      endSession(clientId, room, 'admin_disconnect');
    } else {
      // Client disconnected — notify admin but keep session alive briefly
      session.clientSocketId = null;
      session.status = 'waiting';
      io.to(room).emit('session:client_disconnected');
    }
  });
});

// ---------------------------------------------------------------------------
// Helper — end a session and notify participants
// ---------------------------------------------------------------------------
function endSession(clientId, room, reason) {
  io.to(room).emit('session:ended', { reason });
  sessions.delete(clientId);
  console.log(`[session:ended] clientId=${clientId} reason=${reason}`);
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
httpServer.listen(PORT, () => {
  console.log(`iFilter Socket Server running on port ${PORT}`);
  console.log(`Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
});
