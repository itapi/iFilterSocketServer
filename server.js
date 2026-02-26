require('dotenv').config();
const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const { WebSocketServer } = require('ws');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'iFilter_Secret_Key_2025';
const rawOrigins = process.env.ALLOWED_ORIGINS || 'http://localhost:5173';
const ALLOWED_ORIGINS = rawOrigins === '*' ? '*' : rawOrigins.split(',').map((o) => o.trim());

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------
const PROTOCOL_VERSION = 1;
const MAX_MSG_BYTES = 8192; // 8 KB per message
const VALID_TYPES = ['cmd', 'res', 'event', 'err', 'stream'];

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
// SessionInfo: {
//   adminSocketId, clientSocketId,
//   status: 'waiting' | 'active' | 'ended',
//   startedAt, adminLastSeen, clientLastSeen
// }
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
// Helper — validate protocol envelope
// Returns null if valid, or an error string describing the problem.
// ---------------------------------------------------------------------------
function validateEnvelope(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return 'Payload must be a JSON object';
  }
  if (data.v !== PROTOCOL_VERSION) {
    return `Unsupported protocol version: ${data.v} (expected ${PROTOCOL_VERSION})`;
  }
  if (!data.id || typeof data.id !== 'string' || data.id.length === 0 || data.id.length > 128) {
    return 'Field "id" must be a non-empty string (max 128 chars)';
  }
  if (!VALID_TYPES.includes(data.type)) {
    return `Field "type" must be one of: ${VALID_TYPES.join(', ')}`;
  }
  if (typeof data.ts !== 'number' || data.ts <= 0) {
    return 'Field "ts" must be a positive number (Unix ms)';
  }
  if (data.payload === undefined || data.payload === null || typeof data.payload !== 'object') {
    return 'Field "payload" must be a JSON object';
  }
  return null;
}

// ---------------------------------------------------------------------------
// Helper — build a server-originated error envelope
// ---------------------------------------------------------------------------
function serverError(id, code, message) {
  return {
    v: PROTOCOL_VERSION,
    id: id || 'unknown',
    type: 'err',
    ts: Date.now(),
    from: 'server',
    payload: { code, message },
  };
}

// ---------------------------------------------------------------------------
// HTTP endpoints
// ---------------------------------------------------------------------------
app.get('/health', (_req, res) => {
  const sessionList = [];
  sessions.forEach((s, clientId) => {
    sessionList.push({
      clientId,
      status: s.status,
      startedAt: s.startedAt,
      adminLastSeen: s.adminLastSeen || null,
      clientLastSeen: s.clientLastSeen || null,
    });
  });
  res.json({ ok: true, sessions: sessions.size, sessionList });
});

app.get('/session/:clientId/status', (req, res) => {
  const session = sessions.get(req.params.clientId);
  if (!session) return res.json({ status: 'none' });
  res.json({
    status: session.status,
    startedAt: session.startedAt,
    adminLastSeen: session.adminLastSeen || null,
    clientLastSeen: session.clientLastSeen || null,
  });
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

  // Client connections use the shared secret
  if (role === 'client') {
    if (token !== JWT_SECRET) {
      return next(new Error('Invalid client token'));
    }
  }

  socket.clientId = String(clientId); // normalize — JS may send number, Android always sends string
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

    if (existing && existing.status !== 'ended') {
      existing.adminSocketId = socket.id;
      socket.emit('session:status', { status: existing.status });
    } else {
      sessions.set(clientId, {
        adminSocketId: socket.id,
        clientSocketId: null,
        status: 'waiting',
        startedAt: Date.now(),
        adminLastSeen: Date.now(),
        clientLastSeen: null,
      });
      socket.emit('session:status', { status: 'waiting' });
    }

    const session = sessions.get(clientId);
    if (session.clientSocketId) {
      session.status = 'active';
      const members = io.sockets.adapter.rooms.get(room);
      console.log(`[session:active] admin-triggered | room=${room} | members=[${members ? [...members].join(', ') : 'EMPTY'}]`);
      io.to(room).emit('session:active');
    } else {
      console.log(`[session:waiting] admin waiting | room=${room} | no client yet`);
      socket.emit('session:waiting');
    }
  }

  // ── Client joined ─────────────────────────────────────────────────────────
  if (role === 'client') {
    const session = sessions.get(clientId);
    console.log(`[client-join] session exists=${!!session} | existing clientSocketId=${session?.clientSocketId || 'none'}`);

    if (!session) {
      sessions.set(clientId, {
        adminSocketId: null,
        clientSocketId: socket.id,
        status: 'waiting',
        startedAt: Date.now(),
        adminLastSeen: null,
        clientLastSeen: Date.now(),
      });
      console.log(`[session:waiting] client waiting | room=${room} | no admin session yet`);
      socket.emit('session:waiting');
    } else {
      session.clientSocketId = socket.id;
      session.clientLastSeen = Date.now();
      session.status = 'active';
      const members = io.sockets.adapter.rooms.get(room);
      console.log(`[session:active] client-triggered | room=${room} | members=[${members ? [...members].join(', ') : 'EMPTY'}] | adminSocketId=${session.adminSocketId}`);
      io.to(room).emit('session:active');
    }
  }

  // ── Structured message relay ───────────────────────────────────────────────
  socket.on('message', (rawData) => {
    const session = sessions.get(clientId);

    if (!session || session.status !== 'active') {
      socket.emit('message', serverError(rawData?.id, 'SESSION_NOT_ACTIVE', 'No active session to relay to'));
      return;
    }

 // Size guard (true UTF-8 byte size)
let msgStr;
try {
  msgStr = JSON.stringify(rawData);
} catch (_) {
  msgStr = '';
}

const msgSizeBytes = Buffer.byteLength(msgStr, 'utf8');

if (msgSizeBytes > MAX_MSG_BYTES) {
  console.log(
    `[size-blocked] role=${role} id=${rawData?.id} size=${msgSizeBytes} limit=${MAX_MSG_BYTES}`
  );

  socket.emit('message', serverError(rawData?.id,'MSG_TOO_LARGE',`Message exceeds ${MAX_MSG_BYTES} byte limit. Actual size: ${msgSizeBytes} bytes`));
  return;
}

    // Envelope validation
    const validationErr = validateEnvelope(rawData);
    if (validationErr) {
      socket.emit('message', serverError(rawData?.id, 'INVALID_ENVELOPE', validationErr));
      return;
    }

    // Update last-seen timestamp
    if (role === 'client') session.clientLastSeen = Date.now();
    else session.adminLastSeen = Date.now();

    // Relay to the other side only (exclude sender)
    const relayed = { ...rawData, from: role, relayedAt: Date.now() };
    socket.to(room).emit('message', relayed);

    const sub = rawData.payload?.cmd || rawData.payload?.name || '';
    console.log(`[relay] ${role} → type=${rawData.type}${sub ? '/' + sub : ''} id=${rawData.id}`);
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
      endSession(clientId, room, 'admin_disconnect');
    } else {
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
// Screen relay  (/screen  — raw binary WebSocket, no JSON parsing)
//
// Both sides connect with query params:
//   ?clientId=<id>&token=<token>&role=source   (Android device)
//   ?clientId=<id>&token=<jwt>&role=sink       (admin dashboard)
//
// Binary frame format (produced by ScreenStreamManager.java):
//   [0]     0x00 = SPS/PPS config,  0x01 = H.264 video frame
//   [1..4]  payload size (uint32, big-endian)
//   [5..]   raw H.264 NAL bytes
//
// The server is a pure passthrough relay: it never inspects the binary payload,
// it just forwards every Buffer from source → sink.
// ---------------------------------------------------------------------------
const screenSessions = new Map();
// Map<clientId, { source: WebSocket | null, sink: WebSocket | null }>

const screenWss = new WebSocketServer({ noServer: true });

// Manually route /screen upgrade requests to screenWss.
// Using noServer:true avoids the known conflict between ws and Socket.IO
// when both attach to the same httpServer: ws v8 calls abortHandshake(400)
// for paths that don't match, destroying the socket before Socket.IO can
// handle its own /socket.io/ upgrades — causing "Invalid frame header".
httpServer.on('upgrade', (request, socket, head) => {
  const pathname = new URL(request.url, 'http://localhost').pathname;
  if (pathname === '/screen') {
    screenWss.handleUpgrade(request, socket, head, (ws) => {
      screenWss.emit('connection', ws, request);
    });
  }
  // All other paths (Socket.IO at /socket.io/) are handled by Socket.IO's
  // own upgrade listener — we intentionally don't touch them here.
});

screenWss.on('connection', (ws, req) => {
  // Parse query params from the upgrade URL
  let params;
  try {
    params = new URL(req.url, 'ws://localhost').searchParams;
  } catch {
    ws.close(1008, 'Bad request URL');
    return;
  }

  const clientId = params.get('clientId');
  const token    = params.get('token');
  const role     = params.get('role'); // 'source' or 'sink'

  // ── Auth ────────────────────────────────────────────────────────────────
  if (!clientId || !token || !role) {
    ws.close(1008, 'Missing clientId, token, or role');
    return;
  }
  if (!['source', 'sink'].includes(role)) {
    ws.close(1008, 'role must be source or sink');
    return;
  }

  if (role === 'source') {
    // Device authenticates with the shared secret
    if (token !== JWT_SECRET) {
      ws.close(1008, 'Invalid client token');
      return;
    }
  } else {
    // Admin authenticates with a dashboard JWT
    if (!verifyToken(token)) {
      ws.close(1008, 'Invalid or expired admin token');
      return;
    }
  }

  // ── Session bookkeeping ─────────────────────────────────────────────────
  if (!screenSessions.has(clientId)) {
    screenSessions.set(clientId, { source: null, sink: null });
  }
  const session = screenSessions.get(clientId);
  session[role] = ws;

  console.log(`[screen] ${role} connected | clientId=${clientId}`);

  // ── Binary relay ────────────────────────────────────────────────────────
  ws.on('message', (data, isBinary) => {
    if (!isBinary) return; // we only forward binary frames

    const target = role === 'source' ? session.sink : session.source;
    if (target && target.readyState === target.OPEN) {
      target.send(data, { binary: true });
    }
    // Drop silently if the other side isn't connected yet — device just
    // keeps streaming and the sink will catch up on its next keyframe.
  });

  // ── Cleanup ─────────────────────────────────────────────────────────────
  ws.on('close', (code, reason) => {
    console.log(`[screen] ${role} disconnected | clientId=${clientId} code=${code}`);
    const s = screenSessions.get(clientId);
    if (!s) return;

    s[role] = null;

    // Remove the session entry once both sides have disconnected
    if (s.source === null && s.sink === null) {
      screenSessions.delete(clientId);
    }
  });

  ws.on('error', (err) => {
    console.error(`[screen] ${role} error | clientId=${clientId}:`, err.message);
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
httpServer.listen(PORT, () => {
  console.log(`iFilter Socket Server running on port ${PORT}`);
  console.log(`Protocol version: ${PROTOCOL_VERSION}`);
  console.log(`Max message size: ${MAX_MSG_BYTES} bytes`);
  console.log(`Allowed origins: ${Array.isArray(ALLOWED_ORIGINS) ? ALLOWED_ORIGINS.join(', ') : ALLOWED_ORIGINS}`);
});
