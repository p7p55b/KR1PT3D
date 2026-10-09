// Minimal E2EE relay server using Node.js http + SSE (no deps)
// Serves static client and relays encrypted payloads between users in rooms.

const http = require('http');
const https = require('https');
const url = require('url');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const PORT = process.env.PORT || 3000;
const KEY_FILE = process.env.KEY_FILE || path.join(__dirname, 'key.pem');
const CERT_FILE = process.env.CERT_FILE || path.join(__dirname, 'cert.pem');
const CERT_CN = process.env.CERT_CN || 'localhost';
const AUTO_CERT = process.env.AUTO_CERT !== '0';
const STATIC_DIR = process.env.STATIC_DIR ||
  (fs.existsSync(path.resolve(__dirname, '..', 'front'))
    ? path.resolve(__dirname, '..', 'front')
    : path.resolve(__dirname, 'public'));

// In-memory state: rooms -> { clients, pubkeys, queues }
// clients: Map<user, res> (SSE connections)
// pubkeys: Map<user, pubKeyRawB64>
// queues: Map<user, Array<event>> (buffer for offline)
const rooms = new Map();

// Harden process against unexpected exits
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err && err.stack ? err.stack : err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[unhandledRejection]', reason);
});

function getRoom(roomId) {
  if (!rooms.has(roomId)) {
    rooms.set(roomId, {
      clients: new Map(),
      pubkeys: new Map(),
      queues: new Map(),
    });
  }
  return rooms.get(roomId);
}

let cachedVersion = null;
function getCommitVersion() {
  if (cachedVersion) return cachedVersion;
  try {
    const gitDir = path.resolve(__dirname, '..');
    const hash = execSync('git rev-parse --short HEAD', { cwd: gitDir, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
    const count = execSync('git rev-list --count HEAD', { cwd: gitDir, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
    cachedVersion = `v0.1.0-r${count}.${hash}`;
    return cachedVersion;
  } catch (_) {
    try {
      const vFile = path.join(STATIC_DIR, 'version.txt');
      if (fs.existsSync(vFile)) {
        cachedVersion = fs.readFileSync(vFile, 'utf8').trim();
        return cachedVersion;
      }
    } catch (_) {}
    return 'v0.1.0-dev';
  }
}

function sseWrite(res, event, data) {
  try {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  } catch (_) {
    // Ignore write errors on closed sockets
  }
}

function sendToUser(room, user, event, data) {
  const clientSet = room.clients.get(user);
  if (clientSet && clientSet.size > 0) {
    for (const res of clientSet) {
      sseWrite(res, event, data);
    }
  } else {
    if (!room.queues.has(user)) room.queues.set(user, []);
    room.queues.get(user).push({ event, data });
  }
}

function broadcastToRoom(room, event, data, excludeUser) {
  for (const [u, clientSet] of room.clients.entries()) {
    if (u === excludeUser) continue;
    for (const res of clientSet) {
      sseWrite(res, event, data);
    }
  }
  for (const [u] of room.queues.entries()) {
    if (u === excludeUser) continue;
    if (!room.clients.has(u) || room.clients.get(u).size === 0) {
      room.queues.get(u).push({ event, data });
    }
  }
}

function notFound(res) {
  res.statusCode = 404;
  res.end('Not Found');
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => (data += chunk));
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function serveStatic(req, res) {
  const reqPath = url.parse(req.url).pathname;
  if (reqPath === '/version.txt') {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache');
    return res.end(getCommitVersion());
  }

  const safePath = path.normalize(reqPath === '/' ? '/index.html' : reqPath).replace(/^(\.\.[\/\\])+/, '');
  const filePath = path.join(STATIC_DIR, safePath);
  if (!filePath.startsWith(STATIC_DIR)) {
    return notFound(res);
  }
  fs.readFile(filePath, (err, data) => {
    if (err) return notFound(res);
    const ext = path.extname(filePath).toLowerCase();
    const mime = ext === '.html' ? 'text/html; charset=utf-8'
      : ext === '.js' ? 'text/javascript; charset=utf-8'
      : ext === '.css' ? 'text/css; charset=utf-8'
      : ext === '.json' ? 'application/json; charset=utf-8'
      : 'text/plain; charset=utf-8';
    res.setHeader('Content-Type', mime);
    res.end(data);
  });
}

const requestHandler = async (req, res) => {
  const { pathname, query } = url.parse(req.url, true);
  console.log(`${new Date().toISOString()} ${pathname}`);

  // Anti-fingerprinting and security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');

  // SSE stream: /events?room=...&user=...
  if (req.method === 'GET' && pathname === '/events') {
    const roomId = query.room || 'default';
    const user = query.user;
    if (!user) {
      res.statusCode = 400;
      return res.end('Missing user');
    }
    const room = getRoom(roomId);

    // Setup SSE
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });
    res.write(': connected\n\n');

    if (!room.clients.has(user)) {
      room.clients.set(user, new Set());
    }
    room.clients.get(user).add(res);

    // Keepalive to prevent idle timeouts on some proxies
    const ka = setInterval(() => {
      try { res.write(': keepalive\n\n'); } catch {}
    }, 25000);

    // Drain queued events if any
    const q = room.queues.get(user) || [];
    q.forEach(({ event, data }) => sseWrite(res, event, data));
    room.queues.set(user, []);

    // Broadcast online status if user already registered key
    if (room.pubkeys.has(user)) {
      broadcastToRoom(room, 'peer-joined', {
        user,
        pubKeyRawB64: room.pubkeys.get(user),
        online: true,
      }, user);
    }

    req.on('close', () => {
      clearInterval(ka);
      const set = room.clients.get(user);
      if (set) {
        set.delete(res);
        if (set.size === 0) {
          room.clients.delete(user);
          broadcastToRoom(room, 'peer-left', { user, online: false }, user);
        }
      }
    });
    return; // Keep open
  }

  // Register or update public key: POST /register { room, user, pubKeyRawB64 }
  if (req.method === 'POST' && pathname === '/register') {
    try {
      const { room, user, pubKeyRawB64 } = await parseBody(req);
      if (!room || !user || !pubKeyRawB64) {
        res.statusCode = 400;
        return res.end('Missing fields');
      }
      const r = getRoom(room);
      r.pubkeys.set(user, pubKeyRawB64);
      if (!r.queues.has(user)) r.queues.set(user, []);

      // Notify others in the room
      const evt = { event: 'peer-joined', data: { user, pubKeyRawB64, online: true } };
      broadcastToRoom(r, evt.event, evt.data, user);

      res.setHeader('Access-Control-Allow-Origin', '*');
      res.end(JSON.stringify({ ok: true }));
    } catch (e) {
      res.statusCode = 500;
      res.end('Error');
    }
    return;
  }

  // Get peers: GET /peers?room=...
  if (req.method === 'GET' && pathname === '/peers') {
    const roomId = query.room;
    if (!roomId) {
      res.statusCode = 400;
      return res.end('Missing room');
    }
    const r = getRoom(roomId);
    const peers = Array.from(r.pubkeys.entries()).map(([u, pubKeyRawB64]) => ({
      user: u,
      pubKeyRawB64,
      online: r.clients.has(u) && r.clients.get(u).size > 0,
    }));
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    return res.end(JSON.stringify({ peers }));
  }

  // Send encrypted message: POST /send { room, from, to, payload: { ivB64, ctB64 } }
  if (req.method === 'POST' && pathname === '/send') {
    try {
      const { room, from, to, payload } = await parseBody(req);
      if (!room || !from || !to || !payload) {
        res.statusCode = 400;
        return res.end('Missing fields');
      }
      const r = getRoom(room);
      const messageEvt = { event: 'message', data: { from, to, payload } };

      sendToUser(r, to, messageEvt.event, messageEvt.data);

      res.setHeader('Access-Control-Allow-Origin', '*');
      res.end(JSON.stringify({ ok: true }));
    } catch (e) {
      res.statusCode = 500;
      res.end('Error');
    }
    return;
  }

  // CORS preflight for POST endpoints
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    return res.end();
  }

  // Static files (client)
  return serveStatic(req, res);
};

let server;
let scheme = 'http';
try {
  if (!fs.existsSync(KEY_FILE) || !fs.existsSync(CERT_FILE)) {
    if (AUTO_CERT) {
      try {
        console.log(`Generating self-signed cert via OpenSSL for CN=${CERT_CN}...`);
        execSync(`openssl req -newkey rsa:2048 -nodes -keyout "${KEY_FILE}" -x509 -days 365 -out "${CERT_FILE}" -subj "/CN=${CERT_CN}"`, { stdio: 'ignore' });
      } catch (e) {
        console.warn('OpenSSL not available or cert generation failed. Falling back to HTTP.');
      }
    }
  }
  if (fs.existsSync(KEY_FILE) && fs.existsSync(CERT_FILE)) {
    const key = fs.readFileSync(KEY_FILE);
    const cert = fs.readFileSync(CERT_FILE);
    server = https.createServer({ key, cert }, requestHandler);
    scheme = 'https';
  } else {
    server = http.createServer(requestHandler);
  }
} catch (e) {
  // Fallback to HTTP if reading TLS files fails
  server = http.createServer(requestHandler);
}

// Avoid process exit on client parser errors or server errors
server.on('clientError', (err, socket) => {
  try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch {}
});
server.on('error', (err) => {
  console.error('[server error]', err && err.stack ? err.stack : err);
});

server.listen(PORT, () => {
  console.log(`E2EE relay listening on ${scheme}://localhost:${PORT}`);
  if (scheme === 'http') {
    console.log('Tip: To enable HTTPS (required for crypto.subtle off-localhost), place key.pem and cert.pem next to server.js or set KEY_FILE/CERT_FILE env vars.');
  }
});
