import express from 'express';
import session from 'express-session';
import { Client } from 'ssh2';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import initSqlJs from 'sql.js';
import 'dotenv/config';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.DASHBOARD_PASSWORD || 'changeme';
const SSH_KEY_PATH = process.env.SSH_KEY_PATH || join(process.env.HOME, '.ssh/id_ed25519');
const DB_PATH = join(__dirname, 'stats.db');

// Load servers from config file or environment
function loadServers() {
  const configPath = join(__dirname, 'servers.json');
  if (existsSync(configPath)) {
    return JSON.parse(readFileSync(configPath, 'utf8'));
  }
  if (process.env.SERVERS) {
    return process.env.SERVERS.split(',').map(s => {
      const [name, host, user, limitTB] = s.split(':');
      return { name, host, user, bandwidthLimit: parseFloat(limitTB || 10) * 1024 ** 4 };
    });
  }
  console.error('No servers configured. Create servers.json or set SERVERS env var.');
  process.exit(1);
}

const SERVERS = loadServers();

// Initialize SQLite database
let db;
async function initDb() {
  const SQL = await initSqlJs();
  if (existsSync(DB_PATH)) {
    db = new SQL.Database(readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }
  db.run(`
    CREATE TABLE IF NOT EXISTS stats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp INTEGER NOT NULL,
      server TEXT NOT NULL,
      status TEXT,
      clients INTEGER DEFAULT 0,
      upload_bytes INTEGER DEFAULT 0,
      download_bytes INTEGER DEFAULT 0,
      uptime TEXT
    )
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_stats_timestamp ON stats(timestamp)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_stats_server ON stats(server)`);
  saveDb();
}

function saveDb() {
  if (db) writeFileSync(DB_PATH, Buffer.from(db.export()));
}

function parseBytes(str) {
  if (!str || str === 'N/A') return 0;
  const match = str.match(/^([\d.]+)\s*([KMGTPE]?B?)$/i);
  if (!match) return 0;
  const units = { B: 1, KB: 1024, MB: 1024**2, GB: 1024**3, TB: 1024**4 };
  return Math.round(parseFloat(match[1]) * (units[(match[2] || 'B').toUpperCase()] || 1));
}

// Cache
let statsCache = { data: null, timestamp: 0 };
const CACHE_TTL = 5000;

// SSH Connection Pool
const sshPool = new Map();
const SSH_KEEPALIVE_INTERVAL = 10000;
const SSH_KEEPALIVE_COUNT_MAX = 3;

function getPooledConnection(server) {
  return new Promise((resolve, reject) => {
    const existing = sshPool.get(server.name);
    if (existing && existing.connected) return resolve(existing.conn);

    const conn = new Client();
    let privateKey;
    try {
      privateKey = readFileSync(SSH_KEY_PATH);
    } catch (err) {
      return reject(new Error(`Cannot read SSH key: ${err.message}`));
    }

    conn.on('ready', () => {
      sshPool.set(server.name, { conn, connected: true });
      resolve(conn);
    });
    conn.on('error', (err) => { sshPool.delete(server.name); reject(err); });
    conn.on('close', () => sshPool.delete(server.name));
    conn.on('end', () => sshPool.delete(server.name));

    conn.connect({
      host: server.host,
      port: 22,
      username: server.user,
      privateKey,
      readyTimeout: 15000,
      keepaliveInterval: SSH_KEEPALIVE_INTERVAL,
      keepaliveCountMax: SSH_KEEPALIVE_COUNT_MAX,
    });
  });
}

async function sshExec(server, command) {
  let conn;
  try {
    conn = await getPooledConnection(server);
  } catch (err) {
    throw new Error(`SSH connect failed: ${err.message}`);
  }
  return new Promise((resolve, reject) => {
    let output = '';
    conn.exec(command, (err, stream) => {
      if (err) { sshPool.delete(server.name); return reject(err); }
      stream.on('data', (data) => { output += data.toString(); });
      stream.stderr.on('data', (data) => { output += data.toString(); });
      stream.on('close', () => resolve(output));
    });
  });
}

function parseConduitStatus(output, serverName) {
  const result = { name: serverName, status: 'offline', clients: 0, upload: '0 B', download: '0 B', uptime: 'N/A', error: null };
  if (!output) return result;

  if (output.includes('Active: active') || output.includes('running')) result.status = 'running';
  else if (output.includes('Active: inactive') || output.includes('dead')) result.status = 'stopped';

  const newFormat = [...output.matchAll(/\[STATS\]\s*Connecting:\s*(\d+)\s*\|\s*Connected:\s*(\d+)\s*\|\s*Up:\s*([^|]+)\|\s*Down:\s*([^|]+)\|\s*Uptime:\s*(\S+)/g)];
  const oldFormat = [...output.matchAll(/\[STATS\]\s*Clients:\s*(\d+)\s*\|\s*Up:\s*([^|]+)\|\s*Down:\s*([^|]+)\|\s*Uptime:\s*(\S+)/g)];

  if (newFormat.length > 0) {
    const m = newFormat[newFormat.length - 1];
    result.clients = parseInt(m[2], 10);
    result.upload = m[3].trim();
    result.download = m[4].trim();
    result.uptime = m[5].trim();
  } else if (oldFormat.length > 0) {
    const m = oldFormat[oldFormat.length - 1];
    result.clients = parseInt(m[1], 10);
    result.upload = m[2].trim();
    result.download = m[3].trim();
    result.uptime = m[4].trim();
  }

  if (output.includes('[OK] Connected to Psiphon network')) result.status = 'connected';
  return result;
}

function saveStats(stats) {
  const timestamp = Date.now();
  for (const s of stats) {
    db.run(`INSERT INTO stats (timestamp, server, status, clients, upload_bytes, download_bytes, uptime) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [timestamp, s.name, s.status, s.clients, parseBytes(s.upload), parseBytes(s.download), s.uptime]);
  }
  saveDb();
}

// Batched fetching
const BATCH_SIZE = 3;
const BATCH_DELAY = 500;

async function fetchServerStats(server) {
  try {
    const output = await sshExec(server, 'systemctl status conduit 2>/dev/null; journalctl -u conduit -n 20 --no-pager 2>/dev/null');
    const stats = parseConduitStatus(output, server.name);
    stats.host = server.host;
    return stats;
  } catch (err) {
    return { name: server.name, host: server.host, status: 'error', clients: 0, upload: '0 B', download: '0 B', uptime: 'N/A', error: err.message };
  }
}

async function fetchAllStats() {
  const now = Date.now();
  if (statsCache.data && (now - statsCache.timestamp) < CACHE_TTL) return statsCache.data;

  const results = [];
  for (let i = 0; i < SERVERS.length; i += BATCH_SIZE) {
    const batch = SERVERS.slice(i, i + BATCH_SIZE);
    results.push(...await Promise.all(batch.map(fetchServerStats)));
    if (i + BATCH_SIZE < SERVERS.length) await new Promise(r => setTimeout(r, BATCH_DELAY));
  }

  statsCache = { data: results, timestamp: now };
  try { saveStats(results); } catch (e) { console.error('Failed to save stats:', e); }
  return results;
}

// Express setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: process.env.SESSION_SECRET || 'conduit-dashboard-secret', resave: false, saveUninitialized: false, cookie: { maxAge: 86400000 } }));

const requireAuth = (req, res, next) => {
  if (req.session.authenticated) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  res.redirect('/login');
};

// Routes
app.get('/login', (_, res) => res.sendFile(join(__dirname, 'public/login.html')));
app.post('/login', (req, res) => {
  if (req.body.password === PASSWORD) { req.session.authenticated = true; res.redirect('/'); }
  else res.redirect('/login?error=1');
});
app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/login'); });

app.get('/api/stats', requireAuth, async (_, res) => {
  try { res.json(await fetchAllStats()); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/history', requireAuth, (req, res) => {
  try {
    const hours = parseInt(req.query.hours) || 24;
    const since = Date.now() - (hours * 3600000);
    const stmt = db.prepare(`SELECT timestamp, server, status, clients, upload_bytes, download_bytes, uptime FROM stats WHERE timestamp > ? ORDER BY timestamp ASC`);
    stmt.bind([since]);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/history/:server', requireAuth, (req, res) => {
  try {
    const hours = parseInt(req.query.hours) || 24;
    const since = Date.now() - (hours * 3600000);
    const stmt = db.prepare(`SELECT timestamp, status, clients, upload_bytes, download_bytes, uptime FROM stats WHERE server = ? AND timestamp > ? ORDER BY timestamp ASC`);
    stmt.bind([req.params.server, since]);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/bandwidth', requireAuth, (_, res) => {
  try {
    const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1).getTime();
    const results = {};
    for (const server of SERVERS) {
      const limit = server.bandwidthLimit || null;
      const stmt = db.prepare(`SELECT MAX(upload_bytes) as max_up, MAX(download_bytes) as max_down FROM stats WHERE server = ? AND timestamp > ?`);
      stmt.bind([server.name, startOfMonth]);
      if (stmt.step()) {
        const row = stmt.getAsObject();
        const total = (row.max_up || 0) + (row.max_down || 0);
        results[server.name] = { upload: row.max_up || 0, download: row.max_down || 0, total, limit, percent: limit ? Math.round((total / limit) * 10000) / 100 : 0 };
      }
      stmt.free();
    }
    res.json(results);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/control/:action', requireAuth, async (req, res) => {
  const { action } = req.params;
  if (!['stop', 'start', 'restart'].includes(action)) return res.status(400).json({ error: 'Invalid action' });
  try {
    const results = await Promise.all(SERVERS.map(async s => {
      try { await sshExec(s, `systemctl ${action} conduit`); return { server: s.name, success: true }; }
      catch (e) { return { server: s.name, success: false, error: e.message }; }
    }));
    statsCache = { data: null, timestamp: 0 };
    res.json({ action, results });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/control/:server/:action', requireAuth, async (req, res) => {
  const { server: serverName, action } = req.params;
  if (!['stop', 'start', 'restart'].includes(action)) return res.status(400).json({ error: 'Invalid action' });
  const server = SERVERS.find(s => s.name === serverName);
  if (!server) return res.status(404).json({ error: 'Server not found' });
  try {
    await sshExec(server, `systemctl ${action} conduit`);
    statsCache = { data: null, timestamp: 0 };
    res.json({ server: serverName, action, success: true });
  } catch (e) { res.status(500).json({ server: serverName, action, success: false, error: e.message }); }
});

app.use(requireAuth, express.static(join(__dirname, 'public')));
app.get('/', requireAuth, (_, res) => res.sendFile(join(__dirname, 'public/index.html')));

// Auto-stop servers exceeding bandwidth
async function checkBandwidthLimits() {
  const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1).getTime();
  for (const server of SERVERS) {
    if (!server.bandwidthLimit) continue;
    try {
      const stmt = db.prepare(`SELECT MAX(upload_bytes) as max_up, MAX(download_bytes) as max_down FROM stats WHERE server = ? AND timestamp > ?`);
      stmt.bind([server.name, startOfMonth]);
      if (stmt.step()) {
        const row = stmt.getAsObject();
        const total = (row.max_up || 0) + (row.max_down || 0);
        if (total >= server.bandwidthLimit) {
          console.log(`[AUTO-STOP] ${server.name} exceeded limit (${(total / 1024**4).toFixed(2)} TB / ${(server.bandwidthLimit / 1024**4).toFixed(2)} TB)`);
          try { await sshExec(server, 'systemctl stop conduit'); console.log(`[AUTO-STOP] ${server.name} stopped`); }
          catch (e) { console.error(`[AUTO-STOP] Failed to stop ${server.name}:`, e.message); }
        }
      }
      stmt.free();
    } catch (e) { console.error(`[AUTO-STOP] Error checking ${server.name}:`, e.message); }
  }
}

// Background polling
setInterval(async () => {
  try { await fetchAllStats(); await checkBandwidthLimits(); } catch (e) { console.error('Background poll failed:', e); }
}, 30000);

// Start
initDb().then(() => {
  app.listen(PORT, () => console.log(`Dashboard running on http://localhost:${PORT}`));
}).catch(e => { console.error(e); process.exit(1); });
