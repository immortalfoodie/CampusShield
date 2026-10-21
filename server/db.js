/**
 * CampusShield — Data layer
 *
 * Two completely separate SQLite workspaces are kept:
 *   data/live.db  -> Live Lab Mode (real scans of authorized lab systems)
 *   data/demo.db  -> Demo Mode (simulated environment, clearly labelled)
 * Switching mode only changes which file is active, so no data is ever lost.
 */
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DATA_DIR = path.resolve(__dirname, '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  description TEXT DEFAULT '',
  environment TEXT DEFAULT 'VAPT Lab',
  authorization_note TEXT NOT NULL,
  authorized_by TEXT DEFAULT '',
  status TEXT DEFAULT 'ready',
  created_at TEXT,
  last_scan_at TEXT
);
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  ip TEXT NOT NULL UNIQUE,
  hostname TEXT DEFAULT '',
  os TEXT DEFAULT 'Unknown',
  mac TEXT DEFAULT '',
  type TEXT DEFAULT 'server',
  criticality TEXT DEFAULT 'medium',
  is_entry_point INTEGER DEFAULT 0,
  description TEXT DEFAULT '',
  host_status TEXT DEFAULT 'up',
  source TEXT DEFAULT 'scan',
  first_seen TEXT,
  last_seen TEXT
);
CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  port INTEGER NOT NULL,
  protocol TEXT DEFAULT 'tcp',
  service TEXT DEFAULT '',
  product TEXT DEFAULT '',
  version TEXT DEFAULT '',
  extra TEXT DEFAULT '',
  tunnel TEXT DEFAULT '',
  last_seen TEXT,
  UNIQUE(asset_id, port, protocol)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  port INTEGER,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  description TEXT DEFAULT '',
  evidence TEXT DEFAULT '',
  source TEXT NOT NULL,
  cve TEXT,
  cwe TEXT,
  cvss REAL,
  recommendation TEXT DEFAULT '',
  status TEXT DEFAULT 'open',
  fingerprint TEXT UNIQUE,
  check_id TEXT,
  created_at TEXT,
  updated_at TEXT,
  last_seen TEXT,
  scan_id INTEGER,
  finding_type TEXT DEFAULT 'exposure',
  confidence TEXT DEFAULT 'heuristic',
  severity_rationale TEXT DEFAULT '',
  limitations TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS finding_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
  from_status TEXT,
  to_status TEXT,
  note TEXT,
  at TEXT
);
CREATE TABLE IF NOT EXISTS relationships (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  target_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  description TEXT DEFAULT '',
  created_at TEXT,
  nature TEXT DEFAULT 'modeled_admin',
  direction TEXT DEFAULT 'directed',
  evidence TEXT DEFAULT '',
  UNIQUE(source_id, target_id, type)
);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL,
  target_name TEXT,
  target_address TEXT,
  profile TEXT,
  status TEXT,
  progress REAL DEFAULT 0,
  phase TEXT DEFAULT '',
  command TEXT DEFAULT '',
  started_at TEXT,
  finished_at TEXT,
  hosts_up INTEGER DEFAULT 0,
  ports_found INTEGER DEFAULT 0,
  findings_new INTEGER DEFAULT 0,
  risk_score INTEGER,
  error TEXT,
  log TEXT DEFAULT '',
  is_demo INTEGER DEFAULT 0,
  results TEXT,
  duration_ms INTEGER DEFAULT 0,
  exit_code INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS simulation_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  ref_id INTEGER NOT NULL,
  label TEXT,
  created_at TEXT,
  UNIQUE(kind, ref_id)
);
CREATE TABLE IF NOT EXISTS risk_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT,
  label TEXT,
  score INTEGER,
  level TEXT,
  vulnerabilities INTEGER,
  high_risk_assets INTEGER,
  risky_paths INTEGER,
  assets INTEGER,
  scan_id INTEGER
);
CREATE TABLE IF NOT EXISTS analyses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  filename TEXT,
  created_at TEXT,
  summary TEXT
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
`;

function migrate(db) {
  const getCols = table => new Set(db.prepare(`PRAGMA table_info(${table})`).all().map(r => r.name));
  
  const findingCols = getCols('findings');
  if (!findingCols.has('finding_type')) db.exec("ALTER TABLE findings ADD COLUMN finding_type TEXT DEFAULT 'exposure'");
  if (!findingCols.has('confidence')) db.exec("ALTER TABLE findings ADD COLUMN confidence TEXT DEFAULT 'heuristic'");
  if (!findingCols.has('severity_rationale')) db.exec("ALTER TABLE findings ADD COLUMN severity_rationale TEXT DEFAULT ''");
  if (!findingCols.has('limitations')) db.exec("ALTER TABLE findings ADD COLUMN limitations TEXT DEFAULT ''");

  const relCols = getCols('relationships');
  if (!relCols.has('nature')) db.exec("ALTER TABLE relationships ADD COLUMN nature TEXT DEFAULT 'modeled_admin'");
  if (!relCols.has('direction')) db.exec("ALTER TABLE relationships ADD COLUMN direction TEXT DEFAULT 'directed'");
  if (!relCols.has('evidence')) db.exec("ALTER TABLE relationships ADD COLUMN evidence TEXT DEFAULT ''");

  const scanCols = getCols('scans');
  if (!scanCols.has('duration_ms')) db.exec("ALTER TABLE scans ADD COLUMN duration_ms INTEGER DEFAULT 0");
  if (!scanCols.has('exit_code')) db.exec("ALTER TABLE scans ADD COLUMN exit_code INTEGER DEFAULT 0");
}

const handles = {};

export function openDb(mode) {
  if (!['demo', 'live'].includes(mode)) throw new Error('Unknown workspace mode');
  if (!handles[mode]) {
    const db = new DatabaseSync(path.join(DATA_DIR, `${mode}.db`));
    db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;');
    db.exec(SCHEMA);
    migrate(db);
    handles[mode] = db;
  }
  return handles[mode];
}

/** Close and delete a workspace file (used to reset the demo environment). */
export function destroyDb(mode) {
  if (handles[mode]) {
    try { handles[mode].close(); } catch {}
    delete handles[mode];
  }
  try {
    for (const suffix of ['', '-wal', '-shm']) {
      const f = path.join(DATA_DIR, `${mode}.db${suffix}`);
      if (fs.existsSync(f)) fs.unlinkSync(f);
    }
  } catch (err) {
    if (err.code === 'EBUSY') {
      // On Windows when file locks prevent unlinking, truncate all tables to reset state cleanly
      const db = new DatabaseSync(path.join(DATA_DIR, `${mode}.db`));
      db.exec('PRAGMA foreign_keys = OFF;');
      const tables = ['targets', 'assets', 'services', 'findings', 'finding_history', 'relationships', 'scans', 'simulation_items', 'risk_snapshots', 'analyses', 'meta'];
      for (const t of tables) {
        try { db.exec(`DELETE FROM ${t};`); } catch {}
      }
      db.exec('PRAGMA foreign_keys = ON;');
      db.close();
    } else {
      throw err;
    }
  }
}

function readConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); } catch { return { mode: 'demo' }; }
}
export function getMode() { return readConfig().mode === 'live' ? 'live' : 'demo'; }
export function setMode(mode) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify({ ...readConfig(), mode }, null, 2));
}

/** Small query helpers bound to a database handle. */
export function q(db) {
  return {
    all: (sql, ...p) => db.prepare(sql).all(...p),
    get: (sql, ...p) => db.prepare(sql).get(...p),
    run: (sql, ...p) => db.prepare(sql).run(...p),
    tx(fn) {
      db.exec('BEGIN');
      try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; }
    },
  };
}

/** Database of the currently active mode. */
export function current() {
  const mode = getMode();
  return { mode, db: openDb(mode), ...q(openDb(mode)) };
}

export const now = () => new Date().toISOString();
