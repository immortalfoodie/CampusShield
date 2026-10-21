/**
 * CampusShield — Workspace helpers shared by routes and scanners.
 */
import { q, now } from '../db.js';
import { computeModel, STATUSES } from './risk.js';

export function loadData(db) {
  const x = q(db);
  return {
    assets: x.all('SELECT * FROM assets ORDER BY id'),
    services: x.all('SELECT * FROM services ORDER BY asset_id, port'),
    findings: x.all('SELECT * FROM findings ORDER BY id'),
    relationships: x.all('SELECT * FROM relationships ORDER BY id'),
  };
}

/** The current what-if scenario stored in simulation_items. */
export function loadScenario(db) {
  const items = q(db).all('SELECT * FROM simulation_items');
  return {
    items,
    fixedFindings: new Set(items.filter(i => i.kind === 'finding').map(i => i.ref_id)),
    blockedRels: new Set(items.filter(i => i.kind === 'relationship').map(i => i.ref_id)),
    closedServices: new Set(items.filter(i => i.kind === 'service').map(i => i.ref_id)),
  };
}

export function baselineModel(db) { return computeModel(loadData(db)); }

export function recordSnapshot(db, label, scanId = null) {
  const m = baselineModel(db);
  q(db).run(`INSERT INTO risk_snapshots (at,label,score,level,vulnerabilities,high_risk_assets,risky_paths,assets,scan_id)
    VALUES (?,?,?,?,?,?,?,?,?)`, now(), label, m.overall.score, m.overall.level, m.overall.vulnerabilities,
    m.overall.highRiskAssets, m.overall.riskyPaths, m.overall.assets, scanId);
  return m;
}

export function setFindingStatus(db, id, status, note = '') {
  if (!STATUSES.includes(status)) throw new Error('Invalid status');
  const x = q(db);
  const f = x.get('SELECT * FROM findings WHERE id = ?', id);
  if (!f) throw new Error('Finding not found');
  if (f.status === status) return f;
  x.run('UPDATE findings SET status = ?, updated_at = ? WHERE id = ?', status, now(), id);
  x.run('INSERT INTO finding_history (finding_id, from_status, to_status, note, at) VALUES (?,?,?,?,?)', id, f.status, status, note, now());
  return x.get('SELECT * FROM findings WHERE id = ?', id);
}

/**
 * Insert a finding or update the existing one (deduplicated by fingerprint).
 * A previously fixed finding that is detected again is re-opened (regression).
 */
export function upsertFinding(db, f, scanId = null) {
  const x = q(db);
  const fingerprint = f.fingerprint || `${f.asset_id}|${f.source}|${f.check_id || f.title}|${f.port ?? ''}`;
  const existing = x.get('SELECT * FROM findings WHERE fingerprint = ?', fingerprint);
  if (existing) {
    x.run(`UPDATE findings SET evidence = ?, last_seen = ?, scan_id = COALESCE(?, scan_id), cve = COALESCE(?, cve), cvss = COALESCE(?, cvss),
      finding_type = COALESCE(?, finding_type), confidence = COALESCE(?, confidence), severity_rationale = COALESCE(?, severity_rationale),
      limitations = COALESCE(?, limitations) WHERE id = ?`,
      f.evidence || existing.evidence, now(), scanId, f.cve || null, f.cvss ?? null,
      f.finding_type || null, f.confidence || null, f.severity_rationale || null, f.limitations || null, existing.id);
    if (['fixed', 'retested'].includes(existing.status)) {
      setFindingStatus(db, existing.id, 'open', 'Detected again in a later assessment (regression).');
    }
    return { id: existing.id, created: false };
  }
  const r = x.run(`INSERT INTO findings (asset_id, port, title, severity, description, evidence, source, cve, cwe, cvss,
      recommendation, status, fingerprint, check_id, created_at, updated_at, last_seen, scan_id,
      finding_type, confidence, severity_rationale, limitations)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    f.asset_id, f.port ?? null, f.title, f.severity, f.description || '', f.evidence || '', f.source,
    f.cve || null, f.cwe || null, f.cvss ?? null, f.recommendation || 'Review this observation and retest after remediation.',
    f.status || 'open', fingerprint, f.check_id || null, now(), now(), now(), scanId,
    f.finding_type || 'exposure', f.confidence || 'heuristic', f.severity_rationale || '', f.limitations || '');
  const id = Number(r.lastInsertRowid);
  x.run('INSERT INTO finding_history (finding_id, from_status, to_status, note, at) VALUES (?,?,?,?,?)', id, null, f.status || 'open', `Detected by ${f.source}`, now());
  return { id, created: true };
}

/** CVE identifiers are only stored when they match the official format; otherwise "Not Mapped". */
export function cleanCve(value) {
  const v = String(value || '').trim().toUpperCase();
  return /^CVE-\d{4}-\d{4,}$/.test(v) ? v : null;
}
