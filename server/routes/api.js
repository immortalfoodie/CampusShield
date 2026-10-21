/**
 * CampusShield — API Routes
 * 
 * Clean, structured REST API connecting the Presentation Layer to the Data and Analysis Layers.
 */
import { Router } from 'express';
import { current, openDb, destroyDb, getMode, setMode, q, now } from '../db.js';
import { loadData, loadScenario, baselineModel, recordSnapshot, setFindingStatus, upsertFinding } from '../services/workspace.js';
import { computeModel, recommendActions, PRIORITY_MATRIX, priorityOf } from '../services/risk.js';
import { validateScope } from '../services/scope.js';
import { findNmap, profiles } from '../services/nmap.js';
import { startScan, cancelScan, retestFinding, importNmapXml, importZapJson } from '../services/scanner.js';
import { seedDemo } from '../services/demo.js';
import { analyzePcap } from '../services/pcap.js';
import { analyzeLogs } from '../services/log.js';
import { generateReportPdf } from '../services/report.js';

export const apiRouter = Router();

// Middleware: ensure database is opened for the active mode
apiRouter.use((req, res, next) => {
  req.ctx = current();
  next();
});

// --------------------------------------------------------------------------
// 1. STATE & WORKSPACE
// --------------------------------------------------------------------------
apiRouter.get('/state', (req, res) => {
  try {
    const { db, mode } = req.ctx;
    const data = loadData(db);
    const scenario = loadScenario(db);
    const baseline = computeModel(data);
    const simulated = scenario.items.length ? computeModel(data, scenario) : null;
    const recommendations = recommendActions(data, scenario);
    const nmapPath = findNmap();
    const targets = q(db).all('SELECT * FROM targets ORDER BY id DESC');
    const scans = q(db).all('SELECT * FROM scans ORDER BY started_at DESC LIMIT 20');
    const snapshots = q(db).all('SELECT * FROM risk_snapshots ORDER BY at ASC LIMIT 20');

    res.json({
      mode,
      nmapAvailable: !!nmapPath,
      nmapPath: nmapPath || null,
      data,
      targets,
      scans,
      snapshots,
      baseline,
      simulated,
      scenario: scenario.items,
      recommendations,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.post('/mode', (req, res) => {
  try {
    const { mode } = req.body;
    if (!['demo', 'live'].includes(mode)) {
      return res.status(400).json({ error: 'Mode must be "demo" or "live"' });
    }
    setMode(mode);
    const targetDb = openDb(mode);
    // If switching to demo and demo.db is empty, seed it
    if (mode === 'demo') {
      const assetCount = q(targetDb).get('SELECT COUNT(*) as c FROM assets').c;
      if (assetCount === 0) seedDemo(targetDb);
    }
    res.json({ ok: true, mode });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.post('/reset-demo', (req, res) => {
  try {
    destroyDb('demo');
    const demoDb = openDb('demo');
    seedDemo(demoDb);
    setMode('demo');
    res.json({ ok: true, message: 'Demo environment reset to initial state.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --------------------------------------------------------------------------
// 2. TARGETS
// --------------------------------------------------------------------------
apiRouter.get('/targets', (req, res) => {
  try {
    const targets = q(req.ctx.db).all('SELECT * FROM targets ORDER BY id DESC');
    res.json(targets);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.post('/targets', async (req, res) => {
  try {
    const { name, address, description, environment, authorization_note, authorized_by } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Target name is required.' });
    if (!address?.trim()) return res.status(400).json({ error: 'Target address is required.' });
    if (!authorization_note?.trim()) return res.status(400).json({ error: 'Authorization note is required for all targets.' });

    const check = await validateScope(address);
    if (!check.ok) return res.status(400).json({ error: check.error });

    const x = q(req.ctx.db);
    const r = x.run(
      `INSERT INTO targets (name, address, description, environment, authorization_note, authorized_by, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'ready', ?)`,
      name.trim(), address.trim(), description || '', environment || 'VAPT Lab',
      authorization_note.trim(), authorized_by || 'Lab Administrator', now()
    );

    const target = x.get('SELECT * FROM targets WHERE id = ?', Number(r.lastInsertRowid));
    res.status(201).json(target);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.delete('/targets/:id', (req, res) => {
  try {
    const x = q(req.ctx.db);
    x.run('DELETE FROM targets WHERE id = ?', req.params.id);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --------------------------------------------------------------------------
// 3. NETWORK SCANS
// --------------------------------------------------------------------------
apiRouter.get('/scans/profiles', (req, res) => {
  res.json(profiles());
});

apiRouter.get('/scans', (req, res) => {
  try {
    const scans = q(req.ctx.db).all('SELECT * FROM scans ORDER BY started_at DESC LIMIT 50');
    res.json(scans);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.get('/scans/:id', (req, res) => {
  try {
    const scan = q(req.ctx.db).get('SELECT * FROM scans WHERE id = ?', req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    res.json(scan);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.post('/scans', async (req, res) => {
  try {
    const { targetId, profile, osDetect } = req.body;
    const x = q(req.ctx.db);
    const target = x.get('SELECT * FROM targets WHERE id = ?', targetId);
    if (!target) return res.status(404).json({ error: 'Target not found' });

    const scanId = await startScan({
      db: req.ctx.db,
      mode: req.ctx.mode,
      target,
      profile: profile || 'quick',
      osDetect: !!osDetect
    });

    res.status(201).json({ scanId, message: 'Scan started in background.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.post('/scans/:id/cancel', (req, res) => {
  try {
    const ok = cancelScan(Number(req.params.id));
    res.json({ ok, message: ok ? 'Scan cancel request sent.' : 'Scan not running or already finished.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.post('/scans/import-nmap', async (req, res) => {
  try {
    const { targetId, xml } = req.body;
    if (!xml?.trim()) return res.status(400).json({ error: 'Nmap XML content is required.' });
    const target = q(req.ctx.db).get('SELECT * FROM targets WHERE id = ?', targetId);
    if (!target) return res.status(404).json({ error: 'Target not found' });

    const result = await importNmapXml({ db: req.ctx.db, target, xml });
    res.status(201).json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

apiRouter.post('/scans/import-zap', (req, res) => {
  try {
    const { report } = req.body;
    if (!report) return res.status(400).json({ error: 'ZAP JSON report content is required.' });
    const result = importZapJson({ db: req.ctx.db, report });
    res.status(201).json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --------------------------------------------------------------------------
// 4. ASSETS
// --------------------------------------------------------------------------
apiRouter.get('/assets', (req, res) => {
  try {
    const assets = q(req.ctx.db).all('SELECT * FROM assets ORDER BY id');
    res.json(assets);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.get('/assets/:id', (req, res) => {
  try {
    const x = q(req.ctx.db);
    const asset = x.get('SELECT * FROM assets WHERE id = ?', req.params.id);
    if (!asset) return res.status(404).json({ error: 'Asset not found' });
    const services = x.all('SELECT * FROM services WHERE asset_id = ? ORDER BY port', asset.id);
    const findings = x.all('SELECT * FROM findings WHERE asset_id = ? ORDER BY id', asset.id);
    res.json({ ...asset, services, findings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.patch('/assets/:id', (req, res) => {
  try {
    const x = q(req.ctx.db);
    const { name, criticality, type, description, is_entry_point } = req.body;
    const a = x.get('SELECT * FROM assets WHERE id = ?', req.params.id);
    if (!a) return res.status(404).json({ error: 'Asset not found' });

    x.run(
      `UPDATE assets SET 
         name = COALESCE(?, name),
         criticality = COALESCE(?, criticality),
         type = COALESCE(?, type),
         description = COALESCE(?, description),
         is_entry_point = COALESCE(?, is_entry_point)
       WHERE id = ?`,
      name, criticality, type, description, is_entry_point, a.id
    );

    recordSnapshot(req.ctx.db, `Updated asset ${a.name}`);
    res.json(x.get('SELECT * FROM assets WHERE id = ?', a.id));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.delete('/assets/:id', (req, res) => {
  try {
    const x = q(req.ctx.db);
    x.run('DELETE FROM assets WHERE id = ?', req.params.id);
    recordSnapshot(req.ctx.db, `Deleted asset #${req.params.id}`);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --------------------------------------------------------------------------
// 5. VULNERABILITIES & FINDINGS
// --------------------------------------------------------------------------
apiRouter.get('/findings', (req, res) => {
  try {
    const findings = q(req.ctx.db).all('SELECT * FROM findings ORDER BY id DESC');
    res.json(findings);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.post('/findings', (req, res) => {
  try {
    const { asset_id, port, title, severity, description, evidence, source, cve, cwe, recommendation } = req.body;
    if (!asset_id) return res.status(400).json({ error: 'Affected asset is required.' });
    if (!title?.trim()) return res.status(400).json({ error: 'Finding title is required.' });

    const result = upsertFinding(req.ctx.db, {
      asset_id,
      port: port ? Number(port) : null,
      title: title.trim(),
      severity: severity || 'medium',
      description: description || '',
      evidence: evidence || '',
      source: source || 'Manual Assessment',
      cve: cve || null,
      cwe: cwe || null,
      recommendation: recommendation || 'Investigate and remediate configuration or code.'
    });

    recordSnapshot(req.ctx.db, `Added finding "${title}"`);
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.patch('/findings/:id/status', (req, res) => {
  try {
    const { status, note } = req.body;
    const updated = setFindingStatus(req.ctx.db, req.params.id, status, note || '');
    recordSnapshot(req.ctx.db, `Status change: ${updated.title} -> ${status}`);
    res.json(updated);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

apiRouter.get('/findings/:id/history', (req, res) => {
  try {
    const history = q(req.ctx.db).all('SELECT * FROM finding_history WHERE finding_id = ? ORDER BY at DESC', req.params.id);
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.post('/findings/:id/retest', async (req, res) => {
  try {
    const result = await retestFinding({
      db: req.ctx.db,
      mode: req.ctx.mode,
      findingId: Number(req.params.id)
    });
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --------------------------------------------------------------------------
// 6. RELATIONSHIPS & SECURITY GRAPH
// --------------------------------------------------------------------------
apiRouter.get('/relationships', (req, res) => {
  try {
    const rels = q(req.ctx.db).all('SELECT * FROM relationships ORDER BY id');
    res.json(rels);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.post('/relationships', (req, res) => {
  try {
    const { source_id, target_id, type, description, nature, direction, evidence } = req.body;
    if (source_id === target_id) return res.status(400).json({ error: 'Source and target assets must be different.' });
    if (!type?.trim()) return res.status(400).json({ error: 'Relationship type is required.' });

    const x = q(req.ctx.db);
    const r = x.run(
      'INSERT INTO relationships (source_id, target_id, type, description, nature, direction, evidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      source_id, target_id, type.trim(), description || '', nature || 'modeled_admin', direction || 'directed', evidence || '', now()
    );

    recordSnapshot(req.ctx.db, `Added relationship [${type}]`);
    res.status(201).json({ id: Number(r.lastInsertRowid), source_id, target_id, type, nature, direction, evidence });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

apiRouter.delete('/relationships/:id', (req, res) => {
  try {
    const x = q(req.ctx.db);
    x.run('DELETE FROM relationships WHERE id = ?', req.params.id);
    recordSnapshot(req.ctx.db, `Removed relationship #${req.params.id}`);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --------------------------------------------------------------------------
// 7. RISK & REMEDIATION SIMULATION
// --------------------------------------------------------------------------
apiRouter.get('/risk', (req, res) => {
  try {
    const data = loadData(req.ctx.db);
    const scenario = loadScenario(req.ctx.db);
    const baseline = computeModel(data);
    const simulated = scenario.items.length ? computeModel(data, scenario) : null;
    const recommendations = recommendActions(data, scenario);

    res.json({
      baseline,
      simulated,
      scenario: scenario.items,
      recommendations,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.post('/simulation/toggle', (req, res) => {
  try {
    const { kind, ref_id, label } = req.body;
    if (!['finding', 'relationship', 'service'].includes(kind)) {
      return res.status(400).json({ error: 'Invalid simulation item kind.' });
    }
    const x = q(req.ctx.db);
    const existing = x.get('SELECT * FROM simulation_items WHERE kind = ? AND ref_id = ?', kind, ref_id);
    if (existing) {
      x.run('DELETE FROM simulation_items WHERE id = ?', existing.id);
    } else {
      x.run('INSERT INTO simulation_items (kind, ref_id, label, created_at) VALUES (?, ?, ?, ?)', kind, ref_id, label || '', now());
    }
    res.json({ ok: true, active: !existing });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.post('/simulation/clear', (req, res) => {
  try {
    q(req.ctx.db).run('DELETE FROM simulation_items');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --------------------------------------------------------------------------
// 8. PACKET & LOG ANALYSIS
// --------------------------------------------------------------------------
apiRouter.post('/analyze-pcap', (req, res) => {
  try {
    const { content, filename } = req.body;
    if (!content) return res.status(400).json({ error: 'Base64 PCAP content is required.' });
    const buffer = Buffer.from(content, 'base64');
    const result = analyzePcap(buffer);

    q(req.ctx.db).run(
      'INSERT INTO analyses (kind, filename, created_at, summary) VALUES (?, ?, ?, ?)',
      'pcap', filename || 'capture.pcap', now(), JSON.stringify(result)
    );

    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

apiRouter.post('/analyze-log', (req, res) => {
  try {
    const { content, filename } = req.body;
    if (!content) return res.status(400).json({ error: 'Log content is required.' });
    const result = analyzeLogs(content, filename || 'auth.log');

    q(req.ctx.db).run(
      'INSERT INTO analyses (kind, filename, created_at, summary) VALUES (?, ?, ?, ?)',
      'log', filename || 'auth.log', now(), JSON.stringify(result)
    );

    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --------------------------------------------------------------------------
// 9. PDF REPORT EXPORT
// --------------------------------------------------------------------------
apiRouter.get('/report.pdf', async (req, res) => {
  try {
    const { db, mode } = req.ctx;
    const pdfBuffer = await generateReportPdf(db, mode);
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="CampusShield_VAPT_Report_${mode}.pdf"`);
    res.setHeader('Content-Length', pdfBuffer.length);
    res.end(pdfBuffer);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
