/**
 * CampusShield — Scan orchestrator.
 *
 *  Target ──► Scope check ──► Host discovery (CIDR only) ──► Nmap service scan
 *        ──► Asset inventory upsert ──► Service rules + NSE + web baseline
 *        ──► Auto-retest of fixed findings ──► Risk snapshot
 *
 * Scans run as background jobs; the UI polls /api/scans/:id for progress.
 */
import { q, now } from '../db.js';
import { validateScope, ipToInt, isAllowedLabAddress } from './scope.js';
import { runNmap, parseNmapXml, profiles } from './nmap.js';
import { serviceRuleFindings, nseFindings, webBaseline } from './checks.js';
import { upsertFinding, setFindingStatus, recordSnapshot } from './workspace.js';
import { DEMO_SCAN_PHASES } from './demo.js';

const jobs = new Map(); // scanId -> { controller }
const RETESTABLE = /^(CampusShield Service Rules|CampusShield Web Baseline|Nmap NSE)/;

function logTo(db, scanId) {
  return line => {
    const x = q(db);
    const cur = x.get('SELECT log FROM scans WHERE id = ?', scanId)?.log || '';
    x.run('UPDATE scans SET log = ? WHERE id = ?', (cur + `[${new Date().toLocaleTimeString()}] ${line}\n`).slice(-20000), scanId);
  };
}
function progressTo(db, scanId) {
  return (progress, phase) => q(db).run('UPDATE scans SET progress = ?, phase = COALESCE(?, phase) WHERE id = ?', Math.round(progress * 10) / 10, phase ?? null, scanId);
}

export function inScope(ip, target) {
  if (target.address.includes('/')) {
    const [net, bits] = target.address.split('/');
    const mask = (~0 << (32 - Number(bits))) >>> 0;
    return ((ipToInt(ip) & mask) >>> 0) === ((ipToInt(net) & mask) >>> 0);
  }
  return true; // single IP / hostname targets: Nmap was only pointed at that host
}

/** Store one discovered host as an asset with its services and findings. */
export async function ingestHost(db, target, host, scanId, { nse = true, web = false, log = () => {}, singleHost = false } = {}) {
  const x = q(db);
  let asset = x.get('SELECT * FROM assets WHERE ip = ?', host.ip);
  const defaultName = singleHost ? target.name : (host.hostname || `Host ${host.ip}`);
  if (!asset) {
    const r = x.run(`INSERT INTO assets (target_id,name,ip,hostname,os,mac,type,criticality,description,host_status,source,first_seen,last_seen)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, target.id, defaultName, host.ip, host.hostname, host.os || 'Unknown', host.mac,
      guessType(host.ports), 'medium', singleHost ? target.description : `Discovered in ${target.name}`, 'up', 'scan', now(), now());
    asset = x.get('SELECT * FROM assets WHERE id = ?', Number(r.lastInsertRowid));
    log(`New asset discovered: ${asset.name} (${host.ip})`);
  } else {
    x.run(`UPDATE assets SET hostname = CASE WHEN ? <> '' THEN ? ELSE hostname END, os = CASE WHEN ? <> '' THEN ? ELSE os END,
      mac = CASE WHEN ? <> '' THEN ? ELSE mac END, host_status = 'up', last_seen = ? WHERE id = ?`,
      host.hostname, host.hostname, host.os, host.os, host.mac, host.mac, now(), asset.id);
  }

  // Replace the service list with what was observed now (closed services disappear).
  x.run('DELETE FROM services WHERE asset_id = ?', asset.id);
  for (const p of host.ports)
    x.run('INSERT INTO services (asset_id,port,protocol,service,product,version,extra,tunnel,last_seen) VALUES (?,?,?,?,?,?,?,?,?)',
      asset.id, p.port, p.protocol, p.service, p.product, p.version, p.extra, p.tunnel, now());
  const services = x.all('SELECT * FROM services WHERE asset_id = ?', asset.id);
  log(`${host.ip}: ${services.length} open service(s) — ${services.map(s => `${s.port}/${s.service}`).join(', ') || 'none'}`);

  const candidates = [...serviceRuleFindings(asset, services)];
  if (nse) candidates.push(...nseFindings(asset, host.ports));
  if (web) candidates.push(...await webBaseline(asset, services, log));

  let created = 0;
  const seen = new Set();
  for (const f of candidates) {
    const r = upsertFinding(db, f, scanId);
    seen.add(r.id);
    if (r.created) created++;
  }

  // Auto-retest: scanner-detected findings that were marked fixed and are no longer observed.
  const prior = x.all("SELECT * FROM findings WHERE asset_id = ? AND status IN ('fixed','open','under_review','planned')", asset.id);
  for (const f of prior) {
    if (seen.has(f.id) || !RETESTABLE.test(f.source)) continue;
    if (f.source.startsWith('CampusShield Web Baseline') && !web) continue;
    if (f.source.startsWith('Nmap NSE') && !nse) continue;
    if (f.status === 'fixed') {
      setFindingStatus(db, f.id, 'retested', `Not detected in scan #${scanId}; remediation verified.`);
      log(`Retest passed: "${f.title}" no longer detected.`);
    } else {
      log(`Note: "${f.title}" was not observed in this scan. Mark it Fixed to verify it on the next scan.`);
    }
  }
  return { asset, services: services.length, created };
}

function guessType(ports) {
  const p = new Set(ports.map(x => x.port));
  if ([3306, 5432, 1433, 1521, 27017].some(x => p.has(x))) return 'database';
  if ([80, 443, 8080, 8443].some(x => p.has(x))) return 'application';
  if ([3389, 135, 139].some(x => p.has(x)) && !p.has(22)) return 'endpoint';
  return 'server';
}

/** Start a scan job. Returns the scan id immediately. */
export async function startScan({ db, mode, target, profile = 'quick', osDetect = false }) {
  const x = q(db);
  const profKey = ['quick', 'standard', 'vuln'].includes(profile) ? profile : 'quick';
  const prof = profiles()[profKey];
  const r = x.run(`INSERT INTO scans (target_id,target_name,target_address,profile,status,progress,phase,started_at,is_demo)
    VALUES (?,?,?,?,?,?,?,?,?)`, target.id, target.name, target.address, profKey, 'running', 0, 'Queued', now(), mode === 'demo' ? 1 : 0);
  const scanId = Number(r.lastInsertRowid);
  x.run("UPDATE targets SET status = 'scanning' WHERE id = ?", target.id);
  const controller = new AbortController();
  jobs.set(scanId, { controller });
  const run = mode === 'demo' ? runDemoScan : runLiveScan;
  const startTime = Date.now();
  run({ db, target, scanId, prof, profKey, osDetect, signal: controller.signal, startTime })
    .catch(e => {
      const log = logTo(db, scanId);
      log(`ERROR: ${e.message}`);
      const isCancelled = controller.signal.aborted || /cancelled/i.test(e.message);
      const status = isCancelled ? 'cancelled' : 'failed';
      const phase = isCancelled ? 'Cancelled' : 'Failed';
      x.run("UPDATE scans SET status = ?, error = ?, finished_at = ?, phase = ?, duration_ms = ? WHERE id = ?",
        status, e.message, now(), phase, Date.now() - startTime, scanId);
    })
    .finally(() => {
      jobs.delete(scanId);
      x.run("UPDATE targets SET status = CASE WHEN EXISTS(SELECT 1 FROM scans WHERE target_id = ? AND status = 'completed') THEN 'scanned' ELSE 'ready' END, last_scan_at = ? WHERE id = ?", target.id, now(), target.id);
    });
  return scanId;
}

export function cancelScan(scanId) {
  const j = jobs.get(scanId);
  if (!j) return false;
  j.controller.abort();
  return true;
}

async function runLiveScan({ db, target, scanId, prof, profKey, osDetect, signal, startTime = Date.now() }) {
  const x = q(db);
  const log = logTo(db, scanId), progress = progressTo(db, scanId);
  log(`Live scan of authorized target "${target.name}" (${target.address}) — profile: ${prof.label}`);
  log(`Authorization on record: ${target.authorization_note}`);
  progress(2, 'Validating authorized scope');
  const scope = await validateScope(target.address);
  if (!scope.ok) throw new Error(`Scope check failed: ${scope.error}`);

  let hosts;
  if (scope.kind === 'cidr') {
    progress(5, 'Host discovery (ping sweep)');
    const xml = await runNmap(['-sn', '-T4', scope.address], { signal, onLog: log,
      onProgress: p => progress(5 + p.percent * 0.15, `Host discovery — ${p.task}`) });
    hosts = parseNmapXml(xml).hosts.filter(h => h.status === 'up').map(h => h.ip);
    // Scope Guard: Ensure all discovered hosts in CIDR satisfy authorized lab ranges
    hosts = hosts.filter(h => isAllowedLabAddress(h) && inScope(h, target));
    log(`Discovery found ${hosts.length} live in-scope host(s): ${hosts.join(', ') || 'none'}`);
    if (!hosts.length) throw new Error('No live hosts found in the range. Check that the lab VMs are running and reachable.');
  } else {
    // If hostname (like localhost), use the validated resolved IP address to prevent DNS rebinding
    const resolvedIp = scope.resolved && scope.resolved.length ? scope.resolved[0] : scope.address;
    if (!isAllowedLabAddress(resolvedIp)) {
      throw new Error(`Target address ${resolvedIp} is not in authorized laboratory scope.`);
    }
    hosts = [resolvedIp];
  }

  progress(20, 'Port & service detection');
  const args = [...prof.args, '-Pn'];
  if (osDetect) args.push('-O', '--osscan-guess');
  x.run('UPDATE scans SET command = ? WHERE id = ?', `nmap ${args.join(' ')} ${hosts.join(' ')}`, scanId);
  let xml;
  try {
    xml = await runNmap([...args, ...hosts], { signal, onLog: log,
      onProgress: p => progress(20 + p.percent * 0.6, `${p.task} (${Math.round(p.percent)}%)`) });
  } catch (e) {
    if (osDetect && /root|privilege|admin/i.test(e.message)) {
      log('OS detection needs administrator/root privileges — retrying without -O.');
      xml = await runNmap([...prof.args, '-Pn', ...hosts], { signal, onLog: log, onProgress: p => progress(20 + p.percent * 0.6, p.task) });
    } else throw e;
  }
  const parsed = parseNmapXml(xml);
  const up = parsed.hosts.filter(h => h.status === 'up' && inScope(h.ip, target));
  if (!up.length) throw new Error('Nmap returned no reachable host. Verify the IP and that the VM is running.');

  progress(82, prof.web ? 'Safe vulnerability checks & web baseline' : 'Applying service rules');
  let ports = 0, created = 0;
  for (const h of up) {
    const r = await ingestHost(db, target, h, scanId, { nse: prof.nse, web: prof.web, log, singleHost: scope.kind !== 'cidr' });
    ports += r.services; created += r.created;
  }

  progress(96, 'Recalculating risk model');
  const m = recordSnapshot(db, `Scan #${scanId} — ${target.name}`, scanId);
  const durationMs = Date.now() - startTime;
  x.run(`UPDATE scans SET status='completed', progress=100, phase='Completed', finished_at=?, hosts_up=?, ports_found=?, findings_new=?, risk_score=?,
    results=?, duration_ms=?, exit_code=? WHERE id=?`, now(), up.length, ports, created, m.overall.score,
    JSON.stringify(up.map(h => ({ ip: h.ip, hostname: h.hostname, os: h.os, ports: h.ports.map(({ scripts, ...p }) => p) }))),
    durationMs, xml.exitCode ?? 0, scanId);
  log(`Completed: ${up.length} host(s), ${ports} open service(s), ${created} new finding(s). Duration: ${Math.round(durationMs / 1000)}s. Workspace risk ${m.overall.score}/100.`);
}

const sleep = (ms, signal) => new Promise((res, rej) => {
  const t = setTimeout(res, ms);
  signal?.addEventListener('abort', () => { clearTimeout(t); rej(new Error('Scan cancelled by user.')); });
});

/** Demo Mode: animate the same phases without touching the network. */
async function runDemoScan({ db, target, scanId, prof, profKey, signal, startTime = Date.now() }) {
  const x = q(db);
  const log = logTo(db, scanId), progress = progressTo(db, scanId);
  log('DEMO DATA — NOT FROM A LIVE SCAN. No packets are sent.');
  log(`Simulating "${prof.label}" against ${target.name} (${target.address})`);
  const assets = x.all('SELECT * FROM assets').filter(a => target.address.includes('/') ? inScope(a.ip, target) : a.ip === target.address);
  for (const [phase, pct] of DEMO_SCAN_PHASES) {
    progress(pct - 3, phase);
    log(phase + '…');
    await sleep(900 + Math.random() * 700, signal);
    if (phase.startsWith('Service')) for (const a of assets) {
      const svcs = x.all('SELECT * FROM services WHERE asset_id = ?', a.id);
      log(`${a.ip}: ${svcs.map(s => `${s.port}/${s.service} ${s.product} ${s.version}`.trim()).join(', ')}`);
    }
    progress(pct, phase);
  }
  let ports = 0;
  for (const a of assets) {
    x.run('UPDATE assets SET last_seen = ? WHERE id = ?', now(), a.id);
    x.run('UPDATE services SET last_seen = ? WHERE asset_id = ?', now(), a.id);
    x.run("UPDATE findings SET last_seen = ? WHERE asset_id = ? AND status IN ('open','under_review','planned')", now(), a.id);
    ports += x.get('SELECT COUNT(*) n FROM services WHERE asset_id = ?', a.id).n;
    // Demo retest: findings marked fixed are treated as no longer detected.
    for (const f of x.all("SELECT * FROM findings WHERE asset_id = ? AND status = 'fixed'", a.id)) {
      setFindingStatus(db, f.id, 'retested', `Simulated retest in demo scan #${scanId}.`);
      log(`Retest (simulated): "${f.title}" no longer detected.`);
    }
  }
  const m = recordSnapshot(db, `Scan #${scanId} — ${target.name} (demo)`, scanId);
  const durationMs = Date.now() - startTime;
  x.run(`UPDATE scans SET status='completed', progress=100, phase='Completed', finished_at=?, hosts_up=?, ports_found=?, findings_new=0, risk_score=?, duration_ms=?, exit_code=0 WHERE id=?`,
    now(), assets.length, ports, m.overall.score, durationMs, scanId);
  log(`Completed (demo): ${assets.length} host(s), ${ports} services. Duration: ${Math.round(durationMs / 1000)}s. Workspace risk ${m.overall.score}/100.`);
}

/** Retest a single finding. Live: targeted Nmap re-check of that port. Demo: simulated. */
export async function retestFinding({ db, mode, findingId }) {
  const x = q(db);
  const f = x.get('SELECT * FROM findings WHERE id = ?', findingId);
  if (!f) throw new Error('Finding not found');
  const asset = x.get('SELECT * FROM assets WHERE id = ?', f.asset_id);
  if (mode === 'demo') {
    setFindingStatus(db, f.id, 'retested', 'Simulated retest (demo): issue no longer detected.');
    recordSnapshot(db, `Retest — ${f.title} (demo)`);
    return { result: 'passed', message: 'Demo retest passed — the finding is no longer detected.' };
  }
  if (!RETESTABLE.test(f.source) || f.port == null)
    throw new Error('This finding came from a manual review or imported report. Re-run that tool, then set status to Retested manually.');
  const scope = await validateScope(asset.ip);
  if (!scope.ok) throw new Error(scope.error);
  const args = ['-sT', '-sV', '-Pn', '-p', String(f.port)];
  if (f.source.startsWith('Nmap NSE')) args.push('--script', (f.source.split(': ')[1] || 'banner'));
  const parsed = parseNmapXml(await runNmap([...args, asset.ip], {}));
  const host = parsed.hosts.find(h => h.ip === asset.ip) || { ports: [] };
  const services = host.ports.map(p => ({ ...p, asset_id: asset.id }));
  let candidates = [...serviceRuleFindings(asset, services), ...nseFindings(asset, host.ports)];
  if (f.source.startsWith('CampusShield Web Baseline')) candidates.push(...await webBaseline(asset, services));
  const fp = c => `${c.asset_id}|${c.source}|${c.check_id || c.title}|${c.port ?? ''}`;
  const still = candidates.some(c => fp(c) === f.fingerprint);
  if (!host.ports.find(p => p.port === f.port)) x.run('DELETE FROM services WHERE asset_id = ? AND port = ?', asset.id, f.port);
  if (still) {
    setFindingStatus(db, f.id, 'open', `Retest on ${now().slice(0, 10)}: still detected.`);
    return { result: 'failed', message: 'Retest failed — the issue is still detected. Status set back to Open.' };
  }
  setFindingStatus(db, f.id, 'retested', `Targeted retest of port ${f.port}: not detected.`);
  recordSnapshot(db, `Retest — ${f.title}`);
  return { result: 'passed', message: `Retest passed — port ${f.port} check no longer reports this issue.` };
}

/** Import an existing Nmap XML report for an authorized target. */
export async function importNmapXml({ db, target, xml }) {
  const parsed = parseNmapXml(xml);
  const hosts = parsed.hosts.filter(h => h.status === 'up');
  const inside = hosts.filter(h => target.address.includes('/') ? inScope(h.ip, target) : h.ip === target.address);
  if (!inside.length) throw new Error(`No host in this report matches the authorized target ${target.address}. Report hosts: ${hosts.map(h => h.ip).join(', ') || 'none'}.`);
  const x = q(db);
  const scanId = Number(x.run(`INSERT INTO scans (target_id,target_name,target_address,profile,status,progress,phase,started_at,command)
    VALUES (?,?,?,?,?,?,?,?,?)`, target.id, target.name, target.address, 'nmap-xml-import', 'running', 50, 'Importing', now(), parsed.args).lastInsertRowid);
  const log = logTo(db, scanId);
  log(`Imported Nmap XML report (${parsed.startstr}). ${inside.length} in-scope host(s); ${hosts.length - inside.length} out-of-scope host(s) ignored.`);
  let ports = 0, created = 0;
  for (const h of inside) { const r = await ingestHost(db, target, h, scanId, { nse: true, web: false, log, singleHost: !target.address.includes('/') }); ports += r.services; created += r.created; }
  const m = recordSnapshot(db, `Import #${scanId} — ${target.name}`, scanId);
  x.run("UPDATE scans SET status='completed', progress=100, phase='Completed', finished_at=?, hosts_up=?, ports_found=?, findings_new=?, risk_score=? WHERE id=?",
    now(), inside.length, ports, created, m.overall.score, scanId);
  x.run("UPDATE targets SET status='scanned', last_scan_at=? WHERE id=?", now(), target.id);
  return { scanId, hosts: inside.length, ports, created };
}

/** Import OWASP ZAP JSON report findings for assets in the workspace. */
export function importZapJson({ db, report }) {
  if (!Array.isArray(report.site)) throw new Error('This JSON is not an OWASP ZAP report (missing "site" array). Export via Report > Generate Report > JSON.');
  const x = q(db);
  const strip = s => String(s || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  const sev = a => ({ 3: 'high', 2: 'medium', 1: 'low', 0: 'info' })[Number(a.riskcode)] || 'info';
  let created = 0, updated = 0, skipped = 0;
  for (const site of report.site) {
    let host = site['@host'] || '';
    try { host = new URL(site['@name']).hostname; } catch {}
    const asset = x.get('SELECT * FROM assets WHERE ip = ? OR hostname = ?', host, host);
    if (!asset) { skipped += (site.alerts || []).length; continue; }
    for (const a of site.alerts || []) {
      const inst = (a.instances || [])[0] || {};
      let port = Number(site['@port']) || null;
      const r = upsertFinding(db, {
        asset_id: asset.id, port, title: String(a.name || a.alert || 'ZAP alert').slice(0, 200), severity: sev(a),
        description: strip(a.desc).slice(0, 3000), source: 'OWASP ZAP', check_id: `zap-${a.pluginid}`,
        evidence: `${inst.method || 'GET'} ${inst.uri || ''} ${inst.param ? `param=${inst.param}` : ''} ${inst.evidence ? `evidence: ${String(inst.evidence).slice(0, 300)}` : ''}`.trim(),
        cwe: Number(a.cweid) > 0 ? `CWE-${Number(a.cweid)}` : null,
        recommendation: strip(a.solution).slice(0, 1500) || 'Review the ZAP alert and retest.',
      });
      r.created ? created++ : updated++;
    }
  }
  if (created + updated) recordSnapshot(db, 'OWASP ZAP import');
  return { created, updated, skipped };
}
