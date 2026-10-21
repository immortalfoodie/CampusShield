/**
 * CampusShield — Nmap integration.
 * CampusShield does not reimplement scanning: it orchestrates Nmap and turns its
 * XML output into structured assets, services and findings.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { XMLParser } from 'fast-xml-parser';

export function findNmap() {
  if (process.env.NMAP_PATH && fs.existsSync(process.env.NMAP_PATH)) return process.env.NMAP_PATH;
  const exe = process.platform === 'win32' ? 'nmap.exe' : 'nmap';
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    const c = path.join(dir, exe);
    if (dir && fs.existsSync(c)) return c;
  }
  const extra = process.platform === 'win32'
    ? ['C:\\Program Files (x86)\\Nmap\\nmap.exe', 'C:\\Program Files\\Nmap\\nmap.exe']
    : ['/usr/bin/nmap', '/usr/local/bin/nmap', '/opt/homebrew/bin/nmap'];
  return extra.find(c => fs.existsSync(c)) || null;
}

function hasScript(name) {
  const bin = findNmap();
  if (!bin) return false;
  const dirs = [path.join(path.dirname(bin), 'scripts'), '/usr/share/nmap/scripts', '/usr/local/share/nmap/scripts', '/opt/homebrew/share/nmap/scripts'];
  return dirs.some(d => fs.existsSync(path.join(d, `${name}.nse`)));
}

/** Scan profiles. All use TCP connect scans (-sT) so they work without admin rights. */
export function profiles() {
  const safeScripts = 'banner,ftp-anon,http-title,http-server-header,smb-security-mode,ssl-cert';
  const vulnExpr = `(vuln and safe) or ${safeScripts.split(',').join(' or ')}${hasScript('vulners') ? ' or vulners' : ''}`;
  return {
    quick: {
      label: 'Quick discovery', description: 'Top 100 TCP ports with light service/version detection. ~1 min per host.',
      args: ['-sT', '-sV', '--version-light', '-T4', '--top-ports', '100'], web: false, nse: false,
    },
    standard: {
      label: 'Standard assessment', description: 'Top 1000 TCP ports, version detection, safe NSE scripts and web header baseline.',
      args: ['-sT', '-sV', '-T4', '--top-ports', '1000', '--script', safeScripts], web: true, nse: true,
    },
    vuln: {
      label: 'Vulnerability assessment', description: `Standard + Nmap "vuln and safe" scripts${hasScript('vulners') ? ' + vulners CVE lookup (needs internet)' : ''}. Slowest.`,
      args: ['-sT', '-sV', '-T4', '--top-ports', '1000', '--script', vulnExpr], web: true, nse: true,
    },
  };
}

/**
 * Run Nmap and stream progress.
 * onProgress({ task, percent }) is called whenever Nmap emits a <taskprogress> element.
 */
export function runNmap(args, { onProgress = () => {}, onLog = () => {}, timeoutMs = 15 * 60 * 1000, signal } = {}) {
  return new Promise((resolve, reject) => {
    const bin = findNmap();
    if (!bin) return reject(new Error('Nmap is not installed or not on PATH. Install Nmap (https://nmap.org/download) or use Demo Mode / Nmap XML import.'));
    const fullArgs = ['-oX', '-', '--stats-every', '2s', '--no-stylesheet', ...args];
    onLog(`$ nmap ${fullArgs.join(' ')}`);
    const startTime = Date.now();
    const child = spawn(bin, fullArgs, { windowsHide: true });
    let out = '', err = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('Nmap timed out after ' + Math.round(timeoutMs / 1000) + 's.')); }, timeoutMs);
    signal?.addEventListener('abort', () => { child.kill(); reject(new Error('Scan cancelled by user.')); });
    child.stdout.on('data', d => {
      const s = d.toString();
      out += s;
      for (const m of s.matchAll(/<taskprogress task="([^"]+)"[^>]*percent="([\d.]+)"/g)) onProgress({ task: m[1], percent: Number(m[2]) });
      for (const m of s.matchAll(/<taskbegin task="([^"]+)"/g)) { onProgress({ task: m[1], percent: 0 }); onLog(`Nmap: ${m[1]} started`); }
      for (const m of s.matchAll(/<taskend task="([^"]+)"/g)) onLog(`Nmap: ${m[1]} finished`);
    });
    child.stderr.on('data', d => { err += d.toString(); });
    child.on('error', e => { clearTimeout(timer); reject(e); });
    child.on('close', code => {
      clearTimeout(timer);
      const durationMs = Date.now() - startTime;
      if (code !== 0 && !out.includes('</nmaprun>')) return reject(new Error(err.trim() || `Nmap exited with code ${code}`));
      if (err.trim()) onLog(`Nmap diagnostic output: ${err.trim().slice(0, 400)}`);
      // Wrap output string with execution metadata
      const res = new String(out);
      res.exitCode = code;
      res.durationMs = durationMs;
      res.warnings = err.trim();
      resolve(res);
    });
  });
}

const decode = s => String(s ?? '')
  .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
  .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)));

const arrayTags = new Set(['host', 'port', 'script', 'address', 'hostname', 'osmatch', 'elem', 'table', 'hosthint', 'taskprogress', 'taskbegin', 'taskend', 'extraports']);

/** Parse Nmap XML into a structured host list. */
export function parseNmapXml(xml) {
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '', isArray: n => arrayTags.has(n) });
  const doc = parser.parse(String(xml));
  const run = doc.nmaprun;
  if (!run) throw new Error('Not a valid Nmap XML document (missing <nmaprun>).');
  const hosts = (run.host || []).map(h => {
    const addrs = h.address || [];
    const ip = addrs.find(a => a.addrtype === 'ipv4')?.addr || addrs.find(a => a.addrtype === 'ipv6')?.addr;
    const macA = addrs.find(a => a.addrtype === 'mac');
    const ports = (h.ports?.port || []).filter(p => p.state?.state === 'open').map(p => ({
      port: Number(p.portid), protocol: p.protocol, state: p.state?.state || 'open',
      service: p.service?.name || 'unknown', product: p.service?.product || '', version: p.service?.version || '',
      extra: p.service?.extrainfo || '', tunnel: p.service?.tunnel || '', ostype: p.service?.ostype || '',
      scripts: (p.script || []).map(s => ({ id: s.id, output: decode(s.output) })),
    }));
    const extraports = (h.ports?.extraports || []).map(e => ({ state: e.state, count: Number(e.count) }));
    const osmatch = (h.os?.osmatch || [])[0];
    const osGuess = osmatch?.name || ports.find(p => p.ostype)?.ostype || '';
    return {
      ip, status: h.status?.state || 'unknown',
      mac: macA?.addr || '', vendor: macA?.vendor || '',
      hostname: (h.hostnames?.hostname || [])[0]?.name || '',
      os: osGuess, osAccuracy: osmatch?.accuracy ? Number(osmatch.accuracy) : null,
      ports, extraports
    };
  }).filter(h => h.ip);
  return { args: run.args || '', startstr: run.startstr || '', hosts };
}
