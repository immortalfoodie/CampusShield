/**
 * CampusShield — Safe vulnerability checks (Security Layer).
 *
 * 1. Service exposure rules: deterministic rules based on what Nmap discovered.
 * 2. NSE interpretation: converts Nmap script output (ftp-anon, smb-security-mode,
 *    "vuln and safe" scripts, vulners) into findings. CVEs are only recorded when
 *    reported by the tool itself — never invented.
 * 3. Safe web baseline: one bounded GET request per HTTP service, checking
 *    security-relevant response headers. No payloads, no exploitation.
 */
import http from 'node:http';
import https from 'node:https';
import { cleanCve } from './workspace.js';

const RULES = 'CampusShield Service Rules';
const NSE = 'Nmap NSE';
const WEB = 'CampusShield Web Baseline';

const isHttp = s => /http/i.test(s.service || '') || [80, 81, 443, 8000, 8008, 8080, 8443, 8888].includes(s.port);
const isTls = s => s.tunnel === 'ssl' || /https|ssl/i.test(s.service || '') || [443, 8443].includes(s.port);
const label = s => `${s.port}/${s.protocol || 'tcp'} ${s.service || ''} ${[s.product, s.version].filter(Boolean).join(' ')}`.trim();

/** Rule table: when a service matching `match` is open, raise this finding. */
const SERVICE_RULES = [
  { id: 'telnet-exposed', match: s => s.port === 23 || /telnet/i.test(s.service), severity: 'high', cwe: 'CWE-319',
    finding_type: 'exposure', confidence: 'heuristic',
    title: 'Telnet service exposed (cleartext remote access)',
    description: 'Telnet transmits credentials and session data without encryption. Anyone on the network path can capture them.',
    severity_rationale: 'High severity assigned because cleartext administrative protocols expose credentials across the shared network segment.',
    limitations: 'Discovered via open port observation. No session packets were captured on wire.',
    recommendation: 'Disable Telnet and use SSH with key-based authentication instead.' },
  { id: 'ftp-cleartext', match: s => s.port === 21 || /^ftp$/i.test(s.service), severity: 'medium', cwe: 'CWE-319',
    finding_type: 'exposure', confidence: 'heuristic',
    title: 'FTP service uses cleartext authentication',
    description: 'Plain FTP sends usernames, passwords and files unencrypted.',
    severity_rationale: 'Medium severity assigned because cleartext authentication enables credential sniffing on the local broadcast domain.',
    limitations: 'Open port discovery indicates plain FTP listener; active authentication was not tested.',
    recommendation: 'Disable FTP if not required, or replace it with SFTP/FTPS.' },
  { id: 'smb-exposed', match: s => [139, 445].includes(s.port) || /microsoft-ds|netbios|smb/i.test(s.service), severity: 'medium',
    finding_type: 'exposure', confidence: 'heuristic',
    title: 'SMB/NetBIOS file sharing exposed to the network',
    description: 'Server Message Block (SMB) file sharing is exposed on the network. SMB is a primary target for lateral movement and credential relay attacks.',
    severity_rationale: 'Medium severity assigned for attack-surface exposure. Note: Port 445 being open is a rule-based exposure and hardening recommendation, NOT proof of an active remote code execution vulnerability.',
    limitations: 'Discovered via open TCP port state. Authentication requirements, SMB signing, share permissions, and reachability across subnets were not tested remotely.',
    recommendation: 'Restrict SMB to required hosts with host firewall or VLAN ACLs, enforce SMB signing, disable SMBv1, and keep the OS patched.' },
  { id: 'rdp-exposed', match: s => s.port === 3389 || /ms-wbt-server|rdp/i.test(s.service), severity: 'medium',
    finding_type: 'exposure', confidence: 'heuristic',
    title: 'Remote Desktop (RDP) reachable from the network',
    description: 'Exposed RDP is a common brute-force and remote-exploitation target.',
    severity_rationale: 'Medium severity assigned because open RDP expands the external attack surface for credential attacks.',
    limitations: 'Detected from listening port. NLA enforcement and account lockout policies were not assessed.',
    recommendation: 'Restrict RDP to an admin network or VPN, enforce NLA and strong passwords.' },
  { id: 'vnc-exposed', match: s => (s.port >= 5900 && s.port <= 5903) || /vnc/i.test(s.service), severity: 'medium',
    finding_type: 'exposure', confidence: 'heuristic',
    title: 'VNC remote desktop service exposed',
    description: 'VNC often uses weak authentication and unencrypted sessions.',
    severity_rationale: 'Medium severity assigned because VNC frequently lacks robust authentication and session encryption.',
    limitations: 'Detected from listening port. Password authentication requirements were not probed.',
    recommendation: 'Disable VNC or tunnel it over SSH/VPN with strong authentication.' },
  { id: 'db-exposed', match: s => [3306, 5432, 1433, 1521, 27017, 6379, 9200].includes(s.port) || /mysql|postgres|ms-sql|oracle|mongo|redis|elasticsearch/i.test(s.service),
    severity: 'medium', cwe: 'CWE-284',
    finding_type: 'exposure', confidence: 'heuristic',
    title: 'Database service directly reachable on the network',
    description: 'Database ports should only be reachable from the application servers that need them.',
    severity_rationale: 'Medium severity assigned because direct database exposure circumvents application-tier access controls.',
    limitations: 'Detected from listening port. Authentication credentials and database privileges were not tested.',
    recommendation: 'Bind the database to localhost/app network, restrict ingress by firewall and use strong credentials.' },
  { id: 'snmp-exposed', match: s => s.port === 161 || /snmp/i.test(s.service), severity: 'medium',
    finding_type: 'exposure', confidence: 'heuristic',
    title: 'SNMP service exposed',
    description: 'SNMP v1/v2c uses community strings in cleartext and may leak device configuration.',
    severity_rationale: 'Medium severity assigned because default SNMP communities frequently leak internal network configurations.',
    limitations: 'Detected from listening port. Community strings were not brute-forced.',
    recommendation: 'Disable SNMP if unused or migrate to SNMPv3 with authentication and encryption.' },
  { id: 'r-services', match: s => [512, 513, 514].includes(s.port), severity: 'high', cwe: 'CWE-319',
    finding_type: 'exposure', confidence: 'heuristic',
    title: 'Legacy r-services (rexec/rlogin/rsh) enabled',
    description: 'Berkeley r-services rely on host-based trust and transmit data in cleartext.',
    severity_rationale: 'High severity assigned because legacy Berkeley r-services bypass modern authentication.',
    limitations: 'Detected from open port observation.',
    recommendation: 'Disable r-services and use SSH.' },
  { id: 'http-cleartext', match: s => isHttp(s) && !isTls(s), severity: 'low', cwe: 'CWE-319',
    finding_type: 'hardening', confidence: 'heuristic',
    title: 'Web service offered over cleartext HTTP',
    description: 'Traffic to this web service is not encrypted; credentials or session cookies could be intercepted.',
    severity_rationale: 'Low severity hardening finding. Plain HTTP allows eavesdropping on shared communication links.',
    limitations: 'Observed non-TLS HTTP listener. Application-specific encryption or VPN encapsulation was not assessed.',
    recommendation: 'Serve the application over HTTPS and redirect HTTP to HTTPS. Disable the service if it is not required.' },
];

export function serviceRuleFindings(asset, services) {
  const out = [];
  const isLoopback = asset.ip === '127.0.0.1' || asset.ip === '::1' || asset.ip.startsWith('127.');
  for (const s of services) {
    for (const rule of SERVICE_RULES) {
      if (!rule.match(s)) continue;
      const reachability = isLoopback
        ? `Observed locally on loopback (${asset.ip}). Port may be restricted to local host or reachable externally depending on firewall rules.`
        : `Observed open across laboratory network on host ${asset.ip}.`;
      const limitations = isLoopback
        ? `${rule.limitations || 'Detected via non-intrusive service observation.'} Observed on local loopback (${asset.ip}); remote reachability depends on network interface bindings and host firewall rules.`
        : (rule.limitations || 'Detected via non-intrusive service observation; exploitability not verified.');

      out.push({
        asset_id: asset.id, port: s.port, title: `${rule.title.replace(/\s*\(port \d+\)/, '')} (port ${s.port})`, severity: rule.severity,
        finding_type: rule.finding_type || 'exposure',
        confidence: rule.confidence || 'heuristic',
        severity_rationale: rule.severity_rationale || 'Rule-based potential security exposure triggered by open network service.',
        limitations,
        description: rule.description, recommendation: rule.recommendation, cwe: rule.cwe || null,
        cve: rule.cve || null,
        evidence: `Nmap reported open service ${label(s)} on ${asset.ip}. ${reachability}`,
        source: RULES, check_id: rule.id,
      });
    }
  }
  return out;
}

function cvssToSeverity(c) {
  if (c >= 9) return 'critical';
  if (c >= 7) return 'high';
  if (c >= 4) return 'medium';
  if (c > 0) return 'low';
  return 'info';
}

/** Interpret NSE script results attached to services. */
export function nseFindings(asset, nmapPorts) {
  const out = [];
  for (const p of nmapPorts) {
    for (const sc of p.scripts || []) {
      const output = String(sc.output || '');
      if (sc.id === 'ftp-anon' && /Anonymous FTP login allowed/i.test(output)) {
        out.push({
          asset_id: asset.id, port: p.port, title: `Anonymous FTP login allowed (port ${p.port})`, severity: 'high', cwe: 'CWE-287',
          finding_type: 'vulnerability', confidence: 'confirmed',
          severity_rationale: 'Nmap ftp-anon actively negotiated anonymous login and received FTP code 230 confirmation.',
          limitations: 'Checked anonymous account only. File system write permissions were not verified.',
          description: 'The FTP server accepts the "anonymous" account, allowing anyone to list or download files.',
          evidence: output.slice(0, 600), source: `${NSE}: ftp-anon`, check_id: 'ftp-anon',
          recommendation: 'Disable anonymous FTP access unless explicitly required for public files.'
        });
      } else if (sc.id === 'smb-security-mode' && /message_signing:\s*disabled/i.test(output)) {
        out.push({
          asset_id: asset.id, port: p.port, title: 'SMB message signing disabled', severity: 'medium', cwe: 'CWE-300',
          finding_type: 'hardening', confidence: 'confirmed',
          severity_rationale: 'Negotiation response confirmed SMB message signing is disabled, enabling relay and MITM attacks.',
          limitations: 'Observation based on SMB security mode negotiation response.',
          description: 'Without SMB signing, relay and man-in-the-middle attacks are possible on the network.',
          evidence: output.slice(0, 600), source: `${NSE}: smb-security-mode`, check_id: 'smb-signing',
          recommendation: 'Enable and require SMB message signing via group policy / smb.conf.'
        });
      } else if (sc.id === 'vulners') {
        // vulners lists known CVEs for the detected product version (tool-reported, not invented).
        const entries = [...output.matchAll(/(CVE-\d{4}-\d{4,})\s+(\d+(?:\.\d+)?)/g)]
          .map(m => ({ cve: m[1], cvss: Number(m[2]) }))
          .filter(e => e.cvss >= 7)
          .sort((a, b) => b.cvss - a.cvss)
          .slice(0, 5);
        for (const e of entries) {
          out.push({
            asset_id: asset.id, port: p.port, title: `${e.cve} affects ${p.product || p.service} ${p.version || ''}`.trim(),
            severity: cvssToSeverity(e.cvss), cve: cleanCve(e.cve), cvss: e.cvss,
            finding_type: 'vulnerability', confidence: 'inferred',
            severity_rationale: `The vulners database mapped detected product version (${p.product || p.service} ${p.version || ''}) to ${e.cve} (CVSS ${e.cvss}).`,
            limitations: 'Version-based correlation only. Active exploitability requires manual confirmation; vendor security backports may prevent exploitation.',
            description: `The vulners NSE script matched the detected version of ${p.product || p.service} against a known vulnerability (CVSS ${e.cvss}). Version-based matches must be verified manually.`,
            evidence: `Service: ${p.port}/${p.protocol} ${p.product || ''} ${p.version || ''}. Reported by vulners.nse.`,
            source: `${NSE}: vulners`, check_id: `vulners-${e.cve}`,
            recommendation: `Verify whether ${e.cve} applies, then upgrade ${p.product || p.service} to a patched version.`
          });
        }
      } else if (/VULNERABLE/.test(output) && !/NOT VULNERABLE/.test(output)) {
        const title = (output.match(/\n\s*([^\n]+)\n\s*State: (LIKELY )?VULNERABLE/) || [])[1]?.trim() || `${sc.id} reported a vulnerability`;
        const cve = cleanCve((output.match(/CVE-\d{4}-\d{4,}/) || [])[0]);
        out.push({
          asset_id: asset.id, port: p.port, title: `${title} (port ${p.port})`, severity: /LIKELY/.test(output) ? 'medium' : 'high',
          cve, finding_type: 'vulnerability', confidence: 'confirmed',
          severity_rationale: `Nmap NSE script ${sc.id} actively probed the service and reported a VULNERABLE response.`,
          limitations: 'Based on NSE script evaluation output.',
          description: `Nmap NSE script "${sc.id}" reported this service as vulnerable.`,
          evidence: output.slice(0, 800), source: `${NSE}: ${sc.id}`, check_id: sc.id,
          recommendation: 'Review the script output, confirm the issue in the lab and apply the vendor fix or configuration change.'
        });
      }
    }
  }
  return out;
}

function fetchHeaders(host, port, tls) {
  return new Promise(resolve => {
    let done = false;
    const finish = v => { if (!done) { done = true; resolve(v); } };
    const req = (tls ? https : http).request({
      host, port, path: '/', method: 'GET', timeout: 5000, rejectUnauthorized: false,
      headers: { 'User-Agent': 'CampusShield-Safe-Baseline/2.0', Accept: 'text/html,*/*' },
    }, res => {
      let bytes = 0;
      res.on('data', c => { bytes += c.length; if (bytes > 32768) res.destroy(); });
      const result = () => finish({ status: res.statusCode, headers: res.headers });
      res.on('end', result); res.on('close', result);
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', e => finish({ error: e.message }));
    req.end();
  });
}

/** Safe web baseline: bounded GET to each HTTP(S) service, header checks only. */
export async function webBaseline(asset, services, log = () => {}) {
  const out = [];
  for (const s of services.filter(isHttp).slice(0, 6)) {
    const tls = isTls(s);
    log(`Web baseline: GET ${tls ? 'https' : 'http'}://${asset.ip}:${s.port}/`);
    const r = await fetchHeaders(asset.ip, s.port, tls);
    if (r.error) { log(`  no response (${r.error})`); continue; }
    const h = r.headers;
    const ev = `${tls ? 'HTTPS' : 'HTTP'} GET / on port ${s.port} returned ${r.status}`;
    const base = {
      asset_id: asset.id, port: s.port, source: WEB,
      finding_type: 'hardening', confidence: 'confirmed',
      severity_rationale: 'Passive HTTP response header check confirmed absence of recommended security header.',
      limitations: 'Passive single GET response header check. Reverse proxies or CDNs might modify headers under different paths.'
    };
    if (!tls && [301, 302, 307, 308].includes(r.status) && /^https:/i.test(h.location || '')) continue;
    if (tls && !h['strict-transport-security']) out.push({ ...base, check_id: 'hsts', severity: 'low', title: `HSTS header missing (port ${s.port})`,
      description: 'HTTPS responses should include Strict-Transport-Security to prevent downgrade attacks.', evidence: ev,
      recommendation: 'Add a Strict-Transport-Security header once HTTPS is correctly configured.' });
    if (!h['content-security-policy']) out.push({ ...base, check_id: 'csp', severity: 'low', cwe: 'CWE-693', title: `Content-Security-Policy header missing (port ${s.port})`,
      description: 'Without a CSP, the impact of cross-site scripting (XSS) flaws is greater.', evidence: ev,
      recommendation: 'Define a restrictive Content-Security-Policy; test in report-only mode first.' });
    if (!h['x-frame-options'] && !/frame-ancestors/i.test(h['content-security-policy'] || '')) out.push({ ...base, check_id: 'xfo', severity: 'low', cwe: 'CWE-1021',
      title: `Clickjacking protection missing (port ${s.port})`, description: 'No X-Frame-Options or CSP frame-ancestors directive was observed.', evidence: ev,
      recommendation: 'Set X-Frame-Options: DENY or a CSP frame-ancestors directive.' });
    if (!h['x-content-type-options']) out.push({ ...base, check_id: 'xcto', severity: 'low', title: `X-Content-Type-Options header missing (port ${s.port})`,
      description: 'Browsers may MIME-sniff responses, enabling some content-injection attacks.', evidence: ev,
      recommendation: 'Set X-Content-Type-Options: nosniff.' });
    const cookies = [].concat(h['set-cookie'] || []);
    const weak = cookies.filter(c => !/httponly/i.test(c));
    if (weak.length) out.push({ ...base, check_id: 'cookie-httponly', severity: 'medium', cwe: 'CWE-1004', title: `Session cookie without HttpOnly flag (port ${s.port})`,
      description: 'Cookies without HttpOnly can be read by JavaScript, increasing the impact of XSS.', evidence: `${ev}; Set-Cookie: ${weak[0].split(';')[0].split('=')[0]}=<redacted>`,
      recommendation: 'Set HttpOnly (and Secure over HTTPS) on session cookies.' });
    const disclosure = [h['x-powered-by'] && `X-Powered-By: ${h['x-powered-by']}`, /\d/.test(h.server || '') && `Server: ${h.server}`].filter(Boolean);
    if (disclosure.length) out.push({ ...base, check_id: 'version-disclosure', severity: 'info', cwe: 'CWE-200', title: `Software version disclosed in headers (port ${s.port})`,
      description: 'Response headers reveal server software versions, which helps attackers find matching exploits.', evidence: `${ev}; ${disclosure.join('; ').slice(0, 200)}`,
      recommendation: 'Suppress version details (e.g. ServerTokens Prod, expose_php Off).' });
  }
  return out;
}
