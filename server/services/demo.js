/**
 * CampusShield — Demo environment.
 * Everything created here is clearly marked: DEMO DATA — NOT FROM A LIVE SCAN.
 * The scan-history trend is NOT hardcoded: it is produced by running the real
 * risk engine on earlier states of the demo network.
 */
import { q, now } from '../db.js';
import { recordSnapshot, upsertFinding, setFindingStatus } from './workspace.js';

const DEMO_AUTH = 'DEMO ENVIRONMENT — simulated systems, no real host is contacted.';
const daysAgo = d => new Date(Date.now() - d * 86400000).toISOString();

export const DEMO_ASSETS = [
  { key: 'student', name: 'Student PC', ip: '192.168.56.20', hostname: 'student-pc.campus.lab', os: 'Windows 10 Pro', type: 'endpoint',
    criticality: 'low', entry: 1, description: 'Student lab workstation (untrusted zone).',
    services: [[135, 'msrpc', 'Microsoft Windows RPC', ''], [139, 'netbios-ssn', 'Microsoft Windows netbios-ssn', ''], [445, 'microsoft-ds', 'Microsoft Windows SMB', ''], [3389, 'ms-wbt-server', 'Microsoft Terminal Services', '']] },
  { key: 'faculty', name: 'Faculty PC', ip: '192.168.56.31', hostname: 'faculty-pc.campus.lab', os: 'Ubuntu 22.04 LTS', type: 'endpoint',
    criticality: 'medium', entry: 0, description: 'Faculty workstation used for grading and administration.',
    services: [[22, 'ssh', 'OpenSSH', '8.9p1 Ubuntu 3ubuntu0.6']] },
  { key: 'portal', name: 'Faculty Portal', ip: '192.168.56.101', hostname: 'portal.campus.lab', os: 'Ubuntu 20.04 LTS', type: 'application',
    criticality: 'high', entry: 0, description: 'Web portal for marks and attendance (intentionally vulnerable DVWA-style app).',
    services: [[22, 'ssh', 'OpenSSH', '8.2p1 Ubuntu 4ubuntu0.5'], [80, 'http', 'Apache httpd', '2.4.41'], [8080, 'http', 'Apache Tomcat', '9.0.31']] },
  { key: 'lab', name: 'Lab Server', ip: '192.168.56.110', hostname: 'labsrv.campus.lab', os: 'Debian 10', type: 'server',
    criticality: 'high', entry: 0, description: 'Shared course-material server.',
    services: [[21, 'ftp', 'vsftpd', '3.0.3'], [22, 'ssh', 'OpenSSH', '7.9p1 Debian 10+deb10u2'], [23, 'telnet', 'Linux telnetd', '']] },
  { key: 'db', name: 'Database Server', ip: '192.168.56.120', hostname: 'db.campus.lab', os: 'Ubuntu 22.04 LTS', type: 'database',
    criticality: 'critical', entry: 0, description: 'Student records database (synthetic data only).',
    services: [[22, 'ssh', 'OpenSSH', '8.9p1'], [3306, 'mysql', 'MySQL', '8.0.36']] },
];

const F = (key, port, severity, title, source, extra = {}) => ({ key, port, severity, title, source, ...extra });
const ZAP = 'OWASP ZAP (demo data)';
const RULES = 'CampusShield Service Rules (demo data)';
const NSE = 'Nmap NSE (demo data)';

export const DEMO_FINDINGS = [
  F('portal', 80, 'high', 'SQL Injection in login form', ZAP, { cwe: 'CWE-89',
    description: 'The "username" parameter of /login.php is concatenated into a SQL query. Database errors were returned for crafted input.',
    evidence: "POST /login.php username=admin'-- returned a MySQL syntax error (demo evidence).",
    recommendation: 'Use parameterised queries / prepared statements, validate input and use a least-privilege DB account.' }),
  F('portal', 80, 'medium', 'Reflected Cross-Site Scripting (XSS)', ZAP, { cwe: 'CWE-79',
    description: 'The "search" parameter is reflected into the page without output encoding.',
    evidence: 'GET /search.php?q=<script>alert(1)</script> was reflected unencoded (demo evidence).',
    recommendation: 'Encode output contextually and deploy a Content-Security-Policy.' }),
  F('portal', 80, 'low', 'Web service offered over cleartext HTTP (port 80)', RULES, { cwe: 'CWE-319', check_id: 'http-cleartext',
    description: 'Login credentials for the portal are sent without encryption.',
    evidence: 'Nmap reported 80/tcp http Apache httpd 2.4.41 (demo).',
    recommendation: 'Serve the portal over HTTPS and redirect HTTP to HTTPS. Disable the service if it is not required.' }),
  F('portal', 8080, 'medium', 'Tomcat default/manager pages exposed (port 8080)', NSE, {
    description: 'Apache Tomcat on 8080 exposes default documentation and the /manager path.',
    evidence: 'http-title: "Apache Tomcat/9.0.31" (demo evidence).',
    recommendation: 'Remove default webapps, restrict /manager to localhost, or disable port 8080 if not required.' }),
  F('lab', 21, 'high', 'Anonymous FTP login allowed (port 21)', NSE, { cwe: 'CWE-287', check_id: 'ftp-anon',
    description: 'The FTP server accepts the anonymous account.', evidence: 'ftp-anon: Anonymous FTP login allowed (FTP code 230) (demo).',
    recommendation: 'Disable anonymous FTP access.' }),
  F('lab', 21, 'medium', 'FTP service uses cleartext authentication (port 21)', RULES, { cwe: 'CWE-319', check_id: 'ftp-cleartext',
    description: 'Plain FTP sends credentials and files unencrypted.', evidence: 'Nmap reported 21/tcp ftp vsftpd 3.0.3 (demo).',
    recommendation: 'Replace FTP with SFTP/FTPS or disable it.' }),
  F('lab', 23, 'high', 'Telnet service exposed (cleartext remote access) (port 23)', RULES, { cwe: 'CWE-319', check_id: 'telnet-exposed',
    description: 'Telnet transmits credentials in cleartext.', evidence: 'Nmap reported 23/tcp telnet Linux telnetd (demo).',
    recommendation: 'Disable Telnet and use SSH.' }),
  F('db', 3306, 'medium', 'Database service directly reachable on the network (port 3306)', RULES, { cwe: 'CWE-284', check_id: 'db-exposed',
    description: 'MySQL accepts connections from the whole lab subnet instead of only the portal.', evidence: 'Nmap reported 3306/tcp mysql MySQL 8.0.36 (demo).',
    recommendation: 'Bind MySQL to the application network and restrict ingress to the Faculty Portal only.' }),
  F('student', 445, 'medium', 'SMB/NetBIOS file sharing exposed to the network (port 445)', RULES, { check_id: 'smb-exposed',
    description: 'SMB is exposed on a student workstation.', evidence: 'Nmap reported 445/tcp microsoft-ds (demo).',
    recommendation: 'Disable file sharing on student PCs or restrict it with the host firewall.' }),
  F('student', 445, 'medium', 'SMB message signing disabled', NSE, { cwe: 'CWE-300', check_id: 'smb-signing',
    description: 'SMB signing is not required.', evidence: 'smb-security-mode: message_signing: disabled (demo).',
    recommendation: 'Require SMB signing via group policy.' }),
  F('student', 3389, 'low', 'Remote Desktop (RDP) reachable from the network (port 3389)', RULES, { check_id: 'rdp-exposed',
    description: 'RDP is enabled on a student workstation.', evidence: 'Nmap reported 3389/tcp ms-wbt-server (demo).',
    recommendation: 'Disable RDP on student PCs or restrict it to the admin network.' }),
  F('faculty', 22, 'low', 'SSH password authentication enabled', NSE, {
    description: 'SSH accepts password logins, enabling brute-force attempts.', evidence: 'ssh-auth-methods: password, publickey (demo).',
    recommendation: 'Disable PasswordAuthentication and use SSH keys.' }),
];

/** Findings that existed in earlier demo assessments and were later fixed — they drive the trend. */
const HISTORIC = [
  F('portal', 8080, 'high', 'Tomcat manager accessible with default credentials', NSE, {
    description: 'tomcat/tomcat credentials were accepted on /manager/html.', evidence: 'http-default-accounts reported valid credentials (demo).',
    recommendation: 'Change default credentials and restrict the manager application.' }),
  F('portal', 80, 'medium', 'Directory listing enabled on /uploads', ZAP, { cwe: 'CWE-548',
    description: 'Apache lists files in /uploads/.', evidence: 'GET /uploads/ returned "Index of /uploads" (demo).',
    recommendation: 'Disable Options Indexes in Apache configuration.' }),
];

const RELATIONSHIPS = [
  ['student', 'portal', 'Network Access', 'Students reach the portal over the lab LAN.'],
  ['faculty', 'portal', 'Application Access', 'Faculty log in to manage marks.'],
  ['portal', 'db', 'Database Connection', 'Portal reads/writes student records.'],
  ['student', 'lab', 'Network Access', 'Students download course files over FTP.'],
  ['faculty', 'lab', 'Administrative Access', 'Faculty administer the lab server over SSH.'],
  ['lab', 'db', 'Shared Service', 'Nightly backup job copies the database.'],
];

export function seedDemo(db) {
  const x = q(db);
  const ids = {};
  x.tx(() => {
    const net = x.run(`INSERT INTO targets (name,address,description,environment,authorization_note,authorized_by,status,created_at,last_scan_at)
      VALUES (?,?,?,?,?,?,?,?,?)`, 'Demo Lab Network', '192.168.56.0/24', 'Whole simulated college lab subnet.', 'Demo Lab', DEMO_AUTH, 'Demo', 'scanned', daysAgo(15), daysAgo(1));
    const netId = Number(net.lastInsertRowid);
    for (const a of DEMO_ASSETS) {
      const t = x.run(`INSERT INTO targets (name,address,description,environment,authorization_note,authorized_by,status,created_at,last_scan_at)
        VALUES (?,?,?,?,?,?,?,?,?)`, a.name, a.ip, a.description, 'Demo Lab', DEMO_AUTH, 'Demo', 'scanned', daysAgo(15), daysAgo(1));
      const r = x.run(`INSERT INTO assets (target_id,name,ip,hostname,os,type,criticality,is_entry_point,description,host_status,source,first_seen,last_seen)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, Number(t.lastInsertRowid), a.name, a.ip, a.hostname, a.os, a.type, a.criticality, a.entry, a.description, 'up', 'demo', daysAgo(15), daysAgo(1));
      ids[a.key] = Number(r.lastInsertRowid);
      for (const [port, service, product, version] of a.services)
        x.run('INSERT INTO services (asset_id,port,protocol,service,product,version,last_seen) VALUES (?,?,?,?,?,?,?)', ids[a.key], port, 'tcp', service, product, version, daysAgo(1));
    }
    for (const [s, t, type, desc] of RELATIONSHIPS)
      x.run('INSERT INTO relationships (source_id,target_id,type,description,created_at) VALUES (?,?,?,?,?)', ids[s], ids[t], type, desc, daysAgo(14));

    const add = f => upsertFinding(db, { ...f, asset_id: ids[f.key], fingerprint: `demo|${f.key}|${f.title}` }).id;
    const historic = HISTORIC.map(add);
    DEMO_FINDINGS.forEach(add);

    // Scan history with risk computed by the real engine on each historic state.
    const scan = (label, d, profile) => {
      const m = recordSnapshot(db, label);
      const sid = Number(x.run(`INSERT INTO scans (target_id,target_name,target_address,profile,status,progress,phase,started_at,finished_at,hosts_up,ports_found,findings_new,risk_score,is_demo,log)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)`, netId, 'Demo Lab Network', '192.168.56.0/24', profile, 'completed', 100, 'Completed', d, d, 5,
        DEMO_ASSETS.reduce((n, a) => n + a.services.length, 0), m.overall.vulnerabilities, m.overall.score,
        'DEMO DATA — NOT FROM A LIVE SCAN').lastInsertRowid);
      x.run('UPDATE risk_snapshots SET at = ?, scan_id = ? WHERE id = (SELECT MAX(id) FROM risk_snapshots)', d, sid);
    };
    scan('Scan #1 — initial assessment', daysAgo(14), 'vuln');
    setFindingStatus(db, historic[0], 'fixed', 'Default credentials changed by lab admin (demo).');
    setFindingStatus(db, historic[0], 'retested', 'Not detected in follow-up scan (demo).');
    scan('Scan #2 — after credential fix', daysAgo(7), 'standard');
    setFindingStatus(db, historic[1], 'fixed', 'Directory listing disabled (demo).');
    setFindingStatus(db, historic[1], 'retested', 'Not detected in follow-up scan (demo).');
    scan('Scan #3 — current state', daysAgo(1), 'standard');
    x.run("INSERT OR REPLACE INTO meta (key,value) VALUES ('seeded_at', ?)", now());
  });
}

/** Phases used to animate a simulated scan in Demo Mode. */
export const DEMO_SCAN_PHASES = [
  ['Validating authorized scope', 5], ['Host discovery (ping sweep)', 18], ['Connect scan: top ports', 45],
  ['Service & version detection', 65], ['NSE safe scripts', 80], ['Web header baseline', 90], ['Updating asset inventory & risk model', 100],
];
