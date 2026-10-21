/**
 * CampusShield — Comprehensive Test Suite
 * Validates:
 * 1. Data Layer & Demo Seeding
 * 2. Demo vs Live Mode Data Isolation
 * 3. Scope Guard & Lab Network Guardrails (IPv4, IPv6, CIDR, DNS)
 * 4. Nmap Profiles & Structured XML Parsing
 * 5. Rule-Based Findings (Heuristic vs Confirmed, SMB/445, No CVE mapping)
 * 6. Risk Scoring Formula, Caps, Multipliers & 17-pt Localhost Regression
 * 7. Security Graph & Attack Path Analysis (0-path context, multi-hop chains)
 * 8. What-If Remediation Simulation (Finding fix vs Service/Port blocking vs Baseline immutability)
 * 9. Offline PCAP & Authentication Log Analysis
 * 10. Multi-Page PDF Report Generation & Consistency
 */

import { openDb, destroyDb, setMode, getMode, q } from '../server/db.js';
import { seedDemo } from '../server/services/demo.js';
import { loadData, loadScenario, upsertFinding } from '../server/services/workspace.js';
import { computeModel, recommendActions, levelOf } from '../server/services/risk.js';
import { validateScope, isAllowedLabAddress, isPrivateIPv4, isPrivateIPv6 } from '../server/services/scope.js';
import { profiles, parseNmapXml } from '../server/services/nmap.js';
import { serviceRuleFindings } from '../server/services/checks.js';
import { analyzePcap } from '../server/services/pcap.js';
import { analyzeLogs } from '../server/services/log.js';
import { generateReportPdf } from '../server/services/report.js';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SAMPLES_DIR = path.resolve(__dirname, '..', 'samples');

async function runTests() {
  console.log('🧪 Starting CampusShield Comprehensive Engineering Test Suite...\n');
  let passed = 0;
  let failed = 0;

  function assert(condition, name) {
    if (condition) {
      console.log(`  ✓ ${name}`);
      passed++;
    } else {
      console.error(`  ✗ FAIL: ${name}`);
      failed++;
    }
  }

  // ==========================================
  // [1] Data Layer & Demo Seeding
  // ==========================================
  console.log('[1] Testing Data Layer & Demo Seeding');
  destroyDb('demo');
  const demoDb = openDb('demo');
  seedDemo(demoDb);
  const demoAssets = q(demoDb).all('SELECT * FROM assets');
  const demoFindings = q(demoDb).all('SELECT * FROM findings');
  const demoRels = q(demoDb).all('SELECT * FROM relationships');
  assert(demoAssets.length === 5, 'Demo seeded exactly 5 assets (Student, Faculty, Portal, Lab, DB)');
  assert(demoFindings.length >= 10, 'Demo seeded sample vulnerabilities across assets');
  assert(demoRels.length >= 5, 'Demo seeded network relationships');

  // ==========================================
  // [2] Demo vs Live Mode Data Isolation
  // ==========================================
  console.log('\n[2] Testing Demo vs Live Mode Data Isolation');
  setMode('live');
  const liveDb = openDb('live');
  // Clear any existing test data in live table
  q(liveDb).run('DELETE FROM assets WHERE name = ?', 'Isolated Test Host');
  q(liveDb).run('INSERT INTO assets (name, ip, criticality, type, os) VALUES (?, ?, ?, ?, ?)', 'Isolated Test Host', '192.168.100.99', 'high', 'server', 'Linux');
  const liveCheck = q(liveDb).get('SELECT * FROM assets WHERE name = ?', 'Isolated Test Host');
  const demoCheck = q(demoDb).get('SELECT * FROM assets WHERE name = ?', 'Isolated Test Host');
  assert(liveCheck != null, 'Record written successfully to live.db');
  assert(demoCheck == null, 'Record in live.db is NOT visible in demo.db (Strict Isolation)');
  q(liveDb).run('DELETE FROM assets WHERE name = ?', 'Isolated Test Host');
  setMode('demo');

  // ==========================================
  // [3] Scope Guard & Lab Network Guardrails
  // ==========================================
  console.log('\n[3] Testing Scope Guard & Lab Network Guardrails');
  // Allowed targets
  assert((await validateScope('127.0.0.1')).ok === true, 'IPv4 Loopback 127.0.0.1 allowed');
  assert((await validateScope('localhost')).ok === true, 'localhost allowed (resolves to loopback)');
  assert((await validateScope('::1')).ok === true, 'IPv6 Loopback ::1 allowed');
  assert((await validateScope('fe80::1')).ok === true, 'IPv6 Link-Local fe80::1 allowed');
  assert((await validateScope('fc00::1')).ok === true, 'IPv6 Unique Local Address fc00::1 allowed');
  assert((await validateScope('10.0.1.5')).ok === true, 'Private Class A (10.0.1.5) allowed');
  assert((await validateScope('172.16.20.1')).ok === true, 'Private Class B (172.16.20.1) allowed');
  assert((await validateScope('192.168.56.101')).ok === true, 'Private Class C (192.168.56.101) allowed');
  assert((await validateScope('192.168.1.0/24')).ok === true, 'Small CIDR /24 lab subnet allowed');
  assert((await validateScope('10.0.0.0/28')).ok === true, 'Small CIDR /28 lab subnet allowed');

  // Blocked targets
  assert((await validateScope('8.8.8.8')).ok === false, 'Public IPv4 (Google DNS 8.8.8.8) rejected');
  assert((await validateScope('1.1.1.1')).ok === false, 'Public IPv4 (Cloudflare 1.1.1.1) rejected');
  assert((await validateScope('2001:4860:4860::8888')).ok === false, 'Public IPv6 rejected');
  assert((await validateScope('10.0.0.0/16')).ok === false, 'Large CIDR /16 rejected for safety');
  assert((await validateScope('192.168.0.0/16')).ok === false, 'Large CIDR /16 rejected for safety');
  assert((await validateScope('invalid..ip--format')).ok === false, 'Malformed IP address rejected');

  // ==========================================
  // [4] Nmap Profiles & Structured XML Parsing
  // ==========================================
  console.log('\n[4] Testing Nmap Profiles & Structured XML Parsing');
  const profs = profiles();
  assert(profs.quick != null && profs.standard != null && profs.vuln != null, 'Profiles quick, standard, and vuln defined');
  assert(profs.quick.args.includes('100'), 'Quick discovery specifically targets top 100 ports (--top-ports 100)');
  assert(profs.standard.args.includes('1000'), 'Standard assessment targets top 1000 ports (--top-ports 1000)');

  const sampleXml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.94">
<host starttime="1600000000" endtime="1600000010">
<status state="up" reason="localhost-response"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="localhost" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="135"><state state="open" reason="syn-ack"/><service name="msrpc" product="Microsoft Windows RPC"/></port>
<port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="microsoft-ds" product="Windows SMB"/></port>
<port protocol="tcp" portid="902"><state state="open" reason="syn-ack"/><service name="vmware-auth" product="VMware Authentication"/></port>
<port protocol="tcp" portid="912"><state state="open" reason="syn-ack"/><service name="vmware-auth" product="VMware Authentication"/></port>
</ports>
</host>
</nmaprun>`;
  const parsed = parseNmapXml(sampleXml);
  assert(parsed.hosts.length === 1, 'Parsed exactly 1 host from Nmap XML');
  assert(parsed.hosts[0].ports.length === 4, 'Parsed exactly 4 open TCP ports (135, 445, 902, 912)');
  assert(parsed.hosts[0].ports.some(p => p.port === 445 && p.service === 'microsoft-ds'), 'Parsed port 445 with correct service identification');

  // ==========================================
  // [5] Service Rules & Findings Classification
  // ==========================================
  console.log('\n[5] Testing Service Rules & Heuristic vs Confirmed Findings');
  const smbFindings = serviceRuleFindings(
    { id: 1, ip: '127.0.0.1', name: 'My Laptop' },
    [
      { port: 135, service: 'msrpc', protocol: 'tcp' },
      { port: 445, service: 'microsoft-ds', protocol: 'tcp' },
      { port: 902, service: 'vmware-auth', protocol: 'tcp' },
      { port: 912, service: 'vmware-auth', protocol: 'tcp' }
    ]
  );
  assert(smbFindings.length >= 1, 'Generated finding for exposed port 445');
  const smbRule = smbFindings.find(f => f.port === 445);
  assert(smbRule.finding_type === 'exposure', 'Finding type is correctly labeled "exposure" (not confirmed exploit)');
  assert(smbRule.confidence === 'heuristic', 'Confidence is labeled "heuristic" (port observation rule)');
  assert(smbRule.cve === null, 'No CVE is fabricated for generic port observation');
  assert(smbRule.severity_rationale != null, 'Severity rationale is provided');
  assert(smbRule.limitations.includes('loopback') || smbRule.limitations.includes('127.0.0.1'), 'Limitations note highlights local loopback observation');

  // ==========================================
  // [6] Risk Scoring Formula & 17-pt Localhost Regression
  // ==========================================
  console.log('\n[6] Testing Risk Scoring Formula & 17-pt Localhost Regression');
  // Construct the exact user observed localhost state:
  const localhostData = {
    assets: [{ id: 1, name: 'My Laptop', ip: '127.0.0.1', criticality: 'medium', type: 'endpoint' }],
    services: [
      { id: 101, asset_id: 1, port: 135, protocol: 'tcp', service: 'msrpc' },
      { id: 102, asset_id: 1, port: 445, protocol: 'tcp', service: 'microsoft-ds' },
      { id: 103, asset_id: 1, port: 902, protocol: 'tcp', service: 'vmware-auth' },
      { id: 104, asset_id: 1, port: 912, protocol: 'tcp', service: 'vmware-auth' },
    ],
    findings: [
      { id: 201, asset_id: 1, port: 445, title: 'SMB/NetBIOS file sharing exposed to the network (port 445)', severity: 'medium', status: 'open' }
    ],
    relationships: []
  };
  const localhostModel = computeModel(localhostData);
  const laptopScore = localhostModel.assets[0];
  assert(laptopScore.score === 17, `Localhost regression: Score is exactly 17/100 (Observed: ${laptopScore.score})`);
  assert(laptopScore.level === 'low', `Localhost level is "low" (Observed: ${laptopScore.level})`);
  assert(laptopScore.breakdown.vulnerability === 6, 'Vuln score: 1 Medium finding = 6 pts');
  assert(laptopScore.breakdown.exposure === 11, 'Exposure score: 4 ports × 2 = 8 pts + SMB/445 bonus 3 pts = 11 pts');
  assert(laptopScore.breakdown.relationship === 0, 'Relationship score: 0 pts (no relationships)');
  assert(laptopScore.breakdown.multiplier === 1.0, 'Criticality multiplier: Medium = 1.0');
  assert(localhostModel.paths.length === 0, 'Paths detected: 0 paths (single host network)');
  assert(localhostModel.pathContext.explanation.includes('Single asset'), 'Zero-path explanation clarifies single-asset topology');

  // Test Caps and Criticality Multiplier
  const heavyData = {
    assets: [{ id: 1, name: 'Heavy Host', ip: '10.0.0.1', criticality: 'critical', type: 'server' }],
    services: Array.from({ length: 20 }, (_, i) => ({ id: 500 + i, asset_id: 1, port: 2000 + i, protocol: 'tcp', service: 'custom' })),
    findings: Array.from({ length: 10 }, (_, i) => ({ id: 600 + i, asset_id: 1, port: 2000 + i, title: `Crit ${i}`, severity: 'critical', status: 'open' })),
    relationships: []
  };
  const heavyModel = computeModel(heavyData);
  const heavyAsset = heavyModel.assets[0];
  assert(heavyAsset.breakdown.vulnerability === 50, 'Vulnerability score capped at 50 pts (even with 10 criticals)');
  assert(heavyAsset.breakdown.exposure === 20, 'Exposure score capped at 20 pts (even with 20 services)');
  assert(heavyAsset.score <= 100, `Final score strictly capped at 100 (Calculated: ${heavyAsset.score})`);

  // ==========================================
  // [7] Security Graph & Attack Path Analysis
  // ==========================================
  console.log('\n[7] Testing Security Graph & Attack Path Traversal');
  const demoData = loadData(demoDb);
  const demoModel = computeModel(demoData);
  assert(demoModel.paths.length >= 2, `Demo network identified multi-hop risk paths (found ${demoModel.paths.length})`);
  const topPath = demoModel.paths[0];
  assert(topPath.nodes.length >= 2, 'Top path contains multiple hops');
  assert(topPath.vulnerableHops.length >= 1, 'Top path identifies vulnerable hops along the chain');
  assert(typeof topPath.explanation === 'string' && topPath.explanation.length > 20, 'Top path includes plain-English risk rationale');

  // Two disconnected assets test
  const disconnectedData = {
    assets: [
      { id: 1, name: 'Host A', ip: '10.0.0.1', criticality: 'low', type: 'endpoint', is_entry_point: 1 },
      { id: 2, name: 'Host B', ip: '10.0.0.2', criticality: 'critical', type: 'database' }
    ],
    services: [],
    findings: [{ id: 1, asset_id: 1, title: 'Vuln', severity: 'high', status: 'open' }],
    relationships: []
  };
  const disconModel = computeModel(disconnectedData);
  assert(disconModel.paths.length === 0, 'Disconnected assets produce 0 paths');
  assert(disconModel.pathContext.explanation.includes('No network relationships mapped'), 'Explanation clarifies lack of mapped connections');

  // ==========================================
  // [8] What-If Remediation Simulation
  // ==========================================
  console.log('\n[8] Testing What-If Remediation Simulation');
  // Scenario A: Simulating fixing finding on localhost
  const simFixFinding = computeModel(localhostData, {
    fixedFindings: new Set([201]),
    blockedRels: new Set(),
    closedServices: new Set()
  });
  // Without finding: Vuln = 0, Exposure = 11, Base = 11 × 1.0 = 11/100
  assert(simFixFinding.assets[0].score === 11, `Fixing finding reduces score from 17 to ${simFixFinding.assets[0].score}/100 (-6 pts)`);
  assert(simFixFinding.overall.openServices === 4, 'Underlying services remain listening when only finding is resolved');

  // Scenario B: Simulating blocking service/port 445 on localhost
  const simBlockService = computeModel(localhostData, {
    fixedFindings: new Set(),
    blockedRels: new Set(),
    closedServices: new Set([102]) // Port 445
  });
  // With port 445 closed:
  // Port 445 finding is removed (tied to port 445) -> Vuln = 0
  // 3 remaining ports (135, 902, 912) -> 3 × 2 = 6 pts (No high risk SMB bonus) -> Exposure = 6
  // Score = 6 × 1.0 = 6/100! (-11 pts reduction)
  assert(simBlockService.assets[0].score === 6, `Blocking port 445 reduces score from 17 to ${simBlockService.assets[0].score}/100 (-11 pts)`);
  assert(simBlockService.overall.openServices === 3, 'Service count drops from 4 to 3');

  // Scenario C: Verify baseline immutability
  assert(localhostData.services.length === 4, 'Raw baseline services array remained completely immutable');
  assert(localhostData.findings.length === 1, 'Raw baseline findings array remained completely immutable');

  // ==========================================
  // [9] Offline PCAP & Authentication Log Analysis
  // ==========================================
  console.log('\n[9] Testing Offline PCAP & Authentication Log Analysis');
  const pcapBuffer = fs.readFileSync(path.join(SAMPLES_DIR, 'sample_capture.pcap'));
  const pcapResult = analyzePcap(pcapBuffer);
  assert(pcapResult.packetCount > 0, `Parsed ${pcapResult.packetCount} packets from sample capture`);
  assert(pcapResult.protocols.some(p => p.name === 'HTTP' && p.risk === 'review'), 'Detected unencrypted HTTP traffic');
  assert(pcapResult.protocols.some(p => p.name === 'FTP' && p.risk === 'review'), 'Detected unencrypted FTP traffic');
  assert(pcapResult.credentialIndicators.ftp > 0, 'Observed cleartext credential indicator for FTP PASS');

  const logContent = fs.readFileSync(path.join(SAMPLES_DIR, 'sample_auth.log'), 'utf8');
  const logResult = analyzeLogs(logContent, 'sample_auth.log');
  assert(logResult.findings.some(f => f.event.includes('Failed SSH') && f.risk === 'critical'), 'Identified critical repeated SSH failed logins');

  // ==========================================
  // [10] Multi-Page PDF Report Generation
  // ==========================================
  console.log('\n[10] Testing Multi-Page PDF Report Generation');
  const pdfBuffer = await generateReportPdf(demoDb, 'demo');
  assert(pdfBuffer.length > 5000, `PDF generated successfully (size: ${pdfBuffer.length} bytes)`);
  assert(pdfBuffer.subarray(0, 5).toString('ascii') === '%PDF-', 'Buffer has valid %PDF- magic header');

  const livePdfBuffer = await generateReportPdf(liveDb, 'live');
  assert(livePdfBuffer.length > 3000, `Live mode PDF generated successfully (size: ${livePdfBuffer.length} bytes)`);

  console.log(`\n======================================================`);
  console.log(`CampusShield Test Suite: ${passed} Passed, ${failed} Failed.`);
  console.log(`======================================================\n`);

  if (failed > 0) process.exit(1);
}

runTests().catch(err => {
  console.error('Smoke test suite encountered unhandled error:', err);
  process.exit(1);
});
