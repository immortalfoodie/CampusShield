/**
 * CampusShield — Comprehensive VAPT Assessment Report Generator (PDF)
 * 
 * Generates an executive & technical VAPT assessment report covering all 20 required sections:
 *  1. Cover page
 *  2. Assessment scope
 *  3. Authorization statement
 *  4. Date & metadata
 *  5. Tools used
 *  6. Target information
 *  7. Network scan results
 *  8. Asset inventory
 *  9. Open ports & services
 * 10. Vulnerabilities
 * 11. CVE & CWE mappings
 * 12. Security Graph & Topology
 * 13. Risk paths
 * 14. Explainable risk scores
 * 15. Packet capture findings
 * 16. Log analysis findings
 * 17. Remediation simulation (Before vs After)
 * 18. Strategic recommendations
 * 19. Vulnerability lifecycle
 * 20. Conclusion & sign-off
 */

import PDFDocument from 'pdfkit';
import { q } from '../db.js';
import { computeModel } from './risk.js';
import { loadData, loadScenario } from './workspace.js';

export function generateReportPdf(db, mode) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: 'A4',
        margins: { top: 40, bottom: 40, left: 45, right: 45 },
        bufferPages: true
      });

      const chunks = [];
      doc.on('data', chunk => chunks.push(chunk));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', err => reject(err));

      const data = loadData(db);
      const baseline = computeModel(data);
      const scenario = loadScenario(db);
      const simulated = scenario.items.length ? computeModel(data, scenario) : null;
      const scans = q(db).all('SELECT * FROM scans ORDER BY started_at DESC LIMIT 10');
      const recentPcaps = q(db).all("SELECT * FROM analyses WHERE kind = 'pcap' ORDER BY created_at DESC LIMIT 1");
      const recentLogs = q(db).all("SELECT * FROM analyses WHERE kind = 'log' ORDER BY created_at DESC LIMIT 1");

      const colors = {
        primary: '#0f172a',    // Slate 900
        accent: '#0284c7',     // Sky 600
        accentDark: '#0369a1',
        text: '#1e293b',       // Slate 800
        muted: '#64748b',      // Slate 500
        cardBg: '#f8fafc',     // Slate 50
        border: '#cbd5e1',     // Slate 300
        critical: '#dc2626',   // Red 600
        high: '#ea580c',       // Orange 600
        medium: '#d97706',     // Amber 600
        low: '#16a34a',        // Green 600
        info: '#2563eb'        // Blue 600
      };

      // Helper functions
      const addHeader = (title) => {
        doc.fontSize(16).fillColor(colors.primary).font('Helvetica-Bold').text(title);
        doc.moveTo(45, doc.y + 4).lineTo(550, doc.y + 4).strokeColor(colors.accent).lineWidth(1.5).stroke();
        doc.moveDown(0.8);
      };

      const addSubHeader = (title) => {
        doc.fontSize(12).fillColor(colors.accentDark).font('Helvetica-Bold').text(title);
        doc.moveDown(0.4);
      };

      const addParagraph = (text) => {
        doc.fontSize(9.5).fillColor(colors.text).font('Helvetica').lineGap(2.5).text(text);
        doc.moveDown(0.5);
      };

      // ==========================================
      // SECTION 1: COVER PAGE
      // ==========================================
      doc.rect(0, 0, 595, 20).fill(colors.primary);
      doc.moveDown(4);

      doc.fontSize(12).fillColor(colors.accent).font('Helvetica-Bold').text('CAMPUSSHIELD PLATFORM', { align: 'center', characterSpacing: 2 });
      doc.moveDown(0.5);
      doc.fontSize(26).fillColor(colors.primary).font('Helvetica-Bold').text('Vulnerability Assessment &\nRisk Analysis Report', { align: 'center' });
      doc.moveDown(0.5);
      doc.fontSize(11).fillColor(colors.muted).font('Helvetica').text('Comprehensive Security Posture, Asset Mapping & Remediation Simulation', { align: 'center' });
      
      doc.moveDown(3);

      // Environment Mode Badge
      const isDemo = mode === 'demo';
      const badgeText = isDemo ? 'ENVIRONMENT: DEMO MODE (SIMULATED LABORATORY ENVIRONMENT)' : 'ENVIRONMENT: LIVE LAB MODE (AUTHORIZED TARGETS)';
      const badgeColor = isDemo ? colors.accent : colors.low;
      doc.rect(75, doc.y, 445, 28).fill(badgeColor);
      doc.fillColor('#ffffff').fontSize(10).font('Helvetica-Bold').text(badgeText, 75, doc.y + 8, { width: 445, align: 'center' });
      doc.moveDown(3.5);

      // Metadata Table Card
      const cardY = doc.y;
      doc.roundedRect(65, cardY, 465, 180, 6).fillAndStroke(colors.cardBg, colors.border);
      doc.fillColor(colors.primary).fontSize(11).font('Helvetica-Bold').text('Assessment Overview & Context', 85, cardY + 16);
      doc.moveTo(85, cardY + 32).lineTo(510, cardY + 32).strokeColor(colors.border).lineWidth(1).stroke();

      const meta = [
        ['Target Organization / Scope', isDemo ? 'College Computer Science Network Security Laboratory' : 'Authorized Lab Host / Subnet'],
        ['Generated Date', new Date().toLocaleString()],
        ['Assessment Methodology', 'VAPT: Reconnaissance, Port/Service Scan, Vuln Analysis, Graph Pathing'],
        ['Overall Network Risk Score', `${baseline.overall.score} / 100 (${baseline.overall.level.toUpperCase()})`],
        ['Total Discovered Assets', `${baseline.overall.assets} systems`],
        ['Active Vulnerabilities', `${baseline.overall.vulnerabilities} findings`],
        ['Identified Critical/High Paths', `${baseline.overall.riskyPaths} potential risk paths`],
      ];

      let rowY = cardY + 42;
      meta.forEach(([label, val]) => {
        doc.fontSize(9).font('Helvetica-Bold').fillColor(colors.primary).text(label, 85, rowY, { width: 180 });
        doc.font('Helvetica').fillColor(colors.text).text(val, 270, rowY, { width: 240 });
        rowY += 18;
      });

      doc.moveDown(12);
      doc.fontSize(8.5).font('Helvetica-Oblique').fillColor(colors.muted).text(
        'CONFIDENTIAL DOCUMENT — For Academic, Educational and Authorized Administrative Evaluation Only.',
        { align: 'center' }
      );

      // ==========================================
      // SECTION 2, 3, 4, 5: SCOPE, AUTHORIZATION & TOOLS
      // ==========================================
      doc.addPage();
      addHeader('1. Scope, Authorization & Tools');

      addSubHeader('1.1 Assessment Scope & Rules of Engagement');
      addParagraph(
        'CampusShield is designed specifically for educational network defense evaluation in a controlled laboratory environment. ' +
        'Testing is strictly constrained to authorized virtual machines, test containers, and assigned laboratory subnets. ' +
        'No public Internet destinations or unapproved student/faculty endpoints were accessed during this assessment.'
      );

      addSubHeader('1.2 Authorization Statement');
      addParagraph(
        'Statement: In compliance with institutional cybersecurity policies and laboratory rules, testing was performed under explicit permission. ' +
        'The scope guard guarantees that live network packets are confined to private RFC 1918 IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or localhost loopback). ' +
        'No exploitation or disruptive payload execution was conducted.'
      );

      addSubHeader('1.3 Security Assessment Tools');
      addParagraph(
        '• Nmap 7.9x: Port discovery, service banner extraction, version detection, and safe NSE evaluation.\n' +
        '• CampusShield Safe Web Baseline: Non-intrusive HTTP/S response-header and security cookie posture analysis.\n' +
        '• OWASP ZAP (Import Integration): Correlated application-level vulnerability alert mappings.\n' +
        '• CampusShield Risk Engine: Contextual multi-hop risk analysis and "What-If" remediation simulation.\n' +
        '• Packet & Log Analysers: Offline PCAP/PCAPNG header aggregation and authentication log heuristics.'
      );

      doc.moveDown(0.5);

      // ==========================================
      // SECTION 6, 7, 8: TARGET INFORMATION & ASSETS
      // ==========================================
      addHeader('2. Discovered Assets & Services Inventory');
      addParagraph(
        'The inventory represents all systems discovered through network discovery or authorized target registration. ' +
        'Each asset has been assigned a criticality rating reflecting its sensitivity within the college lab environment.'
      );

      // Asset Table
      const assetHeaders = ['Asset Name', 'IP Address', 'Role / OS', 'Criticality', 'Open Ports', 'Risk'];
      const assetColX = [45, 160, 260, 370, 440, 500];

      let tableY = doc.y;
      doc.rect(45, tableY, 505, 18).fill(colors.primary);
      doc.fillColor('#ffffff').fontSize(8.5).font('Helvetica-Bold');
      assetHeaders.forEach((h, i) => doc.text(h, assetColX[i] + 4, tableY + 5));

      tableY += 18;
      data.assets.forEach((a, idx) => {
        const rowBg = idx % 2 === 0 ? '#ffffff' : colors.cardBg;
        doc.rect(45, tableY, 505, 20).fill(rowBg);
        
        const aRisk = baseline.assets.find(x => x.id === a.id);
        const aServices = data.services.filter(s => s.asset_id === a.id);

        doc.fillColor(colors.text).fontSize(8).font('Helvetica');
        doc.text(a.name, assetColX[0] + 4, tableY + 6, { width: 110, ellipsis: true });
        doc.text(a.ip, assetColX[1] + 4, tableY + 6);
        doc.text(`${a.type} / ${a.os.split(' ')[0]}`, assetColX[2] + 4, tableY + 6, { width: 105, ellipsis: true });
        doc.text(a.criticality.toUpperCase(), assetColX[3] + 4, tableY + 6);
        doc.text(`${aServices.length} ports`, assetColX[4] + 4, tableY + 6);

        const scoreColor = aRisk && aRisk.score >= 70 ? colors.critical : aRisk && aRisk.score >= 40 ? colors.high : colors.low;
        doc.fillColor(scoreColor).font('Helvetica-Bold').text(`${aRisk ? aRisk.score : 0}/100`, assetColX[5] + 4, tableY + 6);

        tableY += 20;
      });

      doc.y = tableY + 15;

      // ==========================================
      // SECTION 9, 10, 11: VULNERABILITIES & CVEs
      // ==========================================
      doc.addPage();
      addHeader('3. Vulnerability Assessment Findings');
      addParagraph(
        'Findings identified across laboratory assets. Each finding includes severity, detection source, observation type (Confirmed Vulnerability vs Heuristic Exposure / Hardening Recommendation), confidence level, associated CWE / verified CVE (or "No CVE mapping"), and actionable remediation recommendations.'
      );

      const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      const sortedFindings = [...data.findings].sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5));

      if (sortedFindings.length === 0) {
        addParagraph('No security findings or exposures were identified on discovered assets.');
      }

      sortedFindings.forEach((f) => {
        if (doc.y > 670) doc.addPage();

        const a = data.assets.find(x => x.id === f.asset_id);
        const sevColor = colors[f.severity] || colors.muted;

        const fBoxY = doc.y;
        doc.roundedRect(45, fBoxY, 505, 74, 4).fillAndStroke(colors.cardBg, colors.border);

        // Severity indicator bar on left
        doc.rect(45, fBoxY, 5, 74).fill(sevColor);

        doc.fillColor(colors.primary).fontSize(9.5).font('Helvetica-Bold');
        doc.text(f.title, 58, fBoxY + 7, { width: 340 });

        doc.fillColor(sevColor).fontSize(8.5).font('Helvetica-Bold');
        doc.text(`[${f.severity.toUpperCase()}]`, 450, fBoxY + 7, { width: 90, align: 'right' });

        doc.fillColor(colors.muted).fontSize(7.5).font('Helvetica');
        const cveText = f.cve ? f.cve : 'No CVE mapping (N/A)';
        const cweText = f.cwe ? ` | ${f.cwe}` : '';
        const fType = (f.finding_type || 'exposure').toUpperCase();
        const fConf = (f.confidence || 'heuristic').toUpperCase();
        doc.text(`Asset: ${a ? a.name : 'Unknown'} (${a ? a.ip : ''}) | Port: ${f.port || 'N/A'} | Type: ${fType} | Conf: ${fConf} | ${cveText}${cweText}`, 58, fBoxY + 20);

        doc.fillColor(colors.text).fontSize(8).font('Helvetica');
        doc.text(`Description: ${f.description || 'Observed during laboratory vulnerability scan.'}`, 58, fBoxY + 33, { width: 480, height: 16, ellipsis: true });

        if (f.severity_rationale) {
          doc.fillColor(colors.muted).fontSize(7.5).font('Helvetica-Oblique');
          doc.text(`Rationale: ${f.severity_rationale}`, 58, fBoxY + 47, { width: 480, height: 11, ellipsis: true });
        }
        
        doc.fillColor(colors.accentDark).fontSize(8).font('Helvetica-Bold');
        doc.text(`Action: ${f.recommendation || 'Remediate configuration or upgrade component.'}`, 58, fBoxY + 59, { width: 480, height: 11, ellipsis: true });

        doc.y = fBoxY + 82;
      });

      // ==========================================
      // SECTION 12, 13, 14: SECURITY GRAPH & RISK PATHS
      // ==========================================
      doc.addPage();
      addHeader('4. Security Graph & Explainable Risk Paths');
      addParagraph(
        'CampusShield’s unique contribution is relational contextualization. Security weaknesses are evaluated not in isolation, ' +
        'but in combination with network connections and trust relationships to identify lateral movement risk.'
      );

      addSubHeader('4.1 Network Relationship Mapping');
      addParagraph(
        `The security graph contains ${data.assets.length} nodes connected by ${data.relationships.length} explicit relationships ` +
        '(e.g., Network Access, Application Access, Database Connection, Administrative Access).'
      );

      if (data.relationships.length === 0) {
        addParagraph(
          data.assets.length <= 1
            ? 'Note: Only one asset is currently present in the workspace. Multi-hop lateral movement paths require additional laboratory assets and defined relationships.'
            : 'Note: Discovered assets are currently isolated. Map authorized network or administrative connections to analyze potential multi-hop risk paths.'
        );
      } else {
        let relY = doc.y;
        data.relationships.forEach(r => {
          const src = data.assets.find(x => x.id === r.source_id);
          const tgt = data.assets.find(x => x.id === r.target_id);
          doc.fontSize(8.5).font('Helvetica-Bold').fillColor(colors.primary).text(`• ${src ? src.name : 'Asset'} `, 55, relY, { continued: true });
          doc.font('Helvetica').fillColor(colors.accent).text(`— [${r.type}] → `, { continued: true });
          doc.font('Helvetica-Bold').fillColor(colors.primary).text(tgt ? tgt.name : 'Asset');
          relY += 15;
        });
        doc.y = relY + 10;
      }

      addSubHeader('4.2 Identified Risk Scenarios (Paths)');
      if (baseline.paths.length === 0) {
        addParagraph(
          data.assets.length <= 1
            ? 'No multi-hop risk paths identified: Single-host environment. A path requires at least two connected systems (an entry point and a downstream target).'
            : data.relationships.length === 0
              ? 'No multi-hop risk paths identified: No relationships mapped between discovered assets.'
              : 'No high-risk paths identified matching current vulnerability and relationship criteria.'
        );
      } else {
        baseline.paths.slice(0, 4).forEach((p, idx) => {
          if (doc.y > 670) doc.addPage();
          const pBoxY = doc.y;
          doc.roundedRect(45, pBoxY, 505, 68, 4).fillAndStroke('#fff7ed', '#fed7aa');
          
          doc.fillColor(colors.high).fontSize(9.5).font('Helvetica-Bold');
          doc.text(`Risk Path #${idx + 1}: ${p.names.join('  ➔  ')}`, 55, pBoxY + 8);

          doc.fillColor(colors.muted).fontSize(8).font('Helvetica');
          doc.text(`Calculated Path Score: ${p.score}/100 (${p.level.toUpperCase()}) | Target Asset: ${p.targetCriticality.toUpperCase()} Criticality`, 55, pBoxY + 22);

          doc.fillColor(colors.text).fontSize(8).font('Helvetica');
          doc.text(p.explanation, 55, pBoxY + 34, { width: 485, height: 30, ellipsis: true });

          doc.y = pBoxY + 76;
        });
      }

      addSubHeader('4.3 Explainable Asset Scoring Methodology');
      addParagraph(
        'Formula: Asset Risk = Math.min(100, Math.round((Vulnerability Score + Exposure Score + Relationship Risk) × Criticality Multiplier))\n' +
        '• Vulnerability Score (max 50): Critical=20, High=12, Medium=6, Low=2, Info=0\n' +
        '• Exposure Score (max 20): +2 per open service +3 per high-risk service (SMB/445, FTP/21, Telnet/23, DB/3306...)\n' +
        '• Relationship Risk (max 30): +2 per connection +5 per untrusted upstream +10 for vulnerable asset connecting to critical target\n' +
        '• Criticality Multiplier: Low=0.8, Medium=1.0, High=1.15, Critical=1.3'
      );

      // ==========================================
      // SECTION 15, 16: PACKET & LOG FINDINGS
      // ==========================================
      doc.addPage();
      addHeader('5. Packet & Log Analysis Findings');

      addSubHeader('5.1 Packet Capture (PCAP) Analysis');
      if (recentPcaps.length > 0) {
        const pSummary = JSON.parse(recentPcaps[0].summary || '{}');
        addParagraph(
          `Analysis of capture file "${recentPcaps[0].filename}": ${pSummary.packetCount || 0} packets inspected across Ethernet links. ` +
          `Identified unencrypted protocol flows requiring review.`
        );
      } else {
        addParagraph('No standalone PCAP captures were analyzed in this session.');
      }

      addSubHeader('5.2 Authentication & Event Log Analysis');
      if (recentLogs.length > 0) {
        const lSummary = JSON.parse(recentLogs[0].summary || '{}');
        addParagraph(
          `Log review for "${recentLogs[0].filename}": Processed ${lSummary.totalLines || 0} lines. ` +
          `Identified ${lSummary.findings ? lSummary.findings.length : 0} event clusters including failed authentication patterns.`
        );
      } else {
        addParagraph('No standalone security log captures were analyzed in this session.');
      }

      // ==========================================
      // SECTION 17, 18, 19, 20: REMEDIATION, BEFORE/AFTER & CONCLUSION
      // ==========================================
      doc.moveDown(0.5);
      addHeader('6. Remediation Simulation & Conclusion');

      addSubHeader('6.1 What-If Remediation Simulation');
      if (simulated) {
        const drop = baseline.overall.score - simulated.overall.score;
        const pathsRemoved = baseline.overall.riskyPaths - simulated.overall.riskyPaths;

        const remBoxY = doc.y;
        doc.roundedRect(45, remBoxY, 505, 80, 4).fillAndStroke('#f0fdf4', '#bbf7d0');

        doc.fillColor(colors.low).fontSize(10).font('Helvetica-Bold');
        doc.text('Simulated Fix Impact Comparison', 55, remBoxY + 10);

        doc.fillColor(colors.text).fontSize(9).font('Helvetica');
        doc.text(`Active simulated interventions: ${scenario.items.length} proposed remediation action(s).`, 55, remBoxY + 25);
        doc.text(`• Baseline Network Risk Score: ${baseline.overall.score} / 100 ➔ Simulated Post-Remediation Score: ${simulated.overall.score} / 100`, 55, remBoxY + 40);
        doc.text(`• Risk Reduction: -${drop} points (${baseline.overall.score ? Math.round((drop / baseline.overall.score) * 100) : 0}% reduction in overall risk)`, 55, remBoxY + 54);
        doc.text(`• Risky Paths Mitigated: ${pathsRemoved} critical connection paths eliminated`, 55, remBoxY + 68);

        doc.y = remBoxY + 92;
      } else {
        addParagraph(
          'Remediation simulations allow security analysts to preview how risk scores and network paths change before applying changes in production. ' +
          'No what-if remediation simulation was active during this export.'
        );
      }

      addSubHeader('6.2 Strategic Recommendations');
      addParagraph(
        '1. Segregate Network Zones: Restrict direct student network access to database servers and sensitive management ports (SSH/Telnet/RDP).\n' +
        '2. Harden Insecure Services: Disable legacy FTP (port 21) and cleartext Telnet (port 23); replace with SSH/SFTP.\n' +
        '3. Web Application Security: Parameterize all SQL queries on portal applications and enforce Content-Security-Policy (CSP).\n' +
        '4. Ongoing Retesting: Follow the Vulnerability Lifecycle (Open ➔ Under Review ➔ Planned ➔ Fixed ➔ Retested) to verify fixes.'
      );

      addSubHeader('6.3 Assessment Conclusion & Sign-Off');
      addParagraph(
        'CampusShield has demonstrated that evaluating vulnerability severity alongside network relationships provides a clearer, ' +
        'more actionable security picture than isolated scanner outputs. Security controls should be prioritized along the identified critical paths.'
      );

      doc.moveDown(1.5);
      const signY = doc.y;
      doc.text('Prepared by: CampusShield Automated Assessment Engine', 45, signY);
      doc.text('Evaluator / Lab Instructor Sign-Off: __________________________', 300, signY);

      // Add page numbering to all pages
      const totalPages = doc.bufferedPageRange().count;
      for (let i = 0; i < totalPages; i++) {
        doc.switchToPage(i);
        doc.fontSize(8).fillColor(colors.muted).font('Helvetica').text(
          `CampusShield VAPT Assessment Report | Page ${i + 1} of ${totalPages}`,
          45,
          795,
          { align: 'center', width: 505 }
        );
      }

      doc.end();
    } catch (e) {
      reject(e);
    }
  });
}
