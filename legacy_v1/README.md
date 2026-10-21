# CampusShield

CampusShield is a local-first VAPT assessment and network-risk visualization platform for authorized college labs. It combines asset inventory, findings, modeled relationships, explainable risk scoring, what-if remediation, offline PCAP/log summaries and PDF export.

## Run it

Requires Node.js 20 or newer. No npm packages or network downloads are needed.

```powershell
node server.js
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). The app listens on loopback only. Set `PORT` to choose another local port.

Workspace data is stored in `data/db.json`. It is created the first time the server starts and is intentionally excluded from Git. Use **Settings → Reset to demo data** to restore the bundled fixture (this replaces the current workspace).

Use the **Demo / Live mode button** in the top bar to switch modes from any page. Switching modes replaces the current mode's dataset after a confirmation prompt; switching to Live clears only the bundled demo records, while switching back to Demo restores the bundled sample workspace.

## What works

- **Dashboard:** database-backed counts, severity distribution, asset risk ranking, recent scans and common services.
- **Targets and assets:** create authorized private-lab targets, update or delete assets, inspect services/findings, and filter/search the inventory.
- **Network scans:** optional Nmap `-sV` service discovery on the top 100 TCP ports; import Nmap XML when the binary is unavailable. A built-in safe web baseline makes bounded GET requests and checks common response headers on discovered HTTP(S) services. Scans require a saved authorization note and accept loopback, private or link-local IPv4 addresses only. Demo fixture targets cannot be scanned.
- **Findings:** add manually reviewed findings, import OWASP ZAP JSON findings scoped to the selected asset, verify CVE syntax (unknown CVEs remain “Not Mapped”), retain CWE identifiers, filter by severity/status, and track Open → Under Review → Planned → Fixed → Retested.
- **Security graph:** interactive SVG map of actual assets and modeled access/dependency relationships.
- **Risk analysis:** asset score from severity-weighted active findings, exposed services, relationship count, asset criticality and a critical-asset connection bonus. Risk paths explain the relevant finding and modeled relationship; they are prioritization scenarios, not proof of exploitability.
- **Remediation:** simulate one or more fixes to update the what-if risk view, then undo simulations. Simulations do not alter a target or finding status.
- **Packet analysis:** offline classic Ethernet PCAP summaries (IPv4, TCP/UDP/ICMP, top flows and HTTP/FTP/Telnet review flags). PCAPNG, IPv6 and other link types are not currently supported.
- **Log analysis:** offline summaries of repeated failed logins, HTTP errors and request lines. This is a small educational heuristic, not an IDS.
- **Reports:** download a locally generated PDF summary based on workspace records.

## Safety and limitations

- Use only systems you own or have explicit permission to assess. CampusShield is designed for localhost, private lab networks and authorized VMs.
- The web server binds to `127.0.0.1`. Live scanning is limited to private/link-local IPv4 or localhost and requires an authorization note. Nmap runs with service detection only; CampusShield does not exploit systems or change target configuration.
- Nmap is an optional external tool. CampusShield does not claim that a port scan is a vulnerability scan. Record verified results from your approved assessment process as findings; the bundled demonstration findings are explicitly fixtures.
- The built-in web check is a non-exploitative baseline for common HTTP response headers and cleartext HTTP. It is not a replacement for OWASP ZAP, authenticated testing, or a full vulnerability scanner. Nmap XML and ZAP JSON imports let you bring actual authorized scanner results into the same asset/risk/report workflow.
- Risk scores are a transparent project-specific heuristic, not CVSS or a compliance rating.
- Data persistence is a local JSON file, intended for a single-user project/demo and not concurrent or production use. Keep authorized log/PCAP uploads local and avoid sensitive captures.
- There is no authentication or multi-user access control. Keep the service bound to loopback and do not expose it to a shared or public network.

## Suggested viva path

1. Show the clearly labeled demo dashboard and bundled network.
2. Open Findings and explain the difference between an individual finding and a relationship-based risk scenario.
3. Explore the Security Graph and explain one connection.
4. Open Risk Analysis to inspect the scoring reasons and path explanation.
5. Simulate a remediation and show the changed what-if score; undo it to restore the baseline.
6. Generate the PDF report.
7. If the isolated lab is available and Nmap is installed, add a target with an authorization note and demonstrate the limited service scan.
