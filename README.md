# CampusShield 🛡️
### Contextual VAPT Network Security Assessment & Risk Mapping Platform

CampusShield is a local-first Vulnerability Assessment and Penetration Testing (VAPT) platform designed for controlled college laboratory networks. Instead of treating vulnerabilities as isolated bullet points, CampusShield maps network relationships, identifies multi-hop risk paths, and allows security evaluators to simulate the impact of remediation before applying fixes.

---

## 🚀 Quick Start

### Prerequisites
- **Node.js 22.13+** (utilizes native `node:sqlite`)
- *(Optional for Live Scanning)*: **Nmap** installed on the host machine. (Nmap is already detected on your Windows machine at `C:\Program Files (x86)\Nmap\nmap.exe`).

### Installation & Launch
```powershell
# 1. Install dependencies
npm install

# 2. (Optional) Re-generate sample PCAP and log captures
npm run samples

# 3. Run the automated test suite
npm test

# 4. Start the server
npm start
```

Access the application in your browser at:
👉 **[http://127.0.0.1:4173](http://127.0.0.1:4173)**

---

## 🏛️ 5-Layer Project Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      PRESENTATION LAYER                     │
│   Dashboard  |  Security Graph  |  Risk Analysis | Reports   │
├─────────────────────────────────────────────────────────────┤
│                       ANALYSIS LAYER                        │
│   Risk Scoring Engine  |  Multi-Hop Path Analysis  | What-If│
├─────────────────────────────────────────────────────────────┤
│                       SECURITY LAYER                        │
│   Nmap Scanner  |  Web Baseline  |  PCAP  |  Log Parser     │
├─────────────────────────────────────────────────────────────┤
│                         DATA LAYER                          │
│   SQLite (data/demo.db & data/live.db)  |  Zero Data Loss   │
├─────────────────────────────────────────────────────────────┤
│                 CONTROLLED LAB ENVIRONMENT                  │
│   Authorized Lab VMs  |  DVWA  |  Student / Faculty PCs     │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 What Makes CampusShield Different?

Traditional student VAPT projects follow:
$$\text{Scan} \longrightarrow \text{Find Vulnerabilities} \longrightarrow \text{Display List}$$

CampusShield follows:
$$\text{Discover} \longrightarrow \text{Assess} \longrightarrow \text{Connect} \longrightarrow \text{Understand} \longrightarrow \text{Prioritize} \longrightarrow \text{Simulate} \longrightarrow \text{Report}$$

### Core Distinctions
1. **Finding vs. Risk Path**:
   - *Finding*: Faculty Portal has an SQL injection vulnerability.
   - *Risk Path*: $\text{Student PC} \xrightarrow{\text{Network Access}} \text{Faculty Portal} \xrightarrow{\text{DB Connection}} \text{Database Server}$.
   - Because the Faculty Portal is connected to a sensitive Database Server, this weakness represents an escalated risk path requiring priority remediation.
2. **Transparent, Explainable Risk Score**:
   - Not a black-box CVSS substitute. Transparent heuristic:
     $$\text{Asset Risk} = (\text{Vulnerability Points} + \text{Exposure Points} + \text{Relationship Risk}) \times \text{Criticality Multiplier}$$
3. **What-If Remediation Simulation**:
   - Preview the effect of fixing a vulnerability or restricting access before touching the target. Displays a side-by-side **Before vs. After** comparison with calculated risk reduction percentage.
4. **Independent Demo vs. Live Modes**:
   - `data/demo.db` and `data/live.db` are isolated. Switching modes never overwrites your live testing records.
5. **Multi-Page Executive & Technical PDF Report**:
   - Exports all 20 specification sections (cover page, scope, tools, asset inventory, vulnerabilities, security graph, risk paths, PCAP/log findings, Before vs. After comparison, recommendations, and conclusion).

---

## 🎓 Suggested Viva Demonstration Flow (3–5 Minutes)

1. **Overview & Dashboard**:
   - Show the KPI cards: Discovered Assets (5), Open Services (13), Vulnerabilities (12), High-Risk Assets (1), Overall Risk (45/100).
   - Explain that data is pulled dynamically from the database and not hardcoded.
2. **Asset Inventory & Vulnerabilities**:
   - Open **Assets** and **Vulnerabilities**. Show how findings track an auditable lifecycle: `Open` $\rightarrow$ `Under Review` $\rightarrow$ `Planned` $\rightarrow$ `Fixed` $\rightarrow$ `Retested`.
3. **Security Graph**:
   - Open **Security Graph**. Point out the nodes (`Student PC`, `Faculty Portal`, `Database Server`) and their connection types (`Network Access`, `Database Connection`).
4. **Risk Analysis**:
   - Open **Risk Analysis**. Point to the identified scenario:
     `Student PC ➔ Faculty Portal ➔ Database Server`
   - Read the generated explanation: *"Faculty Portal has SQL Injection and connects to Critical Database Server..."*
5. **Remediation Simulation (The "Wow" Factor)**:
   - Navigate to **Remediation**.
   - Show the **Before Remediation** score (45/100).
   - Click **Simulate Fix** on the Faculty Portal SQL Injection.
   - Show the score immediately drop to 40/100 (-11% reduction) and explain how the risk model updates dynamically.
6. **Report Generation**:
   - Click **Download PDF Report** to show the professional multi-page document generated with charts, topology, and conclusion.
7. **Offline PCAP & Log Analysis**:
   - Drag and drop `samples/sample_capture.pcap` or `samples/sample_auth.log` to demonstrate offline protocol and brute-force analysis.
