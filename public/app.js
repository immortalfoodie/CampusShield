/**
 * CampusShield — Client Application Logic
 * 
 * Clean, modular Single Page Application (SPA) with hash routing and live state management.
 */

// Global State
let state = {
  mode: 'demo',
  nmapAvailable: false,
  nmapPath: null,
  data: { assets: [], services: [], findings: [], relationships: [] },
  targets: [],
  scans: [],
  snapshots: [],
  baseline: { overall: {}, assets: [], paths: [] },
  simulated: null,
  scenario: [],
};

let activePage = 'dashboard';
let scanPollInterval = null;
let cyGraph = null;

// Utility functions
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const escapeHtml = (str) => String(str ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const formatDate = (iso) => iso ? new Date(iso).toLocaleDateString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';

// API Wrapper
async function fetchApi(url, options = {}) {
  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...options.headers,
      },
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `Request failed with status ${res.status}`);
    }
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) return await res.json();
    if (contentType.includes('application/pdf')) return await res.blob();
    return await res.text();
  } catch (err) {
    showToast(err.message, true);
    throw err;
  }
}

// Toast notification
function showToast(message, isError = false) {
  const container = $('#toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast ${isError ? 'error' : ''}`;
  toast.innerHTML = `<span>${isError ? '⚠️' : '✓'}</span> <div>${escapeHtml(message)}</div>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 250);
  }, 4000);
}

// Modal handling
function openModal(title, contentHtml) {
  $('#modalTitle').textContent = title;
  $('#modalBody').innerHTML = contentHtml;
  $('#modalBackdrop').style.display = 'flex';
}

function closeModal() {
  $('#modalBackdrop').style.display = 'none';
  $('#modalBody').innerHTML = '';
}

$('#modalClose')?.addEventListener('click', closeModal);
$('#modalBackdrop')?.addEventListener('click', (e) => {
  if (e.target.id === 'modalBackdrop') closeModal();
});

// Load workspace state from API
async function loadState() {
  try {
    const s = await fetchApi('/api/state');
    state = s;
    updateTopBar();
    renderCurrentPage();
  } catch (err) {
    console.error('Failed to load initial state:', err);
  }
}

// Update Header Badges & Mode Indicator
function updateTopBar() {
  const isDemo = state.mode === 'demo';
  const label = $('#modeLabelText');
  const btn = $('#modeToggleBtn');
  if (label && btn) {
    label.textContent = isDemo ? 'DEMO MODE' : 'LIVE LAB MODE';
    btn.classList.toggle('live', !isDemo);
  }

  const vulnNavCount = $('#vulnNavCount');
  if (vulnNavCount) {
    const activeCount = state.data.findings.filter(f => ['open', 'under_review', 'planned'].includes(f.status)).length;
    vulnNavCount.textContent = activeCount;
    vulnNavCount.className = `badge ${activeCount > 0 ? 'badge-high' : 'badge-low'}`;
  }

  const crumb = $('#topBreadcrumb');
  if (crumb) {
    crumb.innerHTML = `CampusShield / <span>${activePage.charAt(0).toUpperCase() + activePage.slice(1)}</span>`;
  }
}

// Handle Hash Routing
function handleRoute() {
  const hash = window.location.hash.slice(1).toLowerCase() || 'dashboard';
  const validPages = ['dashboard', 'targets', 'scans', 'assets', 'vulnerabilities', 'graph', 'risk', 'packets', 'logs', 'remediation', 'reports', 'settings'];
  activePage = validPages.includes(hash) ? hash : 'dashboard';

  $$('#sidebarNav .nav-item').forEach(item => {
    item.classList.toggle('active', item.dataset.page === activePage);
  });

  updateTopBar();
  renderCurrentPage();
}

window.addEventListener('hashchange', handleRoute);

// --------------------------------------------------------------------------
// PAGE RENDERERS
// --------------------------------------------------------------------------
function renderCurrentPage() {
  const container = $('#pageContent');
  if (!container) return;

  switch (activePage) {
    case 'dashboard': renderDashboard(container); break;
    case 'targets': renderTargets(container); break;
    case 'scans': renderScans(container); break;
    case 'assets': renderAssets(container); break;
    case 'vulnerabilities': renderVulnerabilities(container); break;
    case 'graph': renderGraph(container); break;
    case 'risk': renderRisk(container); break;
    case 'packets': renderPackets(container); break;
    case 'logs': renderLogs(container); break;
    case 'remediation': renderRemediation(container); break;
    case 'reports': renderReports(container); break;
    case 'settings': renderSettings(container); break;
    default: renderDashboard(container);
  }
}

// 1. DASHBOARD
function renderDashboard(c) {
  const o = state.baseline.overall || {};
  const isDemo = state.mode === 'demo';

  c.innerHTML = `
    <div class="page-header">
      <div class="page-title">
        <h1>VAPT Security Assessment Dashboard</h1>
        <p>Holistic posture of the laboratory network connecting open services, findings and risk paths.</p>
      </div>
      <div class="header-actions">
        <button class="btn btn-secondary btn-sm" id="btnRefreshState">↻ Refresh Data</button>
      </div>
    </div>

    <!-- Quick-action workflow strip -->
    <div class="quick-action-strip">
      <span class="workflow-label">VAPT Workflow:</span>
      <a href="#targets" class="btn btn-secondary btn-sm">1. Add Target</a>
      <span class="workflow-arrow">➔</span>
      <a href="#scans" class="btn btn-secondary btn-sm">2. Start Scan</a>
      <span class="workflow-arrow">➔</span>
      <a href="#vulnerabilities" class="btn btn-secondary btn-sm">3. View Findings</a>
      <span class="workflow-arrow">➔</span>
      <a href="#graph" class="btn btn-secondary btn-sm">4. Security Graph</a>
      <span class="workflow-arrow">➔</span>
      <a href="#remediation" class="btn btn-secondary btn-sm">5. Simulate Fix</a>
      <span class="workflow-arrow">➔</span>
      <a href="#reports" class="btn btn-primary btn-sm">6. Generate Report</a>
    </div>

    <!-- Recent Scan Execution Status Banner -->
    ${(() => {
      const latestScan = state.scans?.[0];
      if (latestScan) {
        const durStr = latestScan.duration_ms ? `${(latestScan.duration_ms / 1000).toFixed(1)}s` : '—';
        return `
          <div style="background:rgba(15,23,42,0.7);border:1px solid var(--border-subtle);border-left:4px solid ${latestScan.status === 'completed' ? 'var(--accent-emerald)' : latestScan.status === 'failed' ? 'var(--color-critical)' : 'var(--accent-amber)'};border-radius:var(--radius-sm);padding:10px 16px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;font-size:0.8rem">
            <div>
              <span style="font-weight:700;color:#fff">Latest Assessment:</span>
              <span style="color:var(--text-main);margin-left:6px">Scan #${latestScan.id} on <strong>${escapeHtml(latestScan.target_name)}</strong> (<code>${escapeHtml(latestScan.target_address)}</code>)</span>
              <span style="color:var(--text-muted);margin-left:8px">• Profile: <code>${latestScan.profile || 'quick'}</code> • Finished: ${formatDate(latestScan.finished_at || latestScan.started_at)} (Duration: ${durStr})</span>
            </div>
            <div style="display:flex;gap:8px;align-items:center">
              <span class="badge ${latestScan.status === 'completed' ? 'badge-low' : 'badge-critical'}">${latestScan.status}</span>
              <a href="#scans" class="btn btn-secondary btn-sm" style="padding:3px 8px;font-size:0.72rem">Scan Details</a>
            </div>
          </div>
        `;
      } else {
        return `
          <div style="background:rgba(56,189,248,0.05);border:1px solid rgba(56,189,248,0.2);border-radius:var(--radius-sm);padding:10px 16px;margin-bottom:20px;font-size:0.8rem;color:var(--text-muted)">
            ℹ️ No scans recorded in <strong>${state.mode.toUpperCase()} MODE</strong> yet. Click <a href="#scans" style="color:var(--accent-cyan);font-weight:600">Start Scan</a> to discover lab assets.
          </div>
        `;
      }
    })()}

    <!-- KPI Summary Cards (Clickable navigation) -->
    <div class="kpi-grid">
      <div class="kpi-card kpi-cyan clickable" onclick="window.location.hash='#assets'" title="Click to view Asset Inventory">
        <div class="kpi-header">
          <span class="kpi-label">Discovered Assets</span>
          <span class="kpi-icon">💻</span>
        </div>
        <div class="kpi-value">${o.assets ?? 0}</div>
        <div class="kpi-footer">Systems in active inventory ➔</div>
      </div>

      <div class="kpi-card kpi-emerald clickable" onclick="window.location.hash='#assets'" title="Click to view Open Services">
        <div class="kpi-header">
          <span class="kpi-label">Open Services</span>
          <span class="kpi-icon">⚡</span>
        </div>
        <div class="kpi-value">${o.openServices ?? 0}</div>
        <div class="kpi-footer">Reachable ports discovered ➔</div>
      </div>

      <div class="kpi-card kpi-rose clickable" onclick="window.location.hash='#vulnerabilities'" title="Click to view Vulnerability Findings">
        <div class="kpi-header">
          <span class="kpi-label">Vulnerabilities</span>
          <span class="kpi-icon">🛡️</span>
        </div>
        <div class="kpi-value">${o.vulnerabilities ?? 0}</div>
        <div class="kpi-footer">Active security findings ➔</div>
      </div>

      <div class="kpi-card kpi-amber clickable" onclick="window.location.hash='#risk'" title="Click to view High-Risk Assets in Risk Analysis">
        <div class="kpi-header">
          <span class="kpi-label">High-Risk Assets</span>
          <span class="kpi-icon">⚠️</span>
        </div>
        <div class="kpi-value">${o.highRiskAssets ?? 0}</div>
        <div class="kpi-footer">Assets scored High or Critical ➔</div>
      </div>

      <div class="kpi-card kpi-purple clickable" onclick="window.location.hash='#risk'" title="Click to inspect Risk Scoring Breakdown">
        <div class="kpi-header">
          <span class="kpi-label">Overall Risk Score</span>
          <span class="kpi-icon">🎯</span>
        </div>
        <div class="kpi-value">${o.score ?? 0}<span style="font-size:1.1rem;color:var(--text-muted)">/100</span></div>
        <div class="kpi-footer">Risk Level: <strong style="color:var(--accent-cyan)">${(o.level || 'LOW').toUpperCase()}</strong> ➔</div>
      </div>
    </div>

    <!-- Charts and Tables Grid -->
    <div class="grid-2">
      <!-- Vulnerabilities by Severity Panel -->
      <div class="panel">
        <div class="panel-header">
          <div>
            <h3 class="panel-title">Vulnerabilities by Severity</h3>
            <p class="panel-subtitle">Distribution of active security observations</p>
          </div>
          <a href="#vulnerabilities" class="btn btn-secondary btn-sm">Inspect Findings</a>
        </div>
        <div style="height: 220px; position: relative;">
          <canvas id="chartVulnSev"></canvas>
        </div>
      </div>

      <!-- Top Vulnerable Assets Panel -->
      <div class="panel">
        <div class="panel-header">
          <div>
            <h3 class="panel-title">Most Vulnerable Assets</h3>
            <p class="panel-subtitle">Highest calculated risk scores based on findings & relationships</p>
          </div>
          <a href="#risk" class="btn btn-secondary btn-sm">Risk Analysis</a>
        </div>
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Asset</th>
                <th>Criticality</th>
                <th>Findings</th>
                <th>Risk Score</th>
              </tr>
            </thead>
            <tbody>
              ${(state.baseline.assets || [])
                .slice()
                .sort((a, b) => b.score - a.score)
                .slice(0, 5)
                .map(a => `
                  <tr>
                    <td><strong>${escapeHtml(a.name)}</strong><br><small style="color:var(--text-muted)">${escapeHtml(a.ip)}</small></td>
                    <td><span class="badge badge-${a.criticality}">${a.criticality}</span></td>
                    <td>${a.activeFindings} active</td>
                    <td><span class="badge badge-${a.level}">${a.score}/100</span></td>
                  </tr>
                `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Recent Scans and Services Grid -->
    <div class="grid-2">
      <div class="panel">
        <div class="panel-header">
          <div>
            <h3 class="panel-title">Recent Scans</h3>
            <p class="panel-subtitle">Assessment execution history</p>
          </div>
          <a href="#scans" class="btn btn-secondary btn-sm">View Scans</a>
        </div>
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Status</th>
                <th>Date</th>
                <th>Hosts / Ports</th>
              </tr>
            </thead>
            <tbody>
              ${(state.scans || []).slice(0, 4).map(s => `
                <tr>
                  <td><strong>${escapeHtml(s.target_name || 'Scan')}</strong><br><small style="color:var(--text-muted)">${escapeHtml(s.target_address || '')}</small></td>
                  <td><span class="badge ${s.status === 'completed' ? 'badge-low' : s.status === 'failed' ? 'badge-critical' : 'badge-medium'}">${s.status}</span></td>
                  <td><small>${formatDate(s.started_at)}</small></td>
                  <td>${s.hosts_up || 0} host(s) / ${s.ports_found || 0} port(s)</td>
                </tr>
              `).join('') || '<tr><td colspan="4" style="text-align:center;color:var(--text-dim)">No scans recorded yet.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div>
            <h3 class="panel-title">Discovered Services</h3>
            <p class="panel-subtitle">Open ports and application services across lab assets</p>
          </div>
          <a href="#assets" class="btn btn-secondary btn-sm">Asset Inventory</a>
        </div>
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Port / Protocol</th>
                <th>Service Name</th>
                <th>Assets Affected</th>
              </tr>
            </thead>
            <tbody>
              ${getServiceAggregates().slice(0, 5).map(svc => `
                <tr>
                  <td><code>${svc.port}/${svc.proto}</code></td>
                  <td><strong>${escapeHtml(svc.name)}</strong></td>
                  <td>${svc.count} system(s)</td>
                </tr>
              `).join('') || '<tr><td colspan="3" style="text-align:center;color:var(--text-dim)">No open services detected yet.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  $('#btnRefreshState')?.addEventListener('click', loadState);

  // Initialize Chart.js if available
  if (window.Chart) {
    const ctx = document.getElementById('chartVulnSev');
    if (ctx) {
      const sev = o.severity || {};
      new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
          datasets: [{
            data: [sev.critical || 0, sev.high || 0, sev.medium || 0, sev.low || 0, sev.info || 0],
            backgroundColor: ['#ef4444', '#f97316', '#eab308', '#10b981', '#0284c7'],
            borderColor: '#0d1322',
            borderWidth: 2,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 11 } } }
          }
        }
      });
    }
  }
}

function getServiceAggregates() {
  const map = new Map();
  for (const s of state.data.services) {
    const key = `${s.port}:${s.protocol}`;
    if (!map.has(key)) {
      map.set(key, { port: s.port, proto: s.protocol, name: s.service || s.product || 'unknown', count: 0 });
    }
    map.get(key).count++;
  }
  return [...map.values()].sort((a, b) => b.count - a.count);
}

// 2. TARGETS
function renderTargets(c) {
  c.innerHTML = `
    <div class="page-header">
      <div class="page-title">
        <h1>Authorized Target Management</h1>
        <p>Register authorized systems and subnets. Scope guards enforce private RFC 1918 / loopback ranges only.</p>
      </div>
      <div class="header-actions">
        <button class="btn btn-primary" id="btnAddTarget">＋ Add Authorized Target</button>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">Registered Targets</h3>
          <p class="panel-subtitle">Total: ${state.targets.length} authorized lab target(s)</p>
        </div>
      </div>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Target Name</th>
              <th>IP / Hostname / CIDR</th>
              <th>Environment</th>
              <th>Authorization Note</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${state.targets.map(t => `
              <tr>
                <td><strong>${escapeHtml(t.name)}</strong><br><small style="color:var(--text-muted)">${escapeHtml(t.description || 'Lab system')}</small></td>
                <td><code>${escapeHtml(t.address)}</code></td>
                <td><span class="badge badge-info">${escapeHtml(t.environment || 'VAPT Lab')}</span></td>
                <td><small style="color:var(--text-muted)">${escapeHtml(t.authorization_note || 'Approved testing')}</small></td>
                <td><span class="badge ${t.status === 'scanned' ? 'badge-low' : 'badge-medium'}">${t.status}</span></td>
                <td>
                  <div style="display:flex;gap:6px">
                    <button class="btn btn-primary btn-sm btn-scan-target" data-id="${t.id}">⚡ Scan</button>
                    <button class="btn btn-danger btn-sm btn-delete-target" data-id="${t.id}">Delete</button>
                  </div>
                </td>
              </tr>
            `).join('') || '<tr><td colspan="6" style="text-align:center;color:var(--text-dim)">No targets registered. Click "Add Authorized Target" to begin.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;

  $('#btnAddTarget')?.addEventListener('click', showAddTargetModal);
  $$('.btn-scan-target').forEach(b => b.addEventListener('click', () => showScanModal(b.dataset.id)));
  $$('.btn-delete-target').forEach(b => b.addEventListener('click', () => deleteTarget(b.dataset.id)));
}

function showAddTargetModal() {
  openModal('Add Authorized Lab Target', `
    <form id="formAddTarget">
      <div class="form-group">
        <label class="form-label">Target Name *</label>
        <input class="form-control" name="name" placeholder="e.g. DVWA Server or Course Lab Subnet" required>
      </div>
      <div class="form-group">
        <label class="form-label">IP Address, Hostname, or CIDR *</label>
        <input class="form-control" name="address" placeholder="e.g. 192.168.56.101 or 192.168.56.0/24 or localhost" required>
        <small style="color:var(--text-dim);display:block;margin-top:4px">Only private (RFC 1918) IPv4 or loopback addresses are allowed.</small>
      </div>
      <div class="form-group">
        <label class="form-label">Environment</label>
        <input class="form-control" name="environment" value="VAPT Lab">
      </div>
      <div class="form-group">
        <label class="form-label">Description</label>
        <input class="form-control" name="description" placeholder="Purpose or lab role">
      </div>
      <div class="form-group">
        <label class="form-label">Authorization Note *</label>
        <textarea class="form-control" name="authorization_note" placeholder="e.g. Authorized by Prof. Sharma for Network Security Lab Course 402." required></textarea>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:20px">
        <button type="button" class="btn btn-secondary" onclick="document.getElementById('modalClose').click()">Cancel</button>
        <button type="submit" class="btn btn-primary">Save Target</button>
      </div>
    </form>
  `);

  $('#formAddTarget')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const body = Object.fromEntries(fd.entries());
    try {
      await fetchApi('/api/targets', { method: 'POST', body: JSON.stringify(body) });
      showToast('Target added successfully.');
      closeModal();
      await loadState();
    } catch (err) {}
  });
}

async function deleteTarget(id) {
  if (!confirm('Are you sure you want to delete this target?')) return;
  try {
    await fetchApi(`/api/targets/${id}`, { method: 'DELETE' });
    showToast('Target deleted.');
    await loadState();
  } catch (err) {}
}

// 3. NETWORK SCANS
function renderScans(c) {
  c.innerHTML = `
    <div class="page-header">
      <div class="page-title">
        <h1>Network Scans & Service Discovery</h1>
        <p>Orchestrate Nmap scans or import Nmap XML reports to detect open ports, protocols and services.</p>
      </div>
      <div class="header-actions">
        <button class="btn btn-secondary" id="btnImportXml">📥 Import Nmap XML</button>
        <button class="btn btn-primary" id="btnStartScan">⚡ Start Scan</button>
      </div>
    </div>

    <!-- Active Scan Card (if running) -->
    <div id="activeScanContainer"></div>

    <div class="panel">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">Scan History</h3>
          <p class="panel-subtitle">Chronological record of all assessments with duration and exit status</p>
        </div>
      </div>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Scan ID</th>
              <th>Target</th>
              <th>Profile</th>
              <th>Status</th>
              <th>Duration</th>
              <th>Hosts Up</th>
              <th>Ports Found</th>
              <th>Risk Score</th>
              <th>Finished</th>
              <th>Details & Log</th>
            </tr>
          </thead>
          <tbody>
            ${state.scans.map(s => {
              const dur = s.duration_ms ? `${(s.duration_ms / 1000).toFixed(1)}s` : '—';
              const pBadge = s.profile === 'vuln' 
                ? '<span class="badge badge-high" title="Vulnerability script scan">Vuln Script</span>'
                : s.profile === 'standard'
                  ? '<span class="badge badge-low" title="Top 1000 ports + Safe NSE">Standard (1000)</span>'
                  : '<span class="badge badge-info" title="Top 100 TCP ports, fast service check">Quick (100)</span>';
              const stClass = s.status === 'completed' ? 'badge-low' : s.status === 'failed' ? 'badge-critical' : s.status === 'cancelled' ? 'badge-medium' : 'badge-info';
              return `
                <tr>
                  <td>#${s.id}</td>
                  <td><strong>${escapeHtml(s.target_name)}</strong><br><small style="color:var(--text-muted)">${escapeHtml(s.target_address)}</small></td>
                  <td>${pBadge}</td>
                  <td><span class="badge ${stClass}">${s.status}</span></td>
                  <td><small>${dur}</small></td>
                  <td>${s.hosts_up || 0}</td>
                  <td>${s.ports_found || 0}</td>
                  <td><strong>${s.risk_score != null ? `${s.risk_score}/100` : '—'}</strong></td>
                  <td><small>${formatDate(s.finished_at || s.started_at)}</small></td>
                  <td><button class="btn btn-secondary btn-sm btn-view-scan-log" data-id="${s.id}">Inspect</button></td>
                </tr>
              `;
            }).join('') || '<tr><td colspan="10" style="text-align:center;color:var(--text-dim)">No scans performed yet.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;

  $('#btnStartScan')?.addEventListener('click', () => showScanModal());
  $('#btnImportXml')?.addEventListener('click', showImportNmapModal);
  $$('.btn-view-scan-log').forEach(b => b.addEventListener('click', () => showScanLogModal(b.dataset.id)));
}

function showScanModal(defaultTargetId = '') {
  if (!state.targets.length) {
    showToast('Please add at least one authorized target first.', true);
    window.location.hash = '#targets';
    return;
  }

  openModal('Execute Network Scan', `
    <form id="formExecuteScan">
      <div class="form-group">
        <label class="form-label">Select Authorized Target</label>
        <select class="form-control" name="targetId">
          ${state.targets.map(t => `<option value="${t.id}" ${t.id == defaultTargetId ? 'selected' : ''}>${escapeHtml(t.name)} (${escapeHtml(t.address)})</option>`).join('')}
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Scan Profile</label>
        <select class="form-control" name="profile">
          <option value="quick" selected>Quick Discovery (Top 100 TCP ports, non-disruptive fast service check)</option>
          <option value="standard">Standard Assessment (Top 1000 ports + Safe NSE scripts + Web baseline)</option>
          <option value="vuln">Vulnerability Assessment (Standard + Nmap vuln scripts)</option>
        </select>
      </div>
      <div class="form-group">
        <label style="display:flex;align-items:center;gap:8px;font-size:0.85rem">
          <input type="checkbox" name="osDetect" value="1">
          <span>Enable OS Fingerprinting (-O)</span>
        </label>
      </div>
      <div style="background:rgba(255,255,255,0.03);padding:12px;border-radius:6px;margin:16px 0;font-size:0.75rem;color:var(--text-muted)">
        🔒 <strong>Safety Note:</strong> Scans run non-disruptive TCP connect probes. In Demo Mode, scans run in simulated mode without sending live packets.
      </div>
      <div style="display:flex;justify-content:flex-end;gap:10px">
        <button type="button" class="btn btn-secondary" onclick="document.getElementById('modalClose').click()">Cancel</button>
        <button type="submit" class="btn btn-primary">Start Scan</button>
      </div>
    </form>
  `);

  $('#formExecuteScan')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const body = {
      targetId: Number(fd.get('targetId')),
      profile: fd.get('profile') || 'quick',
      osDetect: fd.get('osDetect') === '1'
    };
    try {
      closeModal();
      const res = await fetchApi('/api/scans', { method: 'POST', body: JSON.stringify(body) });
      showToast('Scan initiated.');
      pollScanProgress(res.scanId);
    } catch (err) {}
  });
}

function pollScanProgress(scanId) {
  if (scanPollInterval) clearInterval(scanPollInterval);

  const container = $('#activeScanContainer');
  if (container) {
    container.innerHTML = `
      <div class="panel" style="border-color:var(--accent-cyan);background:rgba(56,189,248,0.04)">
        <div class="panel-header">
          <div>
            <h3 class="panel-title" id="scanLiveTitle">Scan #${scanId} In Progress...</h3>
            <p class="panel-subtitle" id="scanLivePhase">Initializing...</p>
          </div>
          <button class="btn btn-danger btn-sm" id="btnCancelScan">Cancel Scan</button>
        </div>
        <div style="background:var(--bg-card);height:10px;border-radius:5px;overflow:hidden;margin-bottom:12px">
          <div id="scanProgressBar" style="width:0%;height:100%;background:linear-gradient(90deg,var(--accent-cyan),var(--accent-indigo));transition:width 0.3s ease"></div>
        </div>
        <pre id="scanLiveLog" style="background:#090d16;padding:12px;border-radius:6px;max-height:160px;overflow-y:auto;font-family:var(--font-mono);font-size:0.75rem;color:#7dd3fc"></pre>
      </div>
    `;

    $('#btnCancelScan')?.addEventListener('click', async () => {
      await fetchApi(`/api/scans/${scanId}/cancel`, { method: 'POST' });
      showToast('Cancel requested.');
    });
  }

  scanPollInterval = setInterval(async () => {
    try {
      const scan = await fetchApi(`/api/scans/${scanId}`);
      const bar = $('#scanProgressBar');
      const phase = $('#scanLivePhase');
      const logBox = $('#scanLiveLog');

      if (bar) bar.style.width = `${scan.progress || 0}%`;
      if (phase) phase.textContent = `Phase: ${scan.phase || 'Scanning'} (${scan.progress || 0}%)`;
      if (logBox && scan.log) {
        logBox.textContent = scan.log;
        logBox.scrollTop = logBox.scrollHeight;
      }

      if (['completed', 'failed', 'cancelled'].includes(scan.status)) {
        clearInterval(scanPollInterval);
        showToast(scan.status === 'completed' ? `Scan #${scanId} completed!` : `Scan #${scanId} ${scan.status}: ${scan.error || 'Finished'}`, scan.status === 'failed');
        await loadState();
      }
    } catch (err) {
      clearInterval(scanPollInterval);
    }
  }, 1200);
}

function showScanLogModal(scanId) {
  const scan = state.scans.find(s => s.id == scanId);
  if (!scan) return;

  const durStr = scan.duration_ms ? `${(scan.duration_ms / 1000).toFixed(2)}s` : '—';
  const exitStr = scan.exit_code != null ? `Exit Code: ${scan.exit_code}` : 'Exit Code: 0 (Normal)';

  openModal(`Scan #${scan.id} Diagnostics & Log`, `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px;font-size:0.8rem">
      <div><strong>Target:</strong> ${escapeHtml(scan.target_name)} (<code>${escapeHtml(scan.target_address)}</code>)</div>
      <div><strong>Profile:</strong> <span class="badge badge-info">${escapeHtml(scan.profile || 'quick')}</span></div>
      <div><strong>Status:</strong> <span class="badge ${scan.status === 'completed' ? 'badge-low' : 'badge-critical'}">${scan.status}</span> (${exitStr})</div>
      <div><strong>Duration:</strong> ${durStr}</div>
      <div><strong>Started:</strong> ${formatDate(scan.started_at)}</div>
      <div><strong>Finished:</strong> ${formatDate(scan.finished_at)}</div>
      <div><strong>Discovered:</strong> ${scan.hosts_up || 0} host(s) up, ${scan.ports_found || 0} open port(s)</div>
      <div><strong>Calculated Risk:</strong> ${scan.risk_score != null ? `${scan.risk_score}/100` : '—'}</div>
    </div>
    <div style="margin-bottom:10px">
      <strong>Executed Command:</strong><br>
      <code style="background:#090d16;padding:4px 8px;border-radius:4px;display:block;margin-top:4px;color:#38bdf8">${escapeHtml(scan.command || 'Nmap scan')}</code>
    </div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
      <strong style="font-size:0.8rem">Console Output / Execution Log:</strong>
      <button class="btn btn-secondary btn-sm" id="btnCopyScanLog" style="padding:2px 8px;font-size:0.72rem">📋 Copy Log</button>
    </div>
    <pre id="preScanLogText" style="background:#090d16;padding:14px;border-radius:6px;max-height:300px;overflow-y:auto;font-family:var(--font-mono);font-size:0.75rem;color:#a5f3fc;white-space:pre-wrap">${escapeHtml(scan.log || 'No console log recorded.')}</pre>
  `);

  $('#btnCopyScanLog')?.addEventListener('click', () => {
    const text = $('#preScanLogText')?.textContent || '';
    navigator.clipboard?.writeText(text).then(() => showToast('Log copied to clipboard!'));
  });
}

function showImportNmapModal() {
  openModal('Import Nmap XML Output', `
    <form id="formImportNmap">
      <div class="form-group">
        <label class="form-label">Associate with Authorized Target</label>
        <select class="form-control" name="targetId">
          ${state.targets.map(t => `<option value="${t.id}">${escapeHtml(t.name)} (${escapeHtml(t.address)})</option>`).join('')}
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Paste Nmap XML Output Content</label>
        <textarea class="form-control" name="xml" style="min-height:180px;font-family:var(--font-mono);font-size:0.75rem" placeholder="<nmaprun ...> ... </nmaprun>" required></textarea>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:10px">
        <button type="button" class="btn btn-secondary" onclick="document.getElementById('modalClose').click()">Cancel</button>
        <button type="submit" class="btn btn-primary">Import XML</button>
      </div>
    </form>
  `);

  $('#formImportNmap')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await fetchApi('/api/scans/import-nmap', {
        method: 'POST',
        body: JSON.stringify({ targetId: Number(fd.get('targetId')), xml: fd.get('xml') })
      });
      showToast('Nmap XML imported successfully.');
      closeModal();
      await loadState();
    } catch (err) {}
  });
}

// 4. ASSETS
function renderAssets(c) {
  const assets = state.baseline.assets || [];

  c.innerHTML = `
    <div class="page-header">
      <div class="page-title">
        <h1>Discovered Asset Inventory</h1>
        <p>Central repository of systems discovered via network scans with criticality ratings and open ports.</p>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">Asset Systems</h3>
          <p class="panel-subtitle">Total: ${assets.length} inventoried assets</p>
        </div>
      </div>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Asset Name</th>
              <th>IP / Hostname</th>
              <th>Criticality</th>
              <th>Role</th>
              <th>Services</th>
              <th>Findings</th>
              <th>Risk Score</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${assets.map(a => {
              const svcs = state.data.services.filter(s => s.asset_id === a.id);
              return `
                <tr>
                  <td><strong>${escapeHtml(a.name)}</strong></td>
                  <td><code>${escapeHtml(a.ip)}</code></td>
                  <td><span class="badge badge-${a.criticality}">${a.criticality}</span></td>
                  <td>${escapeHtml(a.type || 'server')}</td>
                  <td>${svcs.length} open port(s)</td>
                  <td>${a.activeFindings} active</td>
                  <td><span class="badge badge-${a.level}">${a.score}/100</span></td>
                  <td>
                    <button class="btn btn-secondary btn-sm btn-asset-details" data-id="${a.id}">Details</button>
                  </td>
                </tr>
              `;
            }).join('') || '<tr><td colspan="8" style="text-align:center;color:var(--text-dim)">No assets found. Run a network scan to discover systems.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;

  $$('.btn-asset-details').forEach(b => b.addEventListener('click', () => showAssetDetailsModal(b.dataset.id)));
}

async function showAssetDetailsModal(assetId) {
  try {
    const a = await fetchApi(`/api/assets/${assetId}`);
    const scoreObj = state.baseline.assets.find(x => x.id == assetId) || {};

    openModal(`Asset: ${escapeHtml(a.name)}`, `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
        <div><strong>IP Address:</strong> <code>${escapeHtml(a.ip)}</code></div>
        <div><strong>Operating System:</strong> ${escapeHtml(a.os || 'Unknown')}</div>
        <div><strong>Criticality:</strong> <span class="badge badge-${a.criticality}">${a.criticality}</span></div>
        <div><strong>Calculated Risk Score:</strong> <span class="badge badge-${scoreObj.level || 'low'}">${scoreObj.score || 0}/100</span></div>
      </div>

      <div style="margin-bottom:16px">
        <label class="form-label">Adjust Criticality Level</label>
        <div style="display:flex;gap:8px">
          <select class="form-control" id="selectAssetCrit">
            <option value="low" ${a.criticality === 'low' ? 'selected' : ''}>Low Criticality (x0.8 multiplier)</option>
            <option value="medium" ${a.criticality === 'medium' ? 'selected' : ''}>Medium Criticality (x1.0 multiplier)</option>
            <option value="high" ${a.criticality === 'high' ? 'selected' : ''}>High Criticality (x1.15 multiplier)</option>
            <option value="critical" ${a.criticality === 'critical' ? 'selected' : ''}>Critical Asset (x1.3 multiplier)</option>
          </select>
          <button class="btn btn-primary btn-sm" id="btnUpdateAssetCrit">Update</button>
        </div>
      </div>

      <h4 style="font-size:0.9rem;margin-bottom:8px;color:#fff">Open Ports & Services (${a.services?.length || 0})</h4>
      <div class="table-responsive" style="margin-bottom:16px">
        <table>
          <thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr></thead>
          <tbody>
            ${(a.services || []).map(s => `<tr><td><code>${s.port}</code></td><td>${s.protocol}</td><td>${escapeHtml(s.service)}</td><td>${escapeHtml(s.product || '')} ${escapeHtml(s.version || '')}</td></tr>`).join('') || '<tr><td colspan="4">No services recorded.</td></tr>'}
          </tbody>
        </table>
      </div>

      <h4 style="font-size:0.9rem;margin-bottom:8px;color:#fff">Vulnerabilities (${a.findings?.length || 0})</h4>
      <div class="table-responsive">
        <table>
          <thead><tr><th>Severity</th><th>Title</th><th>Status</th><th>Source</th></tr></thead>
          <tbody>
            ${(a.findings || []).map(f => `<tr><td><span class="badge badge-${f.severity}">${f.severity}</span></td><td><strong>${escapeHtml(f.title)}</strong></td><td><span class="status-badge status-${f.status}">${f.status}</span></td><td><small>${escapeHtml(f.source)}</small></td></tr>`).join('') || '<tr><td colspan="4">No vulnerabilities recorded.</td></tr>'}
          </tbody>
        </table>
      </div>
    `);

    $('#btnUpdateAssetCrit')?.addEventListener('click', async () => {
      const crit = $('#selectAssetCrit').value;
      await fetchApi(`/api/assets/${assetId}`, { method: 'PATCH', body: JSON.stringify({ criticality: crit }) });
      showToast('Asset criticality updated. Risk scores recalculated.');
      closeModal();
      await loadState();
    });
  } catch (err) {}
}

// 5. VULNERABILITIES
function renderVulnerabilities(c) {
  const findings = state.data.findings || [];

  c.innerHTML = `
    <div class="page-header">
      <div class="page-title">
        <h1>Vulnerability & Exposure Findings</h1>
        <p>Observed security issues across assets. Differentiates heuristic exposures from confirmed vulnerabilities.</p>
      </div>
      <div class="header-actions">
        <button class="btn btn-secondary" id="btnImportZap">📥 Import OWASP ZAP</button>
        <button class="btn btn-primary" id="btnAddFinding">＋ Add Finding</button>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">Findings Registry</h3>
          <p class="panel-subtitle">Total: ${findings.length} security observation(s) cataloged</p>
        </div>
      </div>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Classification & Confidence</th>
              <th>Finding Title & Port</th>
              <th>Affected Asset</th>
              <th>Detection Source</th>
              <th>CVE / CWE</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${findings.map(f => {
              const a = state.data.assets.find(x => x.id === f.asset_id);
              const fType = f.finding_type || 'exposure';
              const fConf = f.confidence || 'heuristic';
              const typeBadge = fType === 'vulnerability'
                ? '<span class="badge badge-vuln">Vulnerability</span>'
                : fType === 'hardening'
                  ? '<span class="badge badge-hardening">Hardening</span>'
                  : '<span class="badge badge-exposure">Exposure</span>';
              const confBadge = fConf === 'confirmed'
                ? '<span class="badge badge-confirmed" title="Verified via probe response">Confirmed</span>'
                : '<span class="badge badge-heuristic" title="Rule-based heuristic; not proof of remote exploitability">Heuristic</span>';

              return `
                <tr>
                  <td><span class="badge badge-${f.severity}">${f.severity}</span></td>
                  <td>
                    ${typeBadge}<br>
                    <small style="margin-top:3px;display:inline-block">${confBadge}</small>
                  </td>
                  <td>
                    <strong>${escapeHtml(f.title)}</strong><br>
                    <small style="color:var(--text-muted)">Port: ${f.port || 'N/A'}</small>
                  </td>
                  <td>${a ? escapeHtml(a.name) : 'Unknown'}<br><small style="color:var(--text-muted)">${a ? escapeHtml(a.ip) : ''}</small></td>
                  <td><small>${escapeHtml(f.source)}</small></td>
                  <td>
                    ${f.cve ? `<span class="badge badge-info">${escapeHtml(f.cve)}</span>` : '<span style="color:var(--text-dim);font-size:0.75rem">No CVE mapping (N/A)</span>'}
                    ${f.cwe ? `<br><small style="color:var(--text-muted)">${escapeHtml(f.cwe)}</small>` : ''}
                  </td>
                  <td>
                    <select class="form-control select-finding-status" data-id="${f.id}" style="padding:4px 8px;font-size:0.75rem">
                      <option value="open" ${f.status === 'open' ? 'selected' : ''}>Open</option>
                      <option value="under_review" ${f.status === 'under_review' ? 'selected' : ''}>Under Review</option>
                      <option value="planned" ${f.status === 'planned' ? 'selected' : ''}>Remediation Planned</option>
                      <option value="fixed" ${f.status === 'fixed' ? 'selected' : ''}>Fixed</option>
                      <option value="retested" ${f.status === 'retested' ? 'selected' : ''}>Retested</option>
                    </select>
                  </td>
                  <td>
                    <div style="display:flex;gap:4px">
                      <button class="btn btn-secondary btn-sm btn-finding-details" data-id="${f.id}" title="View Triggering Evidence & Rationale">Details</button>
                      <button class="btn btn-secondary btn-sm btn-retest-finding" data-id="${f.id}" title="Run targeted verification scan">Retest</button>
                    </div>
                  </td>
                </tr>
              `;
            }).join('') || '<tr><td colspan="8" style="text-align:center;color:var(--text-dim)">No vulnerabilities identified yet.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;

  $('#btnAddFinding')?.addEventListener('click', showAddFindingModal);
  $('#btnImportZap')?.addEventListener('click', showImportZapModal);
  $$('.btn-finding-details').forEach(b => b.addEventListener('click', () => showFindingDetailsModal(b.dataset.id)));
  $$('.select-finding-status').forEach(sel => {
    sel.addEventListener('change', async (e) => {
      const id = e.target.dataset.id;
      const status = e.target.value;
      try {
        await fetchApi(`/api/findings/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status }) });
        showToast(`Finding status changed to ${status}.`);
        await loadState();
      } catch (err) {}
    });
  });
  $$('.btn-retest-finding').forEach(b => {
    b.addEventListener('click', async () => {
      b.disabled = true;
      b.textContent = 'Testing...';
      try {
        const res = await fetchApi(`/api/findings/${b.dataset.id}/retest`, { method: 'POST' });
        showToast(res.message, res.result !== 'passed');
        await loadState();
      } catch (err) {
        b.disabled = false;
        b.textContent = 'Retest';
      }
    });
  });
}

function showFindingDetailsModal(findingId) {
  const f = state.data.findings.find(x => x.id == findingId);
  if (!f) return;
  const a = state.data.assets.find(x => x.id === f.asset_id);

  openModal(`Finding: ${escapeHtml(f.title)}`, `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px;font-size:0.82rem">
      <div><strong>Severity:</strong> <span class="badge badge-${f.severity}">${f.severity.toUpperCase()}</span></div>
      <div><strong>Observation Type:</strong> <span class="badge badge-info">${escapeHtml((f.finding_type || 'exposure').toUpperCase())}</span></div>
      <div><strong>Confidence:</strong> <span class="badge ${f.confidence === 'confirmed' ? 'badge-low' : 'badge-medium'}">${escapeHtml((f.confidence || 'heuristic').toUpperCase())}</span></div>
      <div><strong>Affected Asset:</strong> ${a ? escapeHtml(a.name) : 'Asset'} (<code>${a ? escapeHtml(a.ip) : ''}</code>)</div>
      <div><strong>Port / Service:</strong> <code>${f.port || 'N/A'}</code></div>
      <div><strong>Detection Source:</strong> ${escapeHtml(f.source)}</div>
      <div><strong>CVE Identifier:</strong> ${f.cve ? `<span class="badge badge-info">${escapeHtml(f.cve)}</span>` : '<span style="color:var(--text-dim)">No CVE mapping (Not applicable)</span>'}</div>
      <div><strong>CWE:</strong> ${escapeHtml(f.cwe || 'None')}</div>
    </div>

    <div style="margin-bottom:12px">
      <strong style="color:#fff;font-size:0.85rem">Triggering Evidence / Observation:</strong>
      <pre style="background:#090d16;padding:10px;border-radius:4px;font-family:var(--font-mono);font-size:0.75rem;color:#7dd3fc;margin-top:4px;white-space:pre-wrap">${escapeHtml(f.evidence || f.description || 'Observed port listening during scan.')}</pre>
    </div>

    ${f.severity_rationale ? `
      <div style="background:rgba(245,158,11,0.06);border-left:3px solid var(--accent-amber);padding:10px 14px;border-radius:4px;margin-bottom:12px;font-size:0.8rem">
        <strong style="color:var(--accent-amber)">Severity Rationale:</strong> ${escapeHtml(f.severity_rationale)}
      </div>
    ` : ''}

    ${f.limitations ? `
      <div style="background:rgba(56,189,248,0.05);border-left:3px solid var(--accent-cyan);padding:10px 14px;border-radius:4px;margin-bottom:12px;font-size:0.8rem">
        <strong style="color:var(--accent-cyan)">Limitations & Scope Caveats:</strong> ${escapeHtml(f.limitations)}
      </div>
    ` : ''}

    <div style="margin-top:14px">
      <strong style="color:#fff;font-size:0.85rem">Practical Recommendation & Verification:</strong>
      <p style="font-size:0.82rem;color:var(--text-main);margin-top:4px;line-height:1.5">${escapeHtml(f.recommendation || 'Harden configuration or block port at firewall.')}</p>
    </div>
  `);
}

function showAddFindingModal() {
  if (!state.data.assets.length) {
    showToast('Add an asset first.', true);
    return;
  }

  openModal('Record Security Finding', `
    <form id="formAddFinding">
      <div class="form-group">
        <label class="form-label">Affected Asset *</label>
        <select class="form-control" name="asset_id">
          ${state.data.assets.map(a => `<option value="${a.id}">${escapeHtml(a.name)} (${escapeHtml(a.ip)})</option>`).join('')}
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Finding Title *</label>
        <input class="form-control" name="title" placeholder="e.g. SQL Injection in Search Endpoint" required>
      </div>
      <div class="form-group">
        <label class="form-label">Severity *</label>
        <select class="form-control" name="severity">
          <option value="critical">Critical</option>
          <option value="high" selected>High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Target Port (optional)</label>
        <input class="form-control" name="port" type="number" placeholder="e.g. 80 or 443">
      </div>
      <div class="form-group">
        <label class="form-label">CVE Identifier (only if verified, else leave blank)</label>
        <input class="form-control" name="cve" placeholder="e.g. CVE-2023-38606">
      </div>
      <div class="form-group">
        <label class="form-label">Description</label>
        <textarea class="form-control" name="description"></textarea>
      </div>
      <div class="form-group">
        <label class="form-label">Remediation Recommendation</label>
        <textarea class="form-control" name="recommendation"></textarea>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:10px">
        <button type="button" class="btn btn-secondary" onclick="document.getElementById('modalClose').click()">Cancel</button>
        <button type="submit" class="btn btn-primary">Save Finding</button>
      </div>
    </form>
  `);

  $('#formAddFinding')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const body = Object.fromEntries(fd.entries());
    try {
      await fetchApi('/api/findings', { method: 'POST', body: JSON.stringify(body) });
      showToast('Finding added.');
      closeModal();
      await loadState();
    } catch (err) {}
  });
}

function showImportZapModal() {
  openModal('Import OWASP ZAP Findings (JSON)', `
    <form id="formImportZap">
      <div class="form-group">
        <label class="form-label">Paste OWASP ZAP JSON Report</label>
        <textarea class="form-control" name="report" style="min-height:200px;font-family:var(--font-mono);font-size:0.75rem" placeholder='{ "@generated": "...", "site": [ ... ] }' required></textarea>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:10px">
        <button type="button" class="btn btn-secondary" onclick="document.getElementById('modalClose').click()">Cancel</button>
        <button type="submit" class="btn btn-primary">Import ZAP Alerts</button>
      </div>
    </form>
  `);

  $('#formImportZap')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const report = JSON.parse(new FormData(e.target).get('report'));
      const res = await fetchApi('/api/scans/import-zap', { method: 'POST', body: JSON.stringify({ report }) });
      showToast(`ZAP Import complete: ${res.created} new findings.`);
      closeModal();
      await loadState();
    } catch (err) {
      showToast('Invalid JSON format for ZAP report.', true);
    }
  });
}

// 6. SECURITY GRAPH
function renderGraph(c) {
  const assetCount = state.data.assets.length;
  const relCount = state.data.relationships.length;

  c.innerHTML = `
    <div class="page-header">
      <div class="page-title">
        <h1>Security Graph & Topology Mapping</h1>
        <p>Interactive security graph connecting discovered systems and modelled relationships to expose risk scenarios.</p>
      </div>
      <div class="header-actions">
        <button class="btn btn-primary" id="btnAddRelationship">＋ Add Relationship</button>
      </div>
    </div>

    <!-- Empty/Single Asset Guidance Banners -->
    ${assetCount === 1 ? `
      <div style="background:rgba(56,189,248,0.08);border:1px solid rgba(56,189,248,0.25);border-radius:var(--radius-sm);padding:12px 18px;margin-bottom:16px;display:flex;align-items:center;gap:12px;font-size:0.82rem;color:#bae6fd">
        <span style="font-size:1.3rem">ℹ️</span>
        <div>
          <strong>Single Host Topology:</strong> Only 1 asset (<strong>${escapeHtml(state.data.assets[0].name)}</strong> — <code>${escapeHtml(state.data.assets[0].ip)}</code>) is cataloged. Multi-hop lateral movement and attack-path analysis require 2 or more connected assets. Register additional lab targets or define relationships to model lateral movement scenarios.
        </div>
      </div>
    ` : assetCount > 1 && relCount === 0 ? `
      <div style="background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.25);border-radius:var(--radius-sm);padding:12px 18px;margin-bottom:16px;display:flex;align-items:center;gap:12px;font-size:0.82rem;color:#fde68a">
        <span style="font-size:1.3rem">⚠️</span>
        <div>
          <strong>Isolated Assets (No Relationships Defined):</strong> ${assetCount} assets are discovered, but no access pathways or trust connections have been defined yet. Click "Add Relationship" above to connect assets and evaluate multi-hop risk paths.
        </div>
      </div>
    ` : ''}

    <div class="panel" style="padding:14px;position:relative">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
        <div style="display:flex;gap:14px;font-size:0.75rem;color:var(--text-muted)">
          <span><span style="color:#ef4444">■</span> Critical/High Risk Asset</span>
          <span><span style="color:#38bdf8">■</span> Standard Asset</span>
          <span><span style="color:#f59e0b">━</span> High-Risk Relationship Path</span>
        </div>
        <small style="color:var(--text-dim)">Click any node or connection to inspect details</small>
      </div>

      <!-- Graph Viewport with Floating Controls -->
      <div class="graph-viewport" id="cyGraphContainer">
        <div class="graph-controls">
          <button class="graph-ctrl-btn" id="btnGraphZoomIn" title="Zoom In">+</button>
          <button class="graph-ctrl-btn" id="btnGraphZoomOut" title="Zoom Out">−</button>
          <button class="graph-ctrl-btn" id="btnGraphFit" title="Fit to Viewport">⛶ Fit</button>
          <button class="graph-ctrl-btn" id="btnGraphReset" title="Reset Layout">↻ Layout</button>
        </div>

        ${assetCount === 0 ? `
          <div class="graph-empty-overlay">
            <div class="graph-empty-icon">🕸️</div>
            <strong style="font-size:1.1rem;color:#fff">No Assets in Network Graph</strong>
            <p style="font-size:0.8rem;color:var(--text-muted);max-width:400px;margin-top:6px">
              Register an authorized lab target and run a discovery scan, or switch to Demo Mode to view the 5-asset campus network topology.
            </p>
          </div>
        ` : ''}
      </div>
    </div>

    <!-- Relationships Table -->
    <div class="panel">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">Modelled Relationships & Trust Pathways</h3>
          <p class="panel-subtitle">Access pathways, dependencies, and observation types between assets</p>
        </div>
      </div>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Source Asset</th>
              <th>Direction & Type</th>
              <th>Target Asset</th>
              <th>Nature</th>
              <th>Evidence / Context</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${state.data.relationships.map(r => {
              const src = state.data.assets.find(x => x.id === r.source_id);
              const tgt = state.data.assets.find(x => x.id === r.target_id);
              const natureBadge = r.nature === 'observed_network'
                ? '<span class="badge badge-low" title="Observed via network scan/traffic">Observed</span>'
                : '<span class="badge badge-info" title="Configured by instructor/admin">Admin Modeled</span>';
              const dirArrow = r.direction === 'bidirectional' ? '⇄' : '➔';

              return `
                <tr>
                  <td><strong>${src ? escapeHtml(src.name) : 'Asset'}</strong> (${src ? escapeHtml(src.ip) : ''})</td>
                  <td>
                    <span style="color:var(--accent-cyan);font-weight:700;margin-right:4px">${dirArrow}</span>
                    <span class="badge badge-info">${escapeHtml(r.type)}</span>
                  </td>
                  <td><strong>${tgt ? escapeHtml(tgt.name) : 'Asset'}</strong> (${tgt ? escapeHtml(tgt.ip) : ''})</td>
                  <td>${natureBadge}</td>
                  <td><small style="color:var(--text-muted)">${escapeHtml(r.evidence || r.description || 'Access connection')}</small></td>
                  <td>
                    <div style="display:flex;gap:4px">
                      <button class="btn btn-secondary btn-sm btn-view-rel" data-id="${r.id}">Inspect</button>
                      <button class="btn btn-danger btn-sm btn-del-rel" data-id="${r.id}">Delete</button>
                    </div>
                  </td>
                </tr>
              `;
            }).join('') || '<tr><td colspan="6" style="text-align:center;color:var(--text-dim)">No relationships mapped. Click "Add Relationship" above.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;

  $('#btnAddRelationship')?.addEventListener('click', showAddRelationshipModal);
  $$('.btn-view-rel').forEach(b => b.addEventListener('click', () => showRelationshipDetailsModal(b.dataset.id)));
  $$('.btn-del-rel').forEach(b => b.addEventListener('click', async () => {
    if (!confirm('Remove this relationship?')) return;
    await fetchApi(`/api/relationships/${b.dataset.id}`, { method: 'DELETE' });
    showToast('Relationship removed.');
    await loadState();
  }));

  initCytoscapeGraph();
}

function initCytoscapeGraph() {
  const container = document.getElementById('cyGraphContainer');
  if (!container || state.data.assets.length === 0) return;

  if (window.cytoscape) {
    const elements = [];
    // Nodes
    state.data.assets.forEach(a => {
      const r = state.baseline.assets.find(x => x.id === a.id);
      const isHot = r && ['critical', 'high'].includes(r.level);
      elements.push({
        data: {
          id: `node_${a.id}`,
          label: `${a.name}\n${a.ip}`,
          criticality: a.criticality,
          color: isHot ? '#ef4444' : '#38bdf8',
          rawId: a.id
        }
      });
    });

    // Edges
    state.data.relationships.forEach(rel => {
      const srcScore = state.baseline.assets.find(x => x.id === rel.source_id);
      const tgtScore = state.baseline.assets.find(x => x.id === rel.target_id);
      const isHot = srcScore?.activeFindings > 0 && ['high', 'critical'].includes(tgtScore?.criticality);
      elements.push({
        data: {
          id: `edge_${rel.id}`,
          rawId: rel.id,
          source: `node_${rel.source_id}`,
          target: `node_${rel.target_id}`,
          label: rel.type,
          lineColor: isHot ? '#f59e0b' : '#334155'
        }
      });
    });

    cyGraph = cytoscape({
      container,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            'label': 'data(label)',
            'color': '#ffffff',
            'font-size': '10px',
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'width': '65px',
            'height': '65px',
            'border-width': 2,
            'border-color': '#ffffff'
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 2.5,
            'line-color': 'data(lineColor)',
            'target-arrow-color': 'data(lineColor)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': '8px',
            'color': '#94a3b8',
            'text-rotation': 'autorotate'
          }
        }
      ],
      layout: { name: 'breadthfirst', directed: true, padding: 50 }
    });

    cyGraph.on('tap', 'node', function(evt) {
      showAssetDetailsModal(evt.target.data('rawId'));
    });

    cyGraph.on('tap', 'edge', function(evt) {
      showRelationshipDetailsModal(evt.target.data('rawId'));
    });

    // Viewport toolbar bindings
    $('#btnGraphZoomIn')?.addEventListener('click', () => {
      cyGraph.zoom(cyGraph.zoom() * 1.25);
    });
    $('#btnGraphZoomOut')?.addEventListener('click', () => {
      cyGraph.zoom(cyGraph.zoom() * 0.8);
    });
    $('#btnGraphFit')?.addEventListener('click', () => {
      cyGraph.fit(null, 50);
    });
    $('#btnGraphReset')?.addEventListener('click', () => {
      cyGraph.layout({ name: 'breadthfirst', directed: true, padding: 50 }).run();
      cyGraph.fit(null, 50);
    });

    // Auto-fit after render
    setTimeout(() => {
      try { cyGraph?.fit(null, 50); } catch (e) {}
    }, 100);

  } else {
    container.innerHTML = `<div style="padding:40px;text-align:center;color:var(--text-dim)">Cytoscape graph initialized. Nodes: ${state.data.assets.length}, Edges: ${state.data.relationships.length}.</div>`;
  }
}

function showRelationshipDetailsModal(relId) {
  const rel = state.data.relationships.find(r => r.id == relId);
  if (!rel) return;
  const src = state.data.assets.find(a => a.id === rel.source_id);
  const tgt = state.data.assets.find(a => a.id === rel.target_id);

  openModal(`Relationship: ${escapeHtml(rel.type)}`, `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px;font-size:0.82rem">
      <div><strong>Source Asset:</strong> ${src ? escapeHtml(src.name) : 'Asset'} (<code>${src ? escapeHtml(src.ip) : ''}</code>)</div>
      <div><strong>Target Asset:</strong> ${tgt ? escapeHtml(tgt.name) : 'Asset'} (<code>${tgt ? escapeHtml(tgt.ip) : ''}</code>)</div>
      <div><strong>Relationship Type:</strong> <span class="badge badge-info">${escapeHtml(rel.type)}</span></div>
      <div><strong>Direction:</strong> ${rel.direction === 'bidirectional' ? 'Bidirectional (Mutual Trust ⇄)' : 'Unidirectional (Source ➔ Target)'}</div>
      <div><strong>Nature:</strong> ${rel.nature === 'observed_network' ? '<span class="badge badge-low">Network Observed</span>' : '<span class="badge badge-info">Administrator Modeled</span>'}</div>
      <div><strong>Created:</strong> ${formatDate(rel.created_at)}</div>
    </div>

    <div style="margin-bottom:12px">
      <strong style="color:#fff;font-size:0.85rem">Description & Purpose:</strong>
      <p style="font-size:0.82rem;color:var(--text-main);margin-top:4px">${escapeHtml(rel.description || 'Access connection between laboratory hosts.')}</p>
    </div>

    <div style="background:rgba(255,255,255,0.02);border:1px solid var(--border-subtle);border-radius:4px;padding:12px;margin-bottom:16px;font-size:0.8rem">
      <strong style="color:var(--accent-cyan)">Evidence / Justification:</strong>
      <p style="color:var(--text-muted);margin-top:4px">${escapeHtml(rel.evidence || 'Documented network or application level access permission.')}</p>
    </div>

    <div style="display:flex;justify-content:space-between;align-items:center;margin-top:20px">
      <button type="button" class="btn btn-danger" id="btnModalDeleteRel">Delete Relationship</button>
      <button type="button" class="btn btn-secondary" onclick="document.getElementById('modalClose').click()">Close</button>
    </div>
  `);

  $('#btnModalDeleteRel')?.addEventListener('click', async () => {
    if (!confirm('Are you sure you want to delete this relationship?')) return;
    await fetchApi(`/api/relationships/${rel.id}`, { method: 'DELETE' });
    showToast('Relationship deleted.');
    closeModal();
    await loadState();
  });
}

function showAddRelationshipModal() {
  if (state.data.assets.length < 2) {
    showToast('Add at least two assets to define a relationship.', true);
    return;
  }

  openModal('Create Relationship', `
    <form id="formAddRel">
      <div class="form-group">
        <label class="form-label">Source Asset (From) *</label>
        <select class="form-control" name="source_id">
          ${state.data.assets.map(a => `<option value="${a.id}">${escapeHtml(a.name)} (${escapeHtml(a.ip)})</option>`).join('')}
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Relationship Type *</label>
        <select class="form-control" name="type">
          <option value="Network Access">Network Access (TCP/IP Port Reachability)</option>
          <option value="Application Access">Application Access (HTTP/API Consumer)</option>
          <option value="Database Connection">Database Connection (SQL / Remote DB Client)</option>
          <option value="Administrative Access">Administrative Access (SSH, RDP, Management)</option>
          <option value="Shared Service">Shared Service (Domain Controller / File Share / DNS)</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Target Asset (To) *</label>
        <select class="form-control" name="target_id">
          ${state.data.assets.map((a, i) => `<option value="${a.id}" ${i === 1 ? 'selected' : ''}>${escapeHtml(a.name)} (${escapeHtml(a.ip)})</option>`).join('')}
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Direction</label>
        <select class="form-control" name="direction">
          <option value="directed" selected>Unidirectional (Source ➔ Target)</option>
          <option value="bidirectional">Bidirectional (Mutual Trust ⇄)</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Relationship Nature</label>
        <select class="form-control" name="nature">
          <option value="modeled_admin" selected>Administrator Modeled (Hypothetical / Documented Trust)</option>
          <option value="observed_network">Network Observed (Port Scan / Traffic Flow Evidence)</option>
          <option value="verified_lateral">Verified Lateral Access (Authenticated Session / Token)</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Evidence / Justification</label>
        <input class="form-control" name="evidence" placeholder="e.g. Lab firewall rule #12 permits port 3306 or SSH key trust">
      </div>
      <div class="form-group">
        <label class="form-label">Description / Context</label>
        <input class="form-control" name="description" placeholder="e.g. Student web portal queries DB backend">
      </div>
      <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:16px">
        <button type="button" class="btn btn-secondary" onclick="document.getElementById('modalClose').click()">Cancel</button>
        <button type="submit" class="btn btn-primary">Connect Assets</button>
      </div>
    </form>
  `);

  $('#formAddRel')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const body = {
      source_id: Number(fd.get('source_id')),
      target_id: Number(fd.get('target_id')),
      type: fd.get('type'),
      direction: fd.get('direction'),
      nature: fd.get('nature'),
      evidence: fd.get('evidence'),
      description: fd.get('description')
    };
    try {
      await fetchApi('/api/relationships', { method: 'POST', body: JSON.stringify(body) });
      showToast('Relationship mapped.');
      closeModal();
      await loadState();
    } catch (err) {}
  });
}

// 7. RISK ANALYSIS
function renderRisk(c) {
  const b = state.baseline || {};
  const paths = b.paths || [];
  const pContext = b.pathContext || {};

  c.innerHTML = `
    <div class="page-header">
      <div class="page-title">
        <h1>Explainable Risk Analysis & Scoring</h1>
        <p>Transparent, auditable points formula: (Vulnerabilities + Exposure + Network Relationships) × Asset Criticality Multiplier.</p>
      </div>
    </div>

    <!-- Auditable Formula Card -->
    <div class="formula-card">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
        <h3 style="color:#fff;font-size:0.95rem;margin:0">📐 CampusShield Auditable Scoring Formula</h3>
        <span class="badge badge-info">Deterministic & Capped</span>
      </div>
      <p style="font-size:0.82rem;color:var(--text-muted);margin:8px 0 0 0">
        <code>Final Asset Score = Min(100, Math.round((Vuln_Score [Cap 50] + Exposure_Score [Cap 20] + Relationship_Score [Cap 30]) × Criticality_Multiplier))</code>
      </p>
      <div class="formula-grid">
        <div class="formula-box">
          <strong>1. Vulnerabilities (Cap: 50 pts)</strong>
          Critical=20, High=12, Medium=6, Low=2, Info=0
        </div>
        <div class="formula-box">
          <strong>2. Exposure (Cap: 20 pts)</strong>
          +2 pts per open port + High-Risk service bonus (+3 for SMB 445, FTP 21, Telnet 23, DB 3306...)
        </div>
        <div class="formula-box">
          <strong>3. Relationships (Cap: 30 pts)</strong>
          +2 pts per connection +5 for upstream untrusted/vulnerable +10 for vulnerable asset connecting to critical target
        </div>
        <div class="formula-box">
          <strong>4. Criticality Multipliers</strong>
          Low = 0.8x | Medium = 1.0x | High = 1.15x | Critical = 1.3x<br>
          Levels: Low (0-39), Medium (40-69), High (70-84), Critical (85-100)
        </div>
      </div>
    </div>

    <!-- Identified Risk Paths -->
    <div class="panel">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">Potential Security Risk Paths</h3>
          <p class="panel-subtitle">Multi-hop relationship chains where low-trust entry points can reach critical targets via vulnerable hops</p>
        </div>
        <span class="badge ${paths.length > 0 ? 'badge-high' : 'badge-low'}">${paths.length} Paths Detected</span>
      </div>
      <div>
        ${paths.length > 0 ? paths.map((p, idx) => `
          <div style="background:var(--bg-main);border:1px solid var(--border-subtle);border-radius:8px;padding:16px;margin-bottom:14px">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
              <span style="font-weight:700;color:var(--accent-amber)">Risk Scenario #${idx + 1}: ${p.names.join('  ➔  ')}</span>
              <span class="badge badge-${p.level}">${p.score}/100 (${p.level.toUpperCase()})</span>
            </div>
            <p style="font-size:0.83rem;color:var(--text-main);line-height:1.5">${escapeHtml(p.explanation)}</p>
          </div>
        `).join('') : `
          <div style="background:rgba(56,189,248,0.06);border:1px solid rgba(56,189,248,0.25);border-radius:var(--radius-sm);padding:16px 20px;display:flex;align-items:center;gap:14px">
            <span style="font-size:1.6rem">ℹ️</span>
            <div>
              <strong style="color:#fff">Zero Attack Paths Detected</strong>
              <p style="font-size:0.83rem;color:var(--text-muted);margin-top:4px;line-height:1.5">
                ${escapeHtml(pContext.explanation || 'No multi-hop risk paths exist under the current network topology.')}
              </p>
              <small style="color:var(--accent-cyan);display:block;margin-top:4px">
                CampusShield strictly prevents fabricating attack paths. A path requires an entry point and intermediate vulnerable hops leading to a critical asset.
              </small>
            </div>
          </div>
        `}
      </div>
    </div>

    <!-- Transparent Score Reasoning Breakdown -->
    <div class="panel">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">Asset Scoring Breakdown & Mathematical Rationale</h3>
          <p class="panel-subtitle">Sum of subtotals and applied multiplier for each system in inventory</p>
        </div>
      </div>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Asset</th>
              <th>Criticality</th>
              <th>Vuln (Cap 50)</th>
              <th>Exposure (Cap 20)</th>
              <th>Rel (Cap 30)</th>
              <th>Multiplier</th>
              <th>Final Score</th>
              <th>Itemized Explanations</th>
            </tr>
          </thead>
          <tbody>
            ${(b.assets || []).map(a => {
              const bd = a.breakdown || {};
              return `
                <tr>
                  <td><strong>${escapeHtml(a.name)}</strong><br><small style="color:var(--text-muted)">${escapeHtml(a.ip)}</small></td>
                  <td><span class="badge badge-${a.criticality}">${a.criticality}</span></td>
                  <td><strong>${bd.vulnerability ?? 0} pts</strong> <small style="color:var(--text-dim)">(raw: ${bd.vulnRaw ?? 0})</small></td>
                  <td><strong>${bd.exposure ?? 0} pts</strong> <small style="color:var(--text-dim)">(raw: ${bd.exposureRaw ?? 0})</small></td>
                  <td><strong>${bd.relationship ?? 0} pts</strong> <small style="color:var(--text-dim)">(raw: ${bd.relRaw ?? 0})</small></td>
                  <td><code>x${bd.multiplier || 1.0}</code></td>
                  <td><span class="badge badge-${a.level}">${a.score}/100</span></td>
                  <td>
                    <ul style="padding-left:18px;font-size:0.75rem;color:var(--text-muted);line-height:1.4">
                      ${(a.reasons || []).map(r => `<li>${escapeHtml(r.text)}</li>`).join('')}
                    </ul>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// 8. PACKET ANALYSIS
function renderPackets(c) {
  c.innerHTML = `
    <div class="page-header">
      <div class="page-title">
        <h1>Offline Packet Capture (PCAP) Analysis</h1>
        <p>Inspect authorized laboratory network captures. Highlights insecure protocols (HTTP, FTP, Telnet) and conversation flows.</p>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h3 class="panel-title">Upload Capture File (.pcap / .pcapng)</h3>
      </div>
      <div style="border:2px dashed var(--border-subtle);border-radius:8px;padding:30px;text-align:center;cursor:pointer" id="dropPcapZone">
        <span style="font-size:2rem;display:block;margin-bottom:8px">📦</span>
        <strong>Click or Drag & Drop a .pcap / .pcapng file here</strong>
        <p style="font-size:0.75rem;color:var(--text-muted);margin-top:4px">Upload samples from Wireshark or test captures in <code>samples/sample_capture.pcap</code>.</p>
        <input type="file" id="inputPcapFile" accept=".pcap,.pcapng" style="display:none">
      </div>
    </div>

    <div id="pcapResultsContainer"></div>
  `;

  const dropZone = $('#dropPcapZone');
  const fileInput = $('#inputPcapFile');

  dropZone?.addEventListener('click', () => fileInput.click());
  fileInput?.addEventListener('change', (e) => {
    if (e.target.files?.[0]) processPcapFile(e.target.files[0]);
  });
}

async function processPcapFile(file) {
  showToast(`Parsing capture "${file.name}"...`);
  const reader = new FileReader();
  reader.onload = async () => {
    const base64 = reader.result.split(',')[1];
    try {
      const res = await fetchApi('/api/analyze-pcap', {
        method: 'POST',
        body: JSON.stringify({ filename: file.name, content: base64 })
      });
      displayPcapResults(res);
      showToast('PCAP analysis completed.');
    } catch (err) {}
  };
  reader.readAsDataURL(file);
}

function displayPcapResults(res) {
  const container = $('#pcapResultsContainer');
  if (!container) return;

  container.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <h3 class="panel-title">Capture Summary: ${escapeHtml(res.filename || 'capture.pcap')}</h3>
        <span class="badge badge-info">${res.packetCount} Packets Analyzed</span>
      </div>

      <!-- Alerts -->
      ${(res.alerts || []).map(a => `
        <div style="background:rgba(249,115,22,0.1);border-left:4px solid var(--color-high);padding:10px 14px;border-radius:4px;margin-bottom:10px;font-size:0.82rem">
          <strong>⚠️ ${escapeHtml(a.title)}:</strong> ${escapeHtml(a.detail)}
        </div>
      `).join('')}

      <div style="margin:20px 0">
        <h4 style="font-size:0.9rem;margin-bottom:8px">Protocol Distribution</h4>
        <div class="table-responsive">
          <table>
            <thead><tr><th>Protocol</th><th>Packet Count</th><th>Risk Level</th><th>Evaluation</th></tr></thead>
            <tbody>
              ${(res.protocols || []).map(p => `
                <tr>
                  <td><strong>${escapeHtml(p.name)}</strong></td>
                  <td>${p.packets}</td>
                  <td><span class="badge ${p.risk === 'review' ? 'badge-high' : 'badge-low'}">${p.risk}</span></td>
                  <td><small>${escapeHtml(p.note || 'Standard protocol')}</small></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

// 9. LOG ANALYSIS
function renderLogs(c) {
  c.innerHTML = `
    <div class="page-header">
      <div class="page-title">
        <h1>Offline Log Analysis</h1>
        <p>Inspect laboratory system and web server logs (SSH auth.log, Apache/Nginx access logs) to detect brute-force and attack patterns.</p>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h3 class="panel-title">Upload Log File (.log / .txt)</h3>
      </div>
      <div style="border:2px dashed var(--border-subtle);border-radius:8px;padding:30px;text-align:center;cursor:pointer" id="dropLogZone">
        <span style="font-size:2rem;display:block;margin-bottom:8px">📋</span>
        <strong>Click or Drag & Drop a .log / .txt file here</strong>
        <p style="font-size:0.75rem;color:var(--text-muted);margin-top:4px">Upload <code>samples/sample_auth.log</code> or <code>samples/sample_access.log</code> to test.</p>
        <input type="file" id="inputLogFile" accept=".log,.txt" style="display:none">
      </div>
    </div>

    <div id="logResultsContainer"></div>
  `;

  const dropZone = $('#dropLogZone');
  const fileInput = $('#inputLogFile');

  dropZone?.addEventListener('click', () => fileInput.click());
  fileInput?.addEventListener('change', (e) => {
    if (e.target.files?.[0]) processLogFile(e.target.files[0]);
  });
}

async function processLogFile(file) {
  showToast(`Parsing log file "${file.name}"...`);
  const reader = new FileReader();
  reader.onload = async () => {
    try {
      const res = await fetchApi('/api/analyze-log', {
        method: 'POST',
        body: JSON.stringify({ filename: file.name, content: reader.result })
      });
      displayLogResults(res);
      showToast('Log analysis completed.');
    } catch (err) {}
  };
  reader.readAsText(file);
}

function displayLogResults(res) {
  const container = $('#logResultsContainer');
  if (!container) return;

  container.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <h3 class="panel-title">Log Analysis Summary: ${escapeHtml(res.filename)}</h3>
        <span class="badge badge-info">${res.totalLines} Lines Processed</span>
      </div>

      <div class="table-responsive">
        <table>
          <thead><tr><th>Origin IP</th><th>Observed Event</th><th>Occurrences</th><th>Risk</th><th>Evidence Sample</th></tr></thead>
          <tbody>
            ${(res.findings || []).map(f => `
              <tr>
                <td><code>${escapeHtml(f.ip)}</code></td>
                <td><strong>${escapeHtml(f.event)}</strong></td>
                <td>${f.count} times</td>
                <td><span class="badge badge-${f.risk}">${f.risk}</span></td>
                <td><code style="font-size:0.75rem">${escapeHtml(f.samples?.[0] || '—')}</code></td>
              </tr>
            `).join('') || '<tr><td colspan="5" style="text-align:center">No security anomalies detected.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

// 10. REMEDIATION (WHAT-IF SIMULATION)
function renderRemediation(c) {
  const base = state.baseline.overall || {};
  const sim = state.simulated?.overall || base;
  const activeItems = state.scenario || [];
  const hasSimulation = activeItems.length > 0;
  const scoreDrop = (base.score || 0) - (sim.score || 0);
  const pathsMitigated = (base.riskyPaths || 0) - (sim.riskyPaths || 0);
  const pctDrop = base.score ? Math.round((scoreDrop / base.score) * 100) : 0;

  c.innerHTML = `
    <div class="page-header">
      <div class="page-title">
        <h1>Remediation Simulation (What-If Model)</h1>
        <p>Preview the exact security impact of proposed fixes before executing changes on the live network.</p>
      </div>
      <div class="header-actions">
        ${hasSimulation ? `<button class="btn btn-secondary btn-sm" id="btnClearSimulation">Reset All Simulations (${activeItems.length})</button>` : ''}
      </div>
    </div>

    <!-- Simulation Context / Status Callout -->
    ${!hasSimulation ? `
      <div class="sim-callout">
        <span style="font-size:1.3rem">ℹ️</span>
        <div>
          <strong>Baseline Assessment Mode:</strong> No hypothetical remediation actions are currently active. Current network risk score is <strong>${base.score || 0}/100</strong> (${(base.level || 'low').toUpperCase()}). Select proposed actions below (fixing vulnerabilities, blocking exposed services, or severing trust relationships) to preview the projected risk drop.
        </div>
      </div>
    ` : `
      <div style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.25);border-radius:var(--radius-sm);padding:12px 18px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;font-size:0.82rem;color:#a7f3d0">
        <div>
          <strong>Active Simulation Scenario (${activeItems.length} action${activeItems.length === 1 ? '' : 's'}):</strong>
          ${scoreDrop > 0 ? `Reduced overall network risk by <strong>-${scoreDrop} points (-${pctDrop}%)</strong> and mitigated <strong>${pathsMitigated}</strong> risky attack path(s).` : `Proposed interventions applied. Note: Overall score unchanged because remaining findings/exposures on affected assets still saturate category points, or no risk paths traversed this component.`}
        </div>
      </div>
    `}

    <!-- Before vs After Comparison Card -->
    <div class="comparison-card">
      <div class="comp-state">
        <span style="font-size:0.75rem;font-weight:700;color:var(--text-muted);text-transform:uppercase">Baseline Network Assessment</span>
        <div style="font-size:2rem;font-weight:700;color:#fff;margin:6px 0">${base.score || 0} <span style="font-size:1rem;color:var(--text-muted)">/100</span></div>
        <div style="font-size:0.8rem;color:var(--text-muted)">
          • Active Findings: <strong>${base.vulnerabilities || 0}</strong><br>
          • Open Services: <strong>${base.openServices || 0}</strong><br>
          • Modeled Risk Paths: <strong>${base.riskyPaths || 0}</strong>
        </div>
      </div>

      <div class="comp-divider">
        ➔
        ${hasSimulation ? `
          <span class="comp-reduction">-${scoreDrop} Points (${pctDrop}%)</span>
        ` : `
          <span style="font-size:0.72rem;color:var(--text-muted);background:rgba(255,255,255,0.04);padding:4px 8px;border-radius:var(--radius-full)">Select Actions Below</span>
        `}
      </div>

      <div class="comp-state" style="${hasSimulation ? 'border-color:var(--accent-emerald);background:rgba(16,185,129,0.03)' : ''}">
        <span style="font-size:0.75rem;font-weight:700;color:${hasSimulation ? 'var(--accent-emerald)' : 'var(--text-muted)'};text-transform:uppercase">
          ${hasSimulation ? 'Simulated Post-Remediation State' : 'Simulated State Projection'}
        </span>
        <div style="font-size:2rem;font-weight:700;color:${hasSimulation ? 'var(--accent-emerald)' : '#fff'};margin:6px 0">
          ${hasSimulation ? `${sim.score || 0} ` : `${base.score || 0} `}<span style="font-size:1rem;color:var(--text-muted)">/100</span>
        </div>
        <div style="font-size:0.8rem;color:var(--text-muted)">
          • Projected Findings: <strong>${sim.vulnerabilities ?? base.vulnerabilities}</strong><br>
          • Projected Services: <strong>${sim.openServices ?? base.openServices}</strong><br>
          • Paths Mitigated: <strong>${pathsMitigated}</strong>
        </div>
      </div>
    </div>

    <!-- 1. Simulate Fixing Vulnerability Findings -->
    <div class="panel">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">1. Simulate Resolving Vulnerability Findings</h3>
          <p class="panel-subtitle">Simulate code fixes or patch applications while leaving underlying network ports open</p>
        </div>
      </div>
      <div class="table-responsive">
        <table>
          <thead><tr><th>Severity</th><th>Finding Title</th><th>Affected Asset</th><th>Simulation Status</th><th>Action</th></tr></thead>
          <tbody>
            ${state.data.findings.filter(f => ['open', 'under_review', 'planned'].includes(f.status)).map(f => {
              const a = state.data.assets.find(x => x.id === f.asset_id);
              const isSimActive = activeItems.some(i => i.kind === 'finding' && i.ref_id === f.id);
              return `
                <tr style="${isSimActive ? 'background:rgba(16,185,129,0.06)' : ''}">
                  <td><span class="badge badge-${f.severity}">${f.severity}</span></td>
                  <td><strong>${escapeHtml(f.title)}</strong><br><small style="color:var(--text-muted)">Port: ${f.port || 'N/A'}</small></td>
                  <td>${a ? escapeHtml(a.name) : 'Asset'}</td>
                  <td>${isSimActive ? '<span class="badge badge-low">SIMULATED AS FIXED</span>' : '<span style="color:var(--text-dim);font-size:0.75rem">Active in baseline</span>'}</td>
                  <td>
                    <button class="btn ${isSimActive ? 'btn-secondary' : 'btn-primary'} btn-sm btn-toggle-sim" data-kind="finding" data-id="${f.id}" data-label="${escapeHtml(f.title)}">
                      ${isSimActive ? 'Undo Simulation' : 'Simulate Fix'}
                    </button>
                  </td>
                </tr>
              `;
            }).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--text-dim)">No active vulnerabilities available to simulate.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- 2. Simulate Disabling or Blocking Exposed Services / Ports -->
    <div class="panel">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">2. Simulate Disabling Services or Blocking Ports</h3>
          <p class="panel-subtitle">Block port at firewall or shutdown service (removes port exposure points, risky service bonus, and tied findings)</p>
        </div>
      </div>
      <div class="table-responsive">
        <table>
          <thead><tr><th>Port</th><th>Service Name</th><th>Host System</th><th>Risk Evaluation</th><th>Simulation Status</th><th>Action</th></tr></thead>
          <tbody>
            ${state.data.services.map(s => {
              const a = state.data.assets.find(x => x.id === s.asset_id);
              const isSimActive = activeItems.some(i => i.kind === 'service' && i.ref_id === s.id);
              const isHighRisk = [445, 21, 23, 3389, 3306, 5432, 1433, 27017, 6379].includes(s.port);
              return `
                <tr style="${isSimActive ? 'background:rgba(16,185,129,0.06)' : ''}">
                  <td><code>${s.port}/${s.protocol}</code></td>
                  <td><strong>${escapeHtml(s.service || 'unknown')}</strong></td>
                  <td>${a ? escapeHtml(a.name) : 'Asset'}<br><small style="color:var(--text-muted)">${a ? escapeHtml(a.ip) : ''}</small></td>
                  <td>${isHighRisk ? '<span class="badge badge-high">+3 High-Risk Bonus</span>' : '<span class="badge badge-info">+2 Base Exp</span>'}</td>
                  <td>${isSimActive ? '<span class="badge badge-low">SIMULATED BLOCKED</span>' : '<span style="color:var(--text-dim);font-size:0.75rem">Listening</span>'}</td>
                  <td>
                    <button class="btn ${isSimActive ? 'btn-secondary' : 'btn-primary'} btn-sm btn-toggle-sim" data-kind="service" data-id="${s.id}" data-label="Block Port ${s.port} (${escapeHtml(s.service || '')})">
                      ${isSimActive ? 'Unblock Port' : `Block Port ${s.port}`}
                    </button>
                  </td>
                </tr>
              `;
            }).join('') || '<tr><td colspan="6" style="text-align:center;color:var(--text-dim)">No exposed services recorded.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- 3. Simulate Restricting Network Relationships -->
    <div class="panel">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">3. Simulate Restricting Network & Access Relationships</h3>
          <p class="panel-subtitle">Isolate lateral network paths or revoke database/management access connections</p>
        </div>
      </div>
      <div class="table-responsive">
        <table>
          <thead><tr><th>Source Asset</th><th>Relationship</th><th>Target Asset</th><th>Simulation Status</th><th>Action</th></tr></thead>
          <tbody>
            ${state.data.relationships.map(r => {
              const src = state.data.assets.find(x => x.id === r.source_id);
              const tgt = state.data.assets.find(x => x.id === r.target_id);
              const isSimActive = activeItems.some(i => i.kind === 'relationship' && i.ref_id === r.id);
              return `
                <tr style="${isSimActive ? 'background:rgba(16,185,129,0.06)' : ''}">
                  <td>${src ? escapeHtml(src.name) : 'Asset'}</td>
                  <td><span class="badge badge-info">${escapeHtml(r.type)}</span></td>
                  <td>${tgt ? escapeHtml(tgt.name) : 'Asset'}</td>
                  <td>${isSimActive ? '<span class="badge badge-low">SIMULATED SEVERED</span>' : '<span style="color:var(--text-dim);font-size:0.75rem">Active connection</span>'}</td>
                  <td>
                    <button class="btn ${isSimActive ? 'btn-secondary' : 'btn-primary'} btn-sm btn-toggle-sim" data-kind="relationship" data-id="${r.id}" data-label="Sever ${escapeHtml(r.type)}">
                      ${isSimActive ? 'Restore Connection' : 'Sever Access Path'}
                    </button>
                  </td>
                </tr>
              `;
            }).join('') || '<tr><td colspan="5" style="text-align:center;color:var(--text-dim)">No relationships mapped.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;

  $$('.btn-toggle-sim').forEach(b => {
    b.addEventListener('click', async () => {
      const kind = b.dataset.kind;
      const ref_id = Number(b.dataset.id);
      const label = b.dataset.label;
      try {
        await fetchApi('/api/simulation/toggle', { method: 'POST', body: JSON.stringify({ kind, ref_id, label }) });
        await loadState();
      } catch (err) {}
    });
  });

  $('#btnClearSimulation')?.addEventListener('click', async () => {
    await fetchApi('/api/simulation/clear', { method: 'POST' });
    showToast('Simulation reset to baseline.');
    await loadState();
  });
}

// 11. REPORTS
function renderReports(c) {
  const b = state.baseline.overall || {};

  c.innerHTML = `
    <div class="page-header">
      <div class="page-title">
        <h1>VAPT Assessment Report Export</h1>
        <p>Export a comprehensive, professional PDF containing scope, scan inventory, findings, security graph, risk paths and remediation recommendations.</p>
      </div>
      <div class="header-actions">
        <a href="/api/report.pdf" class="btn btn-primary" download="CampusShield_VAPT_Report.pdf">
          <span>📥</span> Download Official PDF Report
        </a>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">Report Content Preview</h3>
          <p class="panel-subtitle">All 20 viva & audit specification sections included</p>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;font-size:0.82rem">
        <div style="background:var(--bg-main);padding:12px;border-radius:6px;border:1px solid var(--border-subtle)">
          <strong>1. Executive Scope & Metadata</strong><br>
          <small style="color:var(--text-muted)">Target organization, rules of engagement, and authorization statement.</small>
        </div>
        <div style="background:var(--bg-main);padding:12px;border-radius:6px;border:1px solid var(--border-subtle)">
          <strong>2. Tools & Scan Execution</strong><br>
          <small style="color:var(--text-muted)">Nmap discovery, safe web baseline, and tool commands.</small>
        </div>
        <div style="background:var(--bg-main);padding:12px;border-radius:6px;border:1px solid var(--border-subtle)">
          <strong>3. Asset & Service Inventory</strong><br>
          <small style="color:var(--text-muted)">${b.assets || 0} systems and ${b.openServices || 0} open ports cataloged.</small>
        </div>
        <div style="background:var(--bg-main);padding:12px;border-radius:6px;border:1px solid var(--border-subtle)">
          <strong>4. Vulnerabilities & CVEs</strong><br>
          <small style="color:var(--text-muted)">${b.vulnerabilities || 0} findings mapped with CWE, confidence and verified CVEs.</small>
        </div>
        <div style="background:var(--bg-main);padding:12px;border-radius:6px;border:1px solid var(--border-subtle)">
          <strong>5. Security Graph & Risk Paths</strong><br>
          <small style="color:var(--text-muted)">Topology relationships and multi-hop risk scenario explanations.</small>
        </div>
        <div style="background:var(--bg-main);padding:12px;border-radius:6px;border:1px solid var(--border-subtle)">
          <strong>6. Remediation Simulation</strong><br>
          <small style="color:var(--text-muted)">Before vs After risk scores and strategic security recommendations.</small>
        </div>
      </div>
    </div>
  `;
}

// 12. SETTINGS
function renderSettings(c) {
  const isDemo = state.mode === 'demo';

  c.innerHTML = `
    <div class="page-header">
      <div class="page-title">
        <h1>Workspace Settings & Scoring Methodology</h1>
        <p>Switch between the safe simulated Demo environment and Live Lab Mode for actual scanning.</p>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">Environment Mode</h3>
          <p class="panel-subtitle">Currently in: <strong>${state.mode.toUpperCase()} MODE</strong></p>
        </div>
      </div>
      <p style="font-size:0.85rem;color:var(--text-muted);margin-bottom:16px">
        CampusShield maintains completely separate databases (<code>data/demo.db</code> and <code>data/live.db</code>).
        Switching modes never deletes your live lab data or demo records.
      </p>
      <div style="display:flex;gap:12px">
        <button class="btn ${isDemo ? 'btn-primary' : 'btn-secondary'}" id="btnSetDemoMode">
          Demo Mode (Simulated Lab)
        </button>
        <button class="btn ${!isDemo ? 'btn-primary' : 'btn-secondary'}" id="btnSetLiveMode">
          Live Lab Mode (Authorized Scans)
        </button>
      </div>
    </div>

    <!-- Scoring Methodology Documentation Card -->
    <div class="panel">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">Scoring Methodology & Risk Categories Documentation</h3>
          <p class="panel-subtitle">Mathematical formula, factor bounds, and category thresholds</p>
        </div>
      </div>
      <div style="font-size:0.83rem;color:var(--text-muted);line-height:1.6">
        <p style="margin-bottom:10px">
          CampusShield uses a single, deterministic formula to compute an asset's risk score from three distinct categories:
        </p>
        <pre style="background:#090d16;padding:12px;border-radius:6px;font-family:var(--font-mono);font-size:0.75rem;color:#38bdf8;margin-bottom:12px">Score = Math.min(100, Math.round((Vuln_Pts [Max 50] + Exposure_Pts [Max 20] + Relationship_Pts [Max 30]) × Criticality_Multiplier))</pre>
        <ul style="padding-left:20px;margin-bottom:14px">
          <li><strong>Vulnerability Subtotal (Max 50):</strong> Critical = 20 pts, High = 12 pts, Medium = 6 pts, Low = 2 pts, Info = 0 pts.</li>
          <li><strong>Exposure Subtotal (Max 20):</strong> +2 pts per discovered open port + High-risk service bonus (+3 for SMB/445, FTP/21, Telnet/23, RDP/3389, DB/3306).</li>
          <li><strong>Relationship Subtotal (Max 30):</strong> +2 pts per connected neighbor (max 10), +5 pts per untrusted/vulnerable upstream neighbor (max 10), and +10 pts if a vulnerable asset connects to a high/critical target.</li>
          <li><strong>Criticality Multiplier:</strong> Low = 0.8x, Medium = 1.0x, High = 1.15x, Critical = 1.3x.</li>
          <li><strong>Risk Category Thresholds:</strong> Low (0–39), Medium (40–69), High (70–84), Critical (85–100).</li>
        </ul>
      </div>
    </div>

    ${isDemo ? `
      <div class="panel">
        <div class="panel-header">
          <div>
            <h3 class="panel-title">Reset Demo Environment</h3>
            <p class="panel-subtitle">Restore the original 5-asset college lab network with sample findings and trend history</p>
          </div>
        </div>
        <button class="btn btn-secondary" id="btnResetDemoData">↻ Reset Demo Fixtures</button>
      </div>
    ` : ''}

    <div class="panel">
      <div class="panel-header">
        <div>
          <h3 class="panel-title">Scanner Engine Status</h3>
        </div>
      </div>
      <p style="font-size:0.85rem;color:var(--text-muted)">
        • <strong>Nmap Executable:</strong> ${state.nmapAvailable ? `<span style="color:var(--accent-emerald)">Installed at ${escapeHtml(state.nmapPath)}</span>` : '<span style="color:var(--accent-amber)">Not found on PATH</span>'}<br>
        • <strong>Server Binding:</strong> <code>127.0.0.1:4173</code> (Loopback only for security)
      </p>
    </div>
  `;

  $('#btnSetDemoMode')?.addEventListener('click', () => switchMode('demo'));
  $('#btnSetLiveMode')?.addEventListener('click', () => switchMode('live'));
  $('#btnResetDemoData')?.addEventListener('click', async () => {
    if (!confirm('Reset the demo environment?')) return;
    await fetchApi('/api/reset-demo', { method: 'POST' });
    showToast('Demo environment reset.');
    await loadState();
  });
}

async function switchMode(mode) {
  try {
    await fetchApi('/api/mode', { method: 'POST', body: JSON.stringify({ mode }) });
    showToast(`Switched to ${mode.toUpperCase()} mode.`);
    await loadState();
  } catch (err) {}
}

// Topbar Mode Switcher
$('#modeToggleBtn')?.addEventListener('click', () => {
  const nextMode = state.mode === 'demo' ? 'live' : 'demo';
  switchMode(nextMode);
});

$('#btnQuickReport')?.addEventListener('click', () => {
  window.open('/api/report.pdf', '_blank');
});

$('#mobileToggle')?.addEventListener('click', () => {
  $('#sidebar')?.classList.toggle('open');
});

// App Startup
document.addEventListener('DOMContentLoaded', () => {
  handleRoute();
  loadState();
});
