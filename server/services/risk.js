/**
 * CampusShield — Risk Engine (Analysis Layer)
 *
 * IMPORTANT: this is CampusShield's project-specific, transparent risk model.
 * It is NOT CVSS and not an official rating. Every number it produces is
 * accompanied by human-readable reasons.
 *
 *   Asset Risk = (Vulnerability Score + Exposure Score + Relationship Risk) x Criticality Multiplier
 *
 *   Vulnerability Score (max 50): critical 20, high 12, medium 6, low 2, info 0 per ACTIVE finding
 *   Exposure Score      (max 20): 2 per open service + 3 extra per high-risk service (Telnet, FTP, SMB, DB...)
 *   Relationship Risk   (max 30): 2 per connected asset (max 10)
 *                                + 5 per upstream untrusted / vulnerable neighbour (max 10)
 *                                + 10 if this asset is vulnerable AND connects to a high/critical asset
 *   Criticality multiplier:      low 0.8, medium 1.0, high 1.15, critical 1.3   (result capped at 100)
 *
 *   Overall score = criticality-weighted average of asset scores (weights 1/2/3/4).
 *   Levels: >= 85 Critical, >= 70 High, >= 40 Medium, otherwise Low.
 */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const ACTIVE_STATUSES = ['open', 'under_review', 'planned'];
export const STATUSES = ['open', 'under_review', 'planned', 'fixed', 'retested'];
export const SEVERITY_POINTS = { critical: 20, high: 12, medium: 6, low: 2, info: 0 };
export const CRITICALITY_MULTIPLIER = { low: 0.8, medium: 1.0, high: 1.15, critical: 1.3 };
const CRITICALITY_WEIGHT = { low: 1, medium: 2, high: 3, critical: 4 };
const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** Services whose network exposure is considered high-risk in a lab context. */
export const HIGH_RISK_PORTS = {
  21: 'FTP', 23: 'Telnet', 139: 'NetBIOS', 445: 'SMB', 3389: 'RDP', 5900: 'VNC',
  3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 1521: 'Oracle', 27017: 'MongoDB',
  6379: 'Redis', 161: 'SNMP', 512: 'rexec', 513: 'rlogin', 514: 'rsh',
};

/**
 * Priority matrix: asset criticality (rows) x finding severity (columns).
 * The same finding becomes more urgent on a more important asset.
 */
export const PRIORITY_MATRIX = {
  //          info     low       medium    high       critical
  low:      ['info', 'low',    'medium', 'medium',  'high'],
  medium:   ['info', 'low',    'medium', 'high',    'critical'],
  high:     ['info', 'medium', 'high',   'high',    'critical'],
  critical: ['low',  'medium', 'high',   'critical', 'critical'],
};
export function priorityOf(severity, criticality) {
  const row = PRIORITY_MATRIX[criticality] || PRIORITY_MATRIX.medium;
  return row[SEV_RANK[severity] ?? 2];
}

export function levelOf(score) {
  if (score >= 85) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

/**
 * Build the effective (possibly simulated) state of the network.
 * scenario = { fixedFindings:Set, blockedRels:Set, closedServices:Set }
 */
function effectiveState(data, scenario = {}) {
  const fixed = scenario.fixedFindings || new Set();
  const blocked = scenario.blockedRels || new Set();
  const closed = scenario.closedServices || new Set();
  const closedPorts = new Set(
    data.services.filter(s => closed.has(s.id)).map(s => `${s.asset_id}:${s.port}`)
  );
  const services = data.services.filter(s => !closed.has(s.id));
  const findings = data.findings.filter(f =>
    ACTIVE_STATUSES.includes(f.status) &&
    !fixed.has(f.id) &&
    !(f.port != null && closedPorts.has(`${f.asset_id}:${f.port}`))
  );
  const relationships = data.relationships.filter(r => !blocked.has(r.id));
  return { assets: data.assets, services, findings, relationships };
}

/** Score each asset and explain the result. */
function scoreAssets(state) {
  const byId = new Map(state.assets.map(a => [a.id, a]));
  const findingsOf = id => state.findings.filter(f => f.asset_id === id);
  const isVulnerable = id => findingsOf(id).some(f => SEV_RANK[f.severity] >= 3);

  return state.assets.map(a => {
    const fs = findingsOf(a.id);
    const svcs = state.services.filter(s => s.asset_id === a.id);
    const out = state.relationships.filter(r => r.source_id === a.id);
    const inc = state.relationships.filter(r => r.target_id === a.id);
    const reasons = [];

    // 1. Vulnerability score (max 50)
    const sevCounts = Object.fromEntries(SEVERITIES.map(s => [s, fs.filter(f => f.severity === s).length]));
    const vulnRaw = fs.reduce((n, f) => n + (SEVERITY_POINTS[f.severity] || 0), 0);
    const vuln = Math.min(50, vulnRaw);
    for (const s of ['critical', 'high', 'medium', 'low']) {
      if (sevCounts[s]) {
        reasons.push({
          factor: 'vulnerability',
          points: sevCounts[s] * SEVERITY_POINTS[s],
          text: `${plural(sevCounts[s], `${s}-severity finding`)}: +${sevCounts[s] * SEVERITY_POINTS[s]} pts (${SEVERITY_POINTS[s]} each)`
        });
      }
    }
    if (vulnRaw > 50) {
      reasons.push({ factor: 'vulnerability', points: -(vulnRaw - 50), text: `Vulnerability subtotal capped at 50 pts (raw: ${vulnRaw} pts)` });
    } else if (vuln === 0) {
      reasons.push({ factor: 'vulnerability', points: 0, text: 'No active vulnerability findings: 0 pts' });
    }

    // 2. Exposure score (max 20)
    const risky = svcs.filter(s => HIGH_RISK_PORTS[s.port]);
    const expBase = svcs.length * 2;
    const expBonus = risky.length * 3;
    const exposureRaw = expBase + expBonus;
    const exposure = Math.min(20, exposureRaw);
    if (svcs.length) {
      reasons.push({ factor: 'exposure', points: expBase, text: `${plural(svcs.length, 'open service')}: +${expBase} pts (+2 per port)` });
    }
    if (risky.length) {
      reasons.push({
        factor: 'exposure',
        points: expBonus,
        text: `High-risk service bonus (${risky.map(s => `${HIGH_RISK_PORTS[s.port]}/${s.port}`).join(', ')}): +${expBonus} pts (+3 each)`
      });
    }
    if (exposureRaw > 20) {
      reasons.push({ factor: 'exposure', points: -(exposureRaw - 20), text: `Exposure subtotal capped at 20 pts (raw: ${exposureRaw} pts)` });
    } else if (exposure === 0) {
      reasons.push({ factor: 'exposure', points: 0, text: 'No open network services: 0 pts' });
    }

    // 3. Relationship risk (max 30)
    const neighbours = new Set([...out.map(r => r.target_id), ...inc.map(r => r.source_id)]);
    const connectivity = Math.min(10, neighbours.size * 2);
    if (neighbours.size) {
      reasons.push({ factor: 'relationship', points: connectivity, text: `Connected to ${plural(neighbours.size, 'neighbour asset')}: +${connectivity} pts (+2 each, max 10)` });
    }

    const riskyUpstream = [...new Set(inc.map(r => r.source_id))].filter(id => {
      const n = byId.get(id); return n && (n.is_entry_point || isVulnerable(id));
    });
    const upstream = Math.min(10, riskyUpstream.length * 5);
    if (riskyUpstream.length) {
      reasons.push({
        factor: 'relationship',
        points: upstream,
        text: `Upstream untrusted / vulnerable neighbour (${riskyUpstream.map(id => byId.get(id)?.name).filter(Boolean).join(', ')}): +${upstream} pts (+5 each, max 10)`
      });
    }

    const importantDownstream = out.map(r => byId.get(r.target_id))
      .filter(t => t && ['high', 'critical'].includes(t.criticality));
    const hasMediumPlus = fs.some(f => SEV_RANK[f.severity] >= 2);
    const downstream = hasMediumPlus && importantDownstream.length ? 10 : 0;
    if (downstream) {
      reasons.push({
        factor: 'relationship',
        points: 10,
        text: `Vulnerable asset connects downstream to ${importantDownstream[0].criticality} asset ${importantDownstream[0].name}: +10 pts`
      });
    }

    const relRaw = connectivity + upstream + downstream;
    const relationship = Math.min(30, relRaw);
    if (relRaw > 30) {
      reasons.push({ factor: 'relationship', points: -(relRaw - 30), text: `Relationship subtotal capped at 30 pts (raw: ${relRaw} pts)` });
    } else if (relationship === 0) {
      reasons.push({ factor: 'relationship', points: 0, text: 'No relational lateral risk factors: 0 pts' });
    }

    const base = vuln + exposure + relationship;
    const multiplier = CRITICALITY_MULTIPLIER[a.criticality] || 1.0;
    const score = Math.min(100, Math.round(base * multiplier));
    reasons.push({
      factor: 'summary',
      points: score,
      text: `Formula: (Vuln ${vuln} + Exposure ${exposure} + Relationship ${relationship}) = Base ${base} × Criticality [${a.criticality.toUpperCase()}] (x${multiplier}) = ${score}/100`
    });

    return {
      id: a.id, name: a.name, ip: a.ip, criticality: a.criticality, type: a.type,
      is_entry_point: !!a.is_entry_point,
      score, level: levelOf(score),
      breakdown: {
        vulnerability: vuln,
        vulnRaw,
        vulnCapped: vulnRaw > 50,
        exposure,
        exposureRaw,
        exposureCapped: exposureRaw > 20,
        relationship,
        relRaw,
        relCapped: relRaw > 30,
        base,
        multiplier,
        score
      },
      activeFindings: fs.length, severityCounts: sevCounts,
      services: svcs.length, connections: neighbours.size,
      reasons,
    };
  });
}

const NODE_POINTS = { critical: 25, high: 18, medium: 8, low: 2, info: 0 };
const TARGET_POINTS = { low: 5, medium: 10, high: 20, critical: 30 };

/**
 * Risk Path Analysis.
 * A risk path is NOT a single vulnerability. It is a chain of modelled relationships
 * from an entry point (low-trust asset) to an important asset (high/critical), where
 * at least one asset after the entry point carries an active security finding.
 */
function findRiskPaths(state, scores) {
  const byId = new Map(state.assets.map(a => [a.id, a]));
  const scoreById = new Map(scores.map(s => [s.id, s]));
  const adj = new Map();
  for (const r of state.relationships) {
    if (!adj.has(r.source_id)) adj.set(r.source_id, []);
    adj.get(r.source_id).push(r);
  }
  const worstFinding = id => state.findings
    .filter(f => f.asset_id === id)
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity])[0];

  let entries = state.assets.filter(a => a.is_entry_point);
  if (!entries.length) entries = state.assets.filter(a => a.criticality === 'low' || a.type === 'endpoint');

  const paths = [];
  const MAX_DEPTH = 6, MAX_PATHS = 300;

  for (const entry of entries) {
    const stack = [{ node: entry.id, nodes: [entry.id], edges: [] }];
    while (stack.length && paths.length < MAX_PATHS) {
      const cur = stack.pop();
      for (const edge of adj.get(cur.node) || []) {
        if (cur.nodes.includes(edge.target_id)) continue;
        const next = { node: edge.target_id, nodes: [...cur.nodes, edge.target_id], edges: [...cur.edges, edge] };
        const target = byId.get(edge.target_id);
        if (target && ['high', 'critical'].includes(target.criticality)) {
          const p = evaluatePath(next, byId, worstFinding, state);
          if (p) paths.push(p);
        }
        if (next.edges.length < MAX_DEPTH) stack.push(next);
      }
    }
  }

  // Score & explain
  for (const p of paths) {
    p.level = levelOf(p.score);
    p.explanation = explainPath(p, byId);
  }
  paths.sort((a, b) => b.score - a.score);
  return paths;
}

function evaluatePath(cur, byId, worstFinding, state) {
  const after = cur.nodes.slice(1);
  const vulnerableHops = after
    .map(id => ({ id, finding: worstFinding(id) }))
    .filter(h => h.finding && SEV_RANK[h.finding.severity] >= 2);
  if (!vulnerableHops.length) return null;

  const source = byId.get(cur.nodes[0]);
  const target = byId.get(cur.nodes[cur.nodes.length - 1]);
  let score = TARGET_POINTS[target.criticality] || 10;
  for (const h of vulnerableHops) score += NODE_POINTS[h.finding.severity];
  if (source.is_entry_point) score += 10;
  score -= 5 * (cur.edges.length - 1);
  score = Math.max(0, Math.min(100, score));

  return {
    key: cur.edges.map(e => e.id).join('-'),
    nodes: cur.nodes,
    edges: cur.edges.map(e => e.id),
    edgeTypes: cur.edges.map(e => e.type),
    names: cur.nodes.map(id => byId.get(id).name),
    vulnerableHops: vulnerableHops.map(h => ({
      assetId: h.id, asset: byId.get(h.id).name,
      findingId: h.finding.id, finding: h.finding.title, severity: h.finding.severity,
      count: state.findings.filter(f => f.asset_id === h.id).length,
    })),
    targetCriticality: target.criticality,
    score,
  };
}

function explainPath(p, byId) {
  const src = byId.get(p.nodes[0]);
  const tgt = byId.get(p.nodes[p.nodes.length - 1]);
  const parts = [];
  parts.push(`${src.name} is ${src.is_entry_point ? 'an entry point (low-trust zone)' : 'a low-criticality starting asset'}.`);
  for (let i = 0; i < p.edges.length; i++) {
    const to = byId.get(p.nodes[i + 1]);
    const hop = p.vulnerableHops.find(h => h.assetId === to.id);
    let s = `It has ${p.edgeTypes[i].toLowerCase()} to ${to.name}`;
    if (hop) s += `, which has ${plural(hop.count, 'active finding')} including "${hop.finding}" (${hop.severity.toUpperCase()})`;
    parts.push(s + '.');
  }
  parts.push(`${tgt.name} is rated ${tgt.criticality.toUpperCase()} criticality, so this chain of relationships is a higher-priority area for security review.`);
  parts.push('This is a prioritisation scenario based on modelled relationships, not proof of exploitability.');
  return parts.join(' ');
}

/** Main entry: compute the whole risk model for a (possibly simulated) state. */
export function computeModel(data, scenario = {}) {
  const state = effectiveState(data, scenario);
  const assets = scoreAssets(state);
  const paths = findRiskPaths(state, assets);
  let wSum = 0, wTot = 0;
  for (const a of assets) { const w = CRITICALITY_WEIGHT[a.criticality] || 2; wSum += a.score * w; wTot += w; }
  const score = wTot ? Math.round(wSum / wTot) : 0;
  const assetById = new Map(data.assets.map(a => [a.id, a]));
  const findings = state.findings.map(f => ({
    id: f.id, priority: priorityOf(f.severity, assetById.get(f.asset_id)?.criticality),
  }));
  const reason = state.assets.length <= 1
    ? 'Single asset workspace: Multi-hop risk paths require at least two interconnected assets.'
    : state.relationships.length === 0
      ? 'No network relationships mapped: Multi-hop attack paths require defined access or trust connections between assets.'
      : 'No vulnerable intermediate hops currently bridge entry points to critical targets.';

  return {
    overall: {
      score, level: levelOf(score),
      assets: assets.length,
      vulnerabilities: state.findings.length,
      highRiskAssets: assets.filter(a => ['high', 'critical'].includes(a.level)).length,
      riskyPaths: paths.length,
      openServices: state.services.length,
      severity: Object.fromEntries(SEVERITIES.map(s => [s, state.findings.filter(f => f.severity === s).length])),
    },
    pathContext: {
      totalAssets: state.assets.length,
      totalRelationships: state.relationships.length,
      pathsDetected: paths.length,
      explanation: reason
    },
    assets, paths, findingPriority: Object.fromEntries(findings.map(f => [f.id, f.priority])),
    activeFindingIds: state.findings.map(f => f.id),
    activeRelationshipIds: state.relationships.map(r => r.id),
    activeServiceIds: state.services.map(s => s.id),
  };
}

/**
 * "What should I fix first?" — evaluates every candidate action
 * (fix finding / block service / restrict relationship) and ranks them by how much
 * they reduce the overall score and the number of risky paths.
 */
export function recommendActions(data, baseScenario = {}, limit = 6) {
  const base = computeModel(data, baseScenario);
  const clone = s => ({
    fixedFindings: new Set(s.fixedFindings || []),
    blockedRels: new Set(s.blockedRels || []),
    closedServices: new Set(s.closedServices || []),
  });
  const candidates = [];
  const assetName = id => data.assets.find(a => a.id === id)?.name || 'Unknown';

  // 1. Evaluate fixing individual findings
  for (const fid of base.activeFindingIds) {
    const f = data.findings.find(x => x.id === fid);
    if (!f || SEV_RANK[f.severity] < 1) continue;
    const sc = clone(baseScenario); sc.fixedFindings.add(fid);
    const m = computeModel(data, sc);
    candidates.push({
      kind: 'finding', refId: fid, label: `Fix "${f.title}" on ${assetName(f.asset_id)}`,
      severity: f.severity, scoreDrop: base.overall.score - m.overall.score, pathsRemoved: base.overall.riskyPaths - m.overall.riskyPaths
    });
  }

  // 2. Evaluate blocking / disabling services
  const closed = new Set(baseScenario.closedServices || []);
  for (const sid of (base.activeServiceIds || [])) {
    const s = data.services.find(x => x.id === sid);
    if (!s || closed.has(s.id)) continue;
    const isRisky = HIGH_RISK_PORTS[s.port];
    const sc = clone(baseScenario);
    sc.closedServices.add(sid);
    const m = computeModel(data, sc);
    const drop = base.overall.score - m.overall.score;
    const pathsRemoved = base.overall.riskyPaths - m.overall.riskyPaths;
    if (drop > 0 || pathsRemoved > 0 || isRisky) {
      candidates.push({
        kind: 'service',
        refId: sid,
        label: `Block/Disable ${s.port}/${s.service} on ${assetName(s.asset_id)}`,
        severity: isRisky ? 'high' : 'medium',
        scoreDrop: drop,
        pathsRemoved
      });
    }
  }

  // 3. Evaluate restricting network relationships
  for (const rid of base.activeRelationshipIds) {
    const r = data.relationships.find(x => x.id === rid);
    if (!r) continue;
    const sc = clone(baseScenario); sc.blockedRels.add(rid);
    const m = computeModel(data, sc);
    const removed = base.overall.riskyPaths - m.overall.riskyPaths;
    if (removed <= 0) continue;
    candidates.push({
      kind: 'relationship', refId: rid, label: `Restrict ${r.type}: ${assetName(r.source_id)} → ${assetName(r.target_id)}`,
      severity: 'medium', scoreDrop: base.overall.score - m.overall.score, pathsRemoved: removed
    });
  }

  candidates.sort((a, b) => (b.pathsRemoved * 3 + b.scoreDrop) - (a.pathsRemoved * 3 + a.scoreDrop));
  return candidates.slice(0, limit);
}
