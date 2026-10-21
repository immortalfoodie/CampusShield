/**
 * CampusShield — Log Analysis Service (Security Layer)
 * 
 * Offline log analysis for controlled laboratory environments.
 * Analyzes common log formats:
 * - Linux auth.log / secure (SSH failed logins, sudo, invalid users)
 * - Web server logs (Apache/Nginx access logs for 4xx/5xx spikes, SQLi / path traversal heuristics)
 * - Basic application event logs
 */

const IPV4_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

export function analyzeLogs(content, filename = 'uploaded.log') {
  const lines = String(content || '').split(/\r?\n/).slice(0, 50000);
  const eventGroups = new Map(); // key -> { ip, event, count, samples, risk, description }
  const ipActivity = new Map();  // ip -> { count, failedLogins, webErrors, requests }
  let totalLines = 0;
  let parsedEvents = 0;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;
    totalLines++;

    const ipMatch = line.match(IPV4_REGEX);
    const ip = ipMatch ? ipMatch[0] : 'Internal / System';

    let eventType = null;
    let risk = 'low';
    let detail = '';

    // 1. SSH / Auth log heuristics
    if (/failed\s+password|authentication\s+failure/i.test(line)) {
      eventType = 'Failed SSH / System Login';
      risk = 'high';
      detail = 'Repeated authentication failure indicating potential brute-force or credential stuffing.';
    } else if (/invalid\s+user/i.test(line)) {
      eventType = 'Login Attempt with Invalid Username';
      risk = 'medium';
      detail = 'Attempted login with non-existent system account.';
    } else if (/accepted\s+(?:password|publickey)/i.test(line)) {
      eventType = 'Successful Login';
      risk = 'info';
      detail = 'Legitimate or verified authentication event.';
    } else if (/sudo:\s*auth\s+failure/i.test(line)) {
      eventType = 'Sudo Authentication Failure';
      risk = 'high';
      detail = 'Unauthorized privilege escalation attempt.';
    }
    // 2. Web Access / Error log heuristics
    else if (/union\s+select|select\s+.*\s+from|or\s+1\s*=\s*1|information_schema/i.test(line)) {
      eventType = 'Potential SQL Injection Pattern';
      risk = 'critical';
      detail = 'HTTP request payload matches common SQL injection patterns.';
    } else if (/\.\.\/|\.\.\\|etc\/passwd|win\.ini|boot\.ini/i.test(line)) {
      eventType = 'Directory Traversal Attempt';
      risk = 'high';
      detail = 'Path manipulation characters detected in URI path.';
    } else if (/<script|javascript:|alert\(|onerror=/i.test(line)) {
      eventType = 'Potential Cross-Site Scripting Pattern';
      risk = 'medium';
      detail = 'HTML/script tags observed in web server request URI.';
    } else if (/\b(401|403)\b/.test(line)) {
      eventType = 'HTTP 401/403 Forbidden Access';
      risk = 'medium';
      detail = 'Client attempted to access restricted resources without valid authorization.';
    } else if (/\b(500|502|503|504)\b/.test(line)) {
      eventType = 'HTTP 5xx Server Error';
      risk = 'low';
      detail = 'Web application internal error or backend service crash.';
    } else if (/\b(404)\b/.test(line)) {
      eventType = 'HTTP 404 Resource Not Found';
      risk = 'low';
      detail = 'Probing for files or pages that do not exist.';
    } else if (/\b(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+\S+/i.test(line)) {
      eventType = 'Standard HTTP Request';
      risk = 'info';
      detail = 'Normal web application traffic.';
    }

    if (eventType) {
      parsedEvents++;
      const key = `${ip}::${eventType}`;
      if (!eventGroups.has(key)) {
        eventGroups.set(key, {
          ip,
          event: eventType,
          count: 0,
          risk,
          description: detail,
          samples: []
        });
      }
      const group = eventGroups.get(key);
      group.count++;
      if (group.samples.length < 3) {
        group.samples.push(line.slice(0, 260));
      }

      // Update IP activity metrics
      if (!ipActivity.has(ip)) {
        ipActivity.set(ip, { ip, totalEvents: 0, failedLogins: 0, suspiciousQueries: 0 });
      }
      const ipStats = ipActivity.get(ip);
      ipStats.totalEvents++;
      if (eventType.includes('Failed') || eventType.includes('Invalid')) ipStats.failedLogins++;
      if (['critical', 'high'].includes(risk)) ipStats.suspiciousQueries++;
    }
  }

  // Adjust risk ratings based on thresholds
  const findings = [...eventGroups.values()].map(g => {
    let finalRisk = g.risk;
    if (g.event === 'Failed SSH / System Login' && g.count >= 10) finalRisk = 'critical';
    else if (g.event === 'Failed SSH / System Login' && g.count >= 5) finalRisk = 'high';
    else if (g.event === 'HTTP 401/403 Forbidden Access' && g.count >= 20) finalRisk = 'high';
    else if (g.event === 'HTTP 404 Resource Not Found' && g.count >= 50) finalRisk = 'medium';
    return { ...g, risk: finalRisk };
  });

  findings.sort((a, b) => {
    const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    return (rank[b.risk] - rank[a.risk]) || (b.count - a.count);
  });

  const suspiciousIps = [...ipActivity.values()]
    .filter(stat => stat.failedLogins >= 3 || stat.suspiciousQueries >= 1)
    .sort((a, b) => (b.failedLogins + b.suspiciousQueries * 2) - (a.failedLogins + a.suspiciousQueries * 2));

  return {
    filename,
    totalLines,
    parsedEvents,
    findings: findings.slice(0, 100),
    suspiciousIps: suspiciousIps.slice(0, 10),
    summary: {
      criticalCount: findings.filter(f => f.risk === 'critical').length,
      highCount: findings.filter(f => f.risk === 'high').length,
      mediumCount: findings.filter(f => f.risk === 'medium').length,
      lowCount: findings.filter(f => f.risk === 'low').length,
    }
  };
}
