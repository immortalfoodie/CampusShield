/**
 * CampusShield — Scope guard.
 * Educational laboratory guardrail: scans are strictly allowed against loopback,
 * private (RFC 1918), link-local IPv4, supported IPv6 lab ranges (loopback ::1,
 * link-local fe80::/10, ULA fc00::/7), small private CIDRs (/24 or smaller),
 * or authorized lab hostnames that resolve strictly to private/loopback addresses.
 */
import dns from 'node:dns/promises';
import net from 'node:net';

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;

export function isPrivateIPv4(ip) {
  if (!IPV4.test(ip)) return false;
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 10 ||                       // 10.0.0.0/8
    a === 127 ||                      // 127.0.0.0/8 (Loopback)
    (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
    (a === 192 && b === 168) ||      // 192.168.0.0/16
    (a === 169 && b === 254)         // 169.254.0.0/16 (Link-local)
  );
}

export function isPrivateIPv6(ip) {
  if (net.isIPv6(ip) !== true) return false;
  const normalized = ip.toLowerCase().trim();
  // Loopback (::1)
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1' || /^0*(:0*){1,7}1$/.test(normalized)) return true;
  // Link-local unicast (fe80::/10)
  if (/^fe[89ab][0-9a-f]{0,2}:/i.test(normalized)) return true;
  // Unique Local Addresses (fc00::/7 -> fc00... to fdff...)
  if (/^f[cd][0-9a-f]{0,2}:/i.test(normalized)) return true;
  return false;
}

export function isAllowedLabAddress(addr) {
  const v = net.isIP(addr);
  if (v === 4) return isPrivateIPv4(addr);
  if (v === 6) return isPrivateIPv6(addr);
  return false;
}

export function ipToInt(ip) { return ip.split('.').reduce((n, o) => (n << 8) + Number(o), 0) >>> 0; }
export function intToIp(n) { return [24, 16, 8, 0].map(s => (n >>> s) & 255).join('.'); }

/**
 * Validate an address string. Returns { ok, kind, error, address, resolved? }.
 * kind: 'ip' | 'ipv6' | 'cidr' | 'hostname'
 */
export async function validateScope(input) {
  const raw = String(input || '').trim();
  if (!raw) return { ok: false, error: 'Enter an IP address, CIDR range or hostname.' };
  const address = raw.toLowerCase();

  // 1. CIDR handling
  if (address.includes('/')) {
    const [ip, bitsRaw] = address.split('/');
    const bits = Number(bitsRaw);
    if (!IPV4.test(ip) || !Number.isInteger(bits)) {
      return { ok: false, error: 'Invalid CIDR range. Example: 192.168.56.0/24' };
    }
    if (bits < 24 || bits > 32) {
      return { ok: false, error: 'For educational lab safety, CIDR ranges are limited to /24 (256 addresses) or smaller.' };
    }
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    const network = ipToInt(ip) & mask;
    const broadcast = (network | (~mask >>> 0)) >>> 0;
    if (!isPrivateIPv4(intToIp(network)) || !isPrivateIPv4(intToIp(broadcast))) {
      return { ok: false, error: 'Only private, loopback or link-local lab ranges may be scanned.' };
    }
    return { ok: true, kind: 'cidr', address: `${intToIp(network)}/${bits}` };
  }

  // 2. IPv4 single host
  if (net.isIPv4(address)) {
    if (!isPrivateIPv4(address)) {
      return { ok: false, error: `Public IP address (${address}) is blocked. CampusShield strictly enforces private laboratory ranges.` };
    }
    return { ok: true, kind: 'ip', address };
  }

  // 3. IPv6 single host
  if (net.isIPv6(address)) {
    if (!isPrivateIPv6(address)) {
      return { ok: false, error: `Public IPv6 address (${address}) is blocked. Only IPv6 loopback (::1), link-local (fe80::/10) or ULA (fc00::/7) are allowed.` };
    }
    return { ok: true, kind: 'ipv6', address };
  }

  // 4. Localhost alias
  if (address === 'localhost') {
    return { ok: true, kind: 'hostname', address, resolved: ['127.0.0.1'] };
  }

  // 5. Hostname lookup
  if (!HOSTNAME.test(address)) {
    return { ok: false, error: 'Invalid target address or hostname format.' };
  }

  try {
    const res = await dns.lookup(address, { all: true });
    const ips = res.map(r => r.address);
    if (!ips.length) return { ok: false, error: 'Hostname did not resolve to an address.' };
    const invalidIps = ips.filter(ip => !isAllowedLabAddress(ip));
    if (invalidIps.length > 0) {
      return { ok: false, error: `Hostname resolves to non-private address (${invalidIps.join(', ')}). Blocked by policy.` };
    }
    return { ok: true, kind: 'hostname', address, resolved: ips };
  } catch {
    return { ok: false, error: `Hostname "${address}" could not be resolved. Please verify DNS or use the lab IP address.` };
  }
}
