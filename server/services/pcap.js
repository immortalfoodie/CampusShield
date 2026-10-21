/**
 * CampusShield — Offline packet capture (PCAP / PCAPNG) analysis.
 * Educational traffic summary of an AUTHORIZED capture file. No live sniffing.
 * Credentials are never extracted or displayed — only counted as indicators.
 */

const APP_PORTS = {
  20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3',
  123: 'NTP', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
  465: 'SMTPS', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
  5900: 'VNC', 8080: 'HTTP', 8443: 'HTTPS', 5353: 'mDNS', 1900: 'SSDP',
};
const INSECURE = {
  HTTP: 'Unencrypted web traffic', FTP: 'Cleartext file transfer & credentials', Telnet: 'Cleartext remote shell',
  POP3: 'Cleartext mail retrieval', IMAP: 'Cleartext mail retrieval', SMTP: 'Possibly unencrypted mail', SNMP: 'Cleartext community strings',
  'FTP-DATA': 'Cleartext file transfer', LDAP: 'Possibly unencrypted directory queries', VNC: 'Often weakly encrypted remote desktop',
};

function readHeader(buf) {
  if (buf.length < 24) throw new Error('File too small to be a capture.');
  const magic = buf.readUInt32LE(0);
  if (magic === 0x0a0d0d0a) return { format: 'pcapng' };
  const map = { 0xa1b2c3d4: ['LE', 1e6], 0xd4c3b2a1: ['BE', 1e6], 0xa1b23c4d: ['LE', 1e9], 0x4d3cb2a1: ['BE', 1e9] };
  if (!map[magic]) throw new Error('Unrecognised file. Upload a .pcap or .pcapng capture (e.g. saved from Wireshark/tcpdump).');
  const [endian, tsDiv] = map[magic];
  const linktype = endian === 'LE' ? buf.readUInt32LE(20) : buf.readUInt32BE(20);
  return { format: 'pcap', endian, tsDiv, linktype };
}

/** Yields { ts, linktype, data } for every packet in the file. */
function* packets(buf) {
  const h = readHeader(buf);
  if (h.format === 'pcap') {
    const r32 = o => h.endian === 'LE' ? buf.readUInt32LE(o) : buf.readUInt32BE(o);
    let off = 24;
    while (off + 16 <= buf.length) {
      const ts = r32(off) + r32(off + 4) / h.tsDiv;
      const incl = r32(off + 8);
      off += 16;
      if (incl > 262144 || off + incl > buf.length) break;
      yield { ts, linktype: h.linktype, data: buf.subarray(off, off + incl) };
      off += incl;
    }
    return;
  }
  // PCAPNG: blocks. Section header decides endianness; interfaces give link types.
  let off = 0, le = true;
  const ifaces = [];
  while (off + 12 <= buf.length) {
    let type = buf.readUInt32LE(off);
    if (type === 0x0a0d0d0a) {
      le = buf.readUInt32LE(off + 8) === 0x1a2b3c4d;
      ifaces.length = 0;
    }
    const r32 = o => le ? buf.readUInt32LE(o) : buf.readUInt32BE(o);
    const r16 = o => le ? buf.readUInt16LE(o) : buf.readUInt16BE(o);
    type = r32(off);
    const len = r32(off + 4);
    if (len < 12 || off + len > buf.length) break;
    if (type === 1) ifaces.push({ linktype: r16(off + 8), tsDiv: 1e6 });
    else if (type === 6) {
      const ifc = ifaces[r32(off + 8)] || { linktype: 1, tsDiv: 1e6 };
      const ts = (r32(off + 12) * 4294967296 + r32(off + 16)) / ifc.tsDiv;
      const capLen = r32(off + 20);
      yield { ts, linktype: ifc.linktype, data: buf.subarray(off + 28, off + 28 + capLen) };
    } else if (type === 3) {
      const ifc = ifaces[0] || { linktype: 1 };
      yield { ts: 0, linktype: ifc.linktype, data: buf.subarray(off + 12, off + len - 4) };
    }
    off += len;
  }
}

/** Return offset of the IP header and the ethertype, depending on the link type. */
function linkLayer(linktype, d) {
  if (linktype === 1) { // Ethernet
    if (d.length < 14) return null;
    let et = d.readUInt16BE(12), pos = 14;
    while ((et === 0x8100 || et === 0x88a8) && d.length >= pos + 4) { et = d.readUInt16BE(pos + 2); pos += 4; }
    return { et, pos };
  }
  if (linktype === 101 || linktype === 12 || linktype === 14) { const v = d[0] >> 4; return { et: v === 6 ? 0x86dd : 0x0800, pos: 0 }; }
  if (linktype === 113) return d.length >= 16 ? { et: d.readUInt16BE(14), pos: 16 } : null; // Linux SLL
  if (linktype === 276) return d.length >= 20 ? { et: d.readUInt16BE(0), pos: 20 } : null;   // Linux SLL2
  if (linktype === 0 || linktype === 108) { const v = d[4] >> 4; return { et: v === 6 ? 0x86dd : 0x0800, pos: 4 }; } // BSD loopback
  return null;
}

function ipv6Str(b) {
  const parts = [];
  for (let i = 0; i < 16; i += 2) parts.push(b.readUInt16BE(i).toString(16));
  return parts.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
}

export function analyzePcap(buf) {
  let count = 0, bytes = 0, first = null, last = null, nonIp = 0;
  const transport = {}, apps = {}, flows = new Map(), talkers = {};
  const syns = new Map(); // src>dst -> Set(dport)
  const creds = { ftp: 0, httpBasic: 0, httpForm: 0, telnet: 0 };
  const unsupported = new Set();

  for (const p of packets(buf)) {
    count++; bytes += p.data.length;
    if (p.ts) { first = first == null ? p.ts : Math.min(first, p.ts); last = last == null ? p.ts : Math.max(last, p.ts); }
    const l = linkLayer(p.linktype, p.data);
    if (!l) { unsupported.add(p.linktype); nonIp++; continue; }
    const d = p.data; let pos = l.pos, proto, src, dst, ipEnd;
    if (l.et === 0x0800 && d.length >= pos + 20) {
      const ihl = (d[pos] & 15) * 4;
      proto = d[pos + 9];
      src = [...d.subarray(pos + 12, pos + 16)].join('.');
      dst = [...d.subarray(pos + 16, pos + 20)].join('.');
      ipEnd = Math.min(d.length, pos + d.readUInt16BE(pos + 2));
      pos += ihl;
    } else if (l.et === 0x86dd && d.length >= pos + 40) {
      proto = d[pos + 6];
      src = ipv6Str(d.subarray(pos + 8, pos + 24));
      dst = ipv6Str(d.subarray(pos + 24, pos + 40));
      ipEnd = d.length; pos += 40;
    } else { nonIp++; transport.ARP = (transport.ARP || 0) + (l.et === 0x0806 ? 1 : 0); continue; }

    const tName = { 6: 'TCP', 17: 'UDP', 1: 'ICMP', 58: 'ICMPv6' }[proto] || `IP-${proto}`;
    transport[tName] = (transport[tName] || 0) + 1;
    talkers[src] = (talkers[src] || 0) + 1;
    let sp = 0, dp = 0, payload = null;
    if ((proto === 6 || proto === 17) && d.length >= pos + 4) {
      sp = d.readUInt16BE(pos); dp = d.readUInt16BE(pos + 2);
      if (proto === 6 && d.length >= pos + 14) {
        const flags = d[pos + 13];
        const off = (d[pos + 12] >> 4) * 4;
        payload = d.subarray(pos + off, ipEnd);
        if ((flags & 0x12) === 0x02) { // SYN without ACK: connection attempt
          const k = `${src}>${dst}`;
          if (!syns.has(k)) syns.set(k, new Set());
          syns.get(k).add(dp);
        }
      } else if (proto === 17) payload = d.subarray(pos + 8, ipEnd);
    }
    const app = APP_PORTS[dp] || APP_PORTS[sp] || (proto === 6 || proto === 17 ? `${tName} other` : tName);
    apps[app] = apps[app] || { packets: 0, bytes: 0 };
    apps[app].packets++; apps[app].bytes += p.data.length;

    const key = `${src}|${sp}|${dst}|${dp}|${tName}`;
    const f = flows.get(key) || { source: src, sourcePort: sp, destination: dst, destinationPort: dp, protocol: tName, app, packets: 0, bytes: 0 };
    f.packets++; f.bytes += p.data.length; flows.set(key, f);

    if (payload && payload.length) {
      const text = payload.subarray(0, 512).toString('latin1');
      if ((dp === 21) && /^PASS /m.test(text)) creds.ftp++;
      if ((dp === 80 || dp === 8080) && /^Authorization:\s*Basic /mi.test(text)) creds.httpBasic++;
      if ((dp === 80 || dp === 8080) && /^POST /.test(text) && /(pass(word)?|pwd)=/i.test(payload.toString('latin1'))) creds.httpForm++;
      if (dp === 23 && /password/i.test(text)) creds.telnet++;
    }
  }
  if (!count) throw new Error('No packets could be read from the file.');

  const protocols = Object.entries(apps).map(([name, v]) => ({ name, ...v, risk: INSECURE[name] ? 'review' : 'normal', note: INSECURE[name] || '' }))
    .sort((a, b) => b.packets - a.packets);
  const alerts = [];
  for (const pr of protocols.filter(x => x.risk === 'review'))
    alerts.push({ severity: ['Telnet', 'FTP'].includes(pr.name) ? 'high' : 'medium', title: `Insecure protocol in use: ${pr.name}`, detail: `${pr.packets} packets — ${pr.note}.` });
  const credTotal = creds.ftp + creds.httpBasic + creds.httpForm + creds.telnet;
  if (credTotal) alerts.push({ severity: 'high', title: 'Cleartext credential indicators observed',
    detail: `FTP PASS: ${creds.ftp}, HTTP Basic auth: ${creds.httpBasic}, HTTP form logins: ${creds.httpForm}, Telnet password prompts: ${creds.telnet}. Values were NOT extracted.` });
  for (const [k, ports] of syns) if (ports.size >= 15) {
    const [s, t] = k.split('>');
    alerts.push({ severity: 'medium', title: 'Possible port scan', detail: `${s} sent connection attempts to ${ports.size} different ports on ${t}.` });
  }
  if (unsupported.size) alerts.push({ severity: 'info', title: 'Some packets used an unsupported link type', detail: `Link types: ${[...unsupported].join(', ')}` });

  return {
    packetCount: count, bytes, nonIp,
    durationSec: first != null && last != null ? Math.round((last - first) * 100) / 100 : null,
    transport: Object.entries(transport).filter(([, v]) => v).map(([name, packets]) => ({ name, packets })).sort((a, b) => b.packets - a.packets),
    protocols, alerts,
    credentialIndicators: creds,
    topTalkers: Object.entries(talkers).map(([ip, packets]) => ({ ip, packets })).sort((a, b) => b.packets - a.packets).slice(0, 10),
    flows: [...flows.values()].sort((a, b) => b.packets - a.packets).slice(0, 200),
  };
}
