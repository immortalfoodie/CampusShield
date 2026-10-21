/**
 * CampusShield — Sample generator
 * Creates sample PCAP captures, logs, and scanner outputs in samples/ for viva demonstrations.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SAMPLES_DIR = path.resolve(__dirname, '..', 'samples');
fs.mkdirSync(SAMPLES_DIR, { recursive: true });

// -------------------------------------------------------------
// 1. SAMPLE AUTH & ACCESS LOGS
// -------------------------------------------------------------
const authLog = `
Oct 15 14:02:11 labsrv sshd[14221]: Failed password for invalid user admin from 192.168.56.20 port 49152 ssh2
Oct 15 14:02:14 labsrv sshd[14223]: Failed password for invalid user admin from 192.168.56.20 port 49154 ssh2
Oct 15 14:02:17 labsrv sshd[14225]: Failed password for invalid user root from 192.168.56.20 port 49156 ssh2
Oct 15 14:02:20 labsrv sshd[14227]: Failed password for invalid user root from 192.168.56.20 port 49158 ssh2
Oct 15 14:02:23 labsrv sshd[14229]: Failed password for student from 192.168.56.20 port 49160 ssh2
Oct 15 14:02:26 labsrv sshd[14231]: Failed password for student from 192.168.56.20 port 49162 ssh2
Oct 15 14:02:29 labsrv sshd[14233]: Failed password for student from 192.168.56.20 port 49164 ssh2
Oct 15 14:02:32 labsrv sshd[14235]: Failed password for student from 192.168.56.20 port 49166 ssh2
Oct 15 14:02:35 labsrv sshd[14237]: Failed password for student from 192.168.56.20 port 49168 ssh2
Oct 15 14:02:38 labsrv sshd[14239]: Failed password for student from 192.168.56.20 port 49170 ssh2
Oct 15 14:02:41 labsrv sshd[14241]: Failed password for student from 192.168.56.20 port 49172 ssh2
Oct 15 14:02:44 labsrv sshd[14243]: Failed password for student from 192.168.56.20 port 49174 ssh2
Oct 15 14:05:01 labsrv sudo:   student : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/student ; USER=root ; COMMAND=/bin/bash
Oct 15 14:10:12 labsrv sshd[14300]: Accepted publickey for faculty from 192.168.56.31 port 51234 ssh2
`.trim();

const accessLog = `
192.168.56.20 - - [15/Oct/2026:14:15:10 +0530] "GET /index.php HTTP/1.1" 200 4521
192.168.56.20 - - [15/Oct/2026:14:15:15 +0530] "POST /login.php HTTP/1.1" 302 240
192.168.56.20 - - [15/Oct/2026:14:15:30 +0530] "POST /login.php HTTP/1.1" 500 1204 "username=admin' OR 1=1--"
192.168.56.20 - - [15/Oct/2026:14:15:35 +0530] "POST /login.php HTTP/1.1" 500 1204 "username=admin' UNION SELECT null,username,password FROM users--"
192.168.56.20 - - [15/Oct/2026:14:16:01 +0530] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 403 342
192.168.56.20 - - [15/Oct/2026:14:16:15 +0530] "GET /search.php?q=<script>alert('xss')</script> HTTP/1.1" 200 3820
192.168.56.31 - - [15/Oct/2026:14:20:00 +0530] "GET /admin/marks.php HTTP/1.1" 200 8912
192.168.56.31 - - [15/Oct/2026:14:21:40 +0530] "POST /admin/update.php HTTP/1.1" 200 412
`.trim();

fs.writeFileSync(path.join(SAMPLES_DIR, 'sample_auth.log'), authLog);
fs.writeFileSync(path.join(SAMPLES_DIR, 'sample_access.log'), accessLog);

// -------------------------------------------------------------
// 2. SYNTHETIC ETHERNET PCAP FILE
// -------------------------------------------------------------
function makeSyntheticPcap() {
  const chunks = [];
  // PCAP Global Header (24 bytes)
  const gh = Buffer.alloc(24);
  gh.writeUInt32LE(0xa1b2c3d4, 0); // magic
  gh.writeUInt16LE(2, 4);          // v_major
  gh.writeUInt16LE(4, 6);          // v_minor
  gh.writeInt32LE(0, 8);           // thiszone
  gh.writeUInt32LE(0, 12);         // sigfigs
  gh.writeUInt32LE(65535, 16);     // snaplen
  gh.writeUInt32LE(1, 20);         // network (1 = Ethernet)
  chunks.push(gh);

  const addPacket = (srcIp, dstIp, srcPort, dstPort, protoNum, payloadStr, timeSec = 1729000000) => {
    const payload = Buffer.from(payloadStr, 'latin1');
    const ipTotalLen = 20 + 20 + payload.length; // IP (20) + TCP (20) + Payload
    const frameLen = 14 + ipTotalLen;            // Eth (14) + IP

    // Packet Header (16 bytes)
    const ph = Buffer.alloc(16);
    ph.writeUInt32LE(timeSec, 0);
    ph.writeUInt32LE(123456, 4);
    ph.writeUInt32LE(frameLen, 8);  // caplen
    ph.writeUInt32LE(frameLen, 12); // origlen

    // Ethernet Header (14 bytes)
    const eth = Buffer.alloc(14);
    // dst MAC (00:11:22:33:44:55), src MAC (66:77:88:99:aa:bb)
    eth[12] = 0x08; eth[13] = 0x00; // EtherType = IPv4

    // IPv4 Header (20 bytes)
    const ip = Buffer.alloc(20);
    ip[0] = 0x45; // IPv4, 5 words
    ip.writeUInt16BE(ipTotalLen, 2);
    ip[8] = 64;   // TTL
    ip[9] = protoNum; // 6 = TCP, 17 = UDP
    const sParts = srcIp.split('.').map(Number);
    const dParts = dstIp.split('.').map(Number);
    sParts.forEach((n, i) => ip[12 + i] = n);
    dParts.forEach((n, i) => ip[16 + i] = n);

    // TCP Header (20 bytes)
    const tcp = Buffer.alloc(20);
    tcp.writeUInt16BE(srcPort, 0);
    tcp.writeUInt16BE(dstPort, 2);
    tcp[12] = 0x50; // Data offset 5 (20 bytes)
    tcp[13] = 0x18; // PSH, ACK flags

    chunks.push(ph, eth, ip, tcp, payload);
  };

  // Populate realistic traffic flows
  // Flow 1: Cleartext HTTP traffic
  for (let i = 0; i < 15; i++) {
    addPacket('192.168.56.20', '192.168.56.101', 50000 + i, 80, 6, `GET /login.php HTTP/1.1\r\nHost: portal.lab\r\n\r\n`, 1729000100 + i);
  }
  // Flow 2: Insecure FTP traffic with credential PASS
  addPacket('192.168.56.20', '192.168.56.110', 49200, 21, 6, `USER student\r\n`, 1729000120);
  addPacket('192.168.56.20', '192.168.56.110', 49200, 21, 6, `PASS studentpass123\r\n`, 1729000121);
  addPacket('192.168.56.110', '192.168.56.20', 21, 49200, 6, `230 Login successful.\r\n`, 1729000122);
  // Flow 3: Cleartext Telnet connection attempt
  addPacket('192.168.56.20', '192.168.56.110', 49300, 23, 6, `telnet password prompt test`, 1729000130);
  // Flow 4: MySQL traffic between portal and database
  for (let i = 0; i < 25; i++) {
    addPacket('192.168.56.101', '192.168.56.120', 42000 + i, 3306, 6, `MySQL query packet payload`, 1729000140 + i);
  }
  // Flow 5: SSH traffic from faculty PC
  for (let i = 0; i < 30; i++) {
    addPacket('192.168.56.31', '192.168.56.110', 51000 + i, 22, 6, `Encrypted SSHv2 traffic packet`, 1729000180 + i);
  }

  return Buffer.concat(chunks);
}

fs.writeFileSync(path.join(SAMPLES_DIR, 'sample_capture.pcap'), makeSyntheticPcap());

console.log('[CampusShield] Sample files generated in samples/ directory.');
