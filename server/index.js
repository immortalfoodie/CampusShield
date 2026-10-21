/**
 * CampusShield — Main Server Entry Point
 * 
 * Local-first VAPT assessment and network risk visualization platform.
 * Binds strictly to 127.0.0.1 for safety.
 */

import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { openDb, getMode, setMode, q } from './db.js';
import { seedDemo } from './services/demo.js';
import { apiRouter } from './routes/api.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const PORT = Number(process.env.PORT) || 4173;

// Initialize the active mode workspace
const currentMode = getMode();
const initialDb = openDb(currentMode);
if (currentMode === 'demo') {
  const assetCount = q(initialDb).get('SELECT COUNT(*) as c FROM assets').c;
  if (assetCount === 0) {
    console.log('[CampusShield] Initializing bundled demo environment...');
    seedDemo(initialDb);
  }
}

const app = express();

// JSON body parser with increased limit for XML/PCAP base64 imports
app.use(express.json({ limit: '32mb' }));
app.use(express.urlencoded({ extended: true, limit: '32mb' }));

// Security & Caching headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  next();
});

// API Routes
app.use('/api', apiRouter);

// Serve node_modules libraries (Chart.js and Cytoscape.js) for offline, self-contained operation
app.use('/vendor/chart.js', express.static(path.join(ROOT_DIR, 'node_modules/chart.js/dist/chart.umd.js')));
app.use('/vendor/cytoscape.js', express.static(path.join(ROOT_DIR, 'node_modules/cytoscape/dist/cytoscape.min.js')));

// Serve frontend assets
app.use(express.static(PUBLIC_DIR));

// Fallback to index.html for SPA hash routing
app.get('*', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[CampusShield Server Error]', err);
  if (!res.headersSent) {
    res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

process.on('uncaughtException', (err) => {
  console.error('[CampusShield Uncaught Exception]', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[CampusShield Unhandled Rejection]', reason);
});

process.on('SIGINT', () => {
  console.log('[CampusShield] Caught SIGINT - ignoring to keep daemon active');
});

process.on('SIGTERM', () => {
  console.log('[CampusShield] Caught SIGTERM - ignoring to keep daemon active');
});

process.on('exit', (code) => {
  console.log(`[CampusShield] Process exit event with code: ${code}`);
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`
  ==============================================================
   🛡️  CampusShield — Laboratory VAPT Assessment Platform
   Running at: http://127.0.0.1:${PORT}
   Mode:       ${currentMode.toUpperCase()} MODE
   Safety:     Localhost loopback only. Authorized testing only.
  ==============================================================
  `);
});
