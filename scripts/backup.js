'use strict';
// Consistent online backup of the database (safe while the server is running). Uses MongoDB's own `mongodump`
// (install the MongoDB Database Tools: https://www.mongodb.com/docs/database-tools/installation/).
//   npm run backup -- /path/to/backups/cartitaz-2025-01-31.archive.gz
// Restore with:  mongorestore --uri "$MONGODB_URI" --nsInclude "<db>.*" --gzip --archive=<file>
// (On MongoDB Atlas you can also use its built-in Cloud Backup.)
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { load } = require('../src/config');

const out = process.argv[2];
if (!out) { console.error('Usage: npm run backup -- <output-file.archive.gz>'); process.exit(1); }
const cfg = load({ ...process.env, NODE_ENV: process.env.NODE_ENV || 'development' });
const target = path.resolve(out);
if (fs.existsSync(target)) { console.error('Refusing to overwrite an existing file: ' + target); process.exit(1); }
fs.mkdirSync(path.dirname(target), { recursive: true });
// The connection string may contain a password, so pass it through a private temporary config file instead of the command line.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ct-backup-'));
const conf = path.join(dir, 'dump.yml');
fs.writeFileSync(conf, 'uri: ' + JSON.stringify(cfg.mongoUri) + '\n', { mode: 0o600 });
let r;
try { r = spawnSync('mongodump', ['--config', conf, '--db', cfg.mongoDb, '--gzip', '--archive=' + target], { stdio: ['ignore', 'inherit', 'inherit'] }); }
finally { fs.rmSync(dir, { recursive: true, force: true }); }
if (r.error && r.error.code === 'ENOENT') { console.error('mongodump was not found. Install the MongoDB Database Tools, or use your MongoDB host\'s backups (e.g. Atlas Cloud Backup).'); process.exit(1); }
if (r.status !== 0) { try { fs.rmSync(target, { force: true }); } catch {} console.error('mongodump failed.'); process.exit(1); }
fs.chmodSync(target, 0o600);
console.log('Backup written to ' + target + '. It contains customer data: store it encrypted and access-controlled.');
