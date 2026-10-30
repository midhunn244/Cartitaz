'use strict';
const http = require('http');
const { load } = require('./config');
const { createApp } = require('./app');
const bootstrap = require('./bootstrap');

async function start(env = process.env) {
  const cfg = load(env);
  const app = await createApp(cfg);
  const server = http.createServer(app.handler);
  server.headersTimeout = 15000; server.requestTimeout = 30000; server.keepAliveTimeout = 5000; server.maxHeadersCount = 60;
  await bootstrap.run(app.db, cfg).catch((e) => console.error('[bootstrap] failed:', e.message));
  await new Promise((resolve) => server.listen(cfg.port, cfg.host, async () => {
    console.log(`Cartitaz running on http://${cfg.host}:${cfg.port}  (admin: ${cfg.adminPath}, env: ${cfg.prod ? 'production' : 'development'})`);
    if (!app.db.transactional) console.warn('[warn] MongoDB is running without replica-set support, so multi-step changes are not atomic. Use a replica set (MongoDB Atlas is one) in production.');
    if (!(await app.db.one('admins', {}, { projection: { id: 1 } }))) console.log('No administrator exists yet. Create one with: npm run create-admin');
    resolve();
  }));
  const stop = () => server.close(async () => { await app.close(); process.exit(0); });
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
  return { server, app, cfg };
}
if (require.main === module) start().catch((e) => { console.error('Could not start:', e.message); process.exit(1); });
module.exports = { start };
