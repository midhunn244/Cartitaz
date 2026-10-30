'use strict';
// Optional first-owner creation for hosts without shell access (e.g. Render free instances).
// Set BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD as SECRET environment variables, deploy once, sign in,
// choose a new password when asked, then DELETE both variables. It only ever acts while NO administrator exists.
const sec = require('./security');

async function run(db, cfg, log = console) {
  const b = cfg.bootstrap || {};
  if (!b.username && !b.password) return { status: 'none' };
  if (!b.username || !b.password) { log.warn('[bootstrap] Both BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD are required. Ignored.'); return { status: 'incomplete' }; }
  if (await db.one('admins', {}, { projection: { id: 1 } })) {
    log.warn('[bootstrap] An administrator already exists, so BOOTSTRAP_ADMIN_* is ignored. Delete these variables from your host settings.');
    return { status: 'ignored' };
  }
  if (!/^[a-zA-Z0-9._-]{3,40}$/.test(b.username)) { log.error('[bootstrap] BOOTSTRAP_ADMIN_USERNAME must be 3-40 letters, numbers, . _ -'); return { status: 'invalid' }; }
  const prob = sec.passwordProblem(b.password, b.username);
  if (prob) { log.error('[bootstrap] Password rejected: ' + prob + '. No administrator was created.'); return { status: 'weak' }; }
  const hash = await sec.hashPassword(b.password), t = Date.now();
  const id = await db.insert('admins', { username: b.username, name: b.name || b.username, role: 'owner', pass_hash: hash, totp_secret: null, totp_enabled: 0, totp_last: 0,
    failed: 0, locked_until: 0, disabled: 0, must_change: 1, created_at: t, last_login: null });
  await db.insert('audit', { ts: t, admin_id: null, username: 'bootstrap', action: 'user.create_bootstrap', entity: 'admin', entity_id: String(id), detail: JSON.stringify({ username: b.username, role: 'owner' }), ip: 'local' });
  log.log(`[bootstrap] Owner "${b.username}" created. Sign in, choose a new password, then DELETE the BOOTSTRAP_ADMIN_* variables.`);
  return { status: 'created' };
}
module.exports = { run };
