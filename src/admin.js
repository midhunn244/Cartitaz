'use strict';
const crypto = require('crypto');
const sec = require('./security');
const { F, VErr, httpErr, money, normPhone } = require('./http');
const { STATUSES, NEXT, REQUEST_STATUSES, LABEL } = require('./core');
const { COLLATION, toBuffer } = require('./db');

const ICONS = ['Bags', 'Watches', 'Home', 'Candle', 'Wellness'];
const HEX = /^#[0-9a-fA-F]{6}$/;
const EXPENSE_KINDS = ['shipping_cost', 'payment_fee', 'packaging', 'advertising', 'other'];
const ROLE_PERMS = {
  owner: new Set(['*']),
  manager: new Set(['products:r', 'products:w', 'categories:r', 'categories:w', 'orders:r', 'orders:status', 'orders:w', 'customers:r', 'customers:w',
    'suppliers:r', 'suppliers:w', 'inventory:r', 'inventory:w', 'promotions:r', 'promotions:w', 'settings:r', 'settings:w', 'finance:r', 'finance:w']),
  support: new Set(['products:r', 'categories:r', 'orders:r', 'orders:status', 'customers:r', 'inventory:r']),
};
const can = (role, perm) => { const s = ROLE_PERMS[role]; return !!s && (s.has('*') || s.has(perm)); };
const permList = (role) => ['products:r', 'products:w', 'categories:r', 'categories:w', 'orders:r', 'orders:status', 'orders:w', 'customers:r', 'customers:w', 'suppliers:r',
  'suppliers:w', 'inventory:r', 'inventory:w', 'promotions:r', 'promotions:w', 'settings:r', 'settings:w', 'finance:r', 'finance:w', 'security:r', 'security:w'].filter((p) => can(role, p));

function sniff(buf) {
  if (buf.length > 3 && buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return 'image/jpeg';
  if (buf.length > 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) return 'image/png';
  if (buf.length > 12 && buf.subarray(0, 4).toString('latin1') === 'RIFF' && buf.subarray(8, 12).toString('latin1') === 'WEBP') return 'image/webp';
  return null;
}
const dayMs = (s, endOfDay = false) => { const t = Date.parse(s + 'T00:00:00Z'); return Number.isNaN(t) ? null : t + (endOfDay ? 86400000 : 0); };

function register({ db, core, cfg, limiter, audit }) {
  const routes = [];
  const now = () => Date.now();
  const add = (method, path, perm, handler, opts = {}) => {
    const keys = [];
    const re = new RegExp('^' + path.replace(/:[a-z_]+/g, (m) => { keys.push(m.slice(1)); return '([^/]+)'; }) + '/?$');
    routes.push({ method, re, keys, perm, handler, ...opts });
  };
  const idParam = (ctx, k = 'id') => { const n = Number(ctx.params[k]); if (!Number.isInteger(n) || n < 1) throw httpErr(404, 'Not found'); return n; };
  const page = (q) => ({ limit: Math.min(200, Math.max(1, parseInt(q.limit, 10) || 50)), offset: Math.max(0, parseInt(q.offset, 10) || 0) });
  const rx = (s) => new RegExp(String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');   // case-insensitive "contains"
  const cookie = (v, clear) => `cc_session=${v}; HttpOnly; SameSite=Strict; Path=${cfg.adminPath}${cfg.cookieSecure ? '; Secure' : ''}${clear ? '; Max-Age=0' : ''}`;
  const CI = { collation: COLLATION };
  const by = (rows, k = 'id') => new Map(rows.map((r) => [r[k], r]));
  const uniq = (xs) => [...new Set(xs.filter((x) => x != null))];
  const countBy = async (coll, field) => new Map((await db.aggregate(coll, [{ $group: { _id: '$' + field, n: { $sum: 1 } } }])).map((r) => [r._id, r.n]));
  const addMove = (m) => db.insert('stock_moves', { variant_id: null, order_id: null, admin_id: null, ...m });

  // =====================================================================
  // AUTH
  // =====================================================================
  const lockout = async (a, t) => {
    const failed = a.failed + 1;
    if (failed >= 5) await db.update('admins', { id: a.id }, { failed: 0, locked_until: t + 15 * 60 * 1000 });
    else await db.update('admins', { id: a.id }, { failed });
  };
  const RC = 'ABCDEFGHJKMNPQRSTVWXYZ23456789';
  async function newRecoveryCodes(adminId) {
    const codes = [], docs = [];
    for (let i = 0; i < 8; i++) {
      const b = crypto.randomBytes(10); let c = ''; for (const x of b) c += RC[x % RC.length];
      codes.push(c.slice(0, 5) + '-' + c.slice(5));
      docs.push({ admin_id: adminId, hash: sec.sha256('rc:' + c), used_at: null });
    }
    await db.tx(async () => { await db.deleteMany('recovery_codes', { admin_id: adminId }); await db.insertMany('recovery_codes', docs); });
    return codes;
  }
  const recoveryLeft = (adminId) => db.count('recovery_codes', { admin_id: adminId, used_at: null });
  add('POST', '/login', null, async (ctx) => {
    const d = new F(ctx.body).str('username', { req: true, max: 60 }).str('password', { req: true, max: 300, trim: false }).str('totp', { max: 24 }).done();
    const ipHit = limiter.hit('login:ip:' + ctx.ip, 15, 15 * 60 * 1000);
    if (!ipHit.ok) throw httpErr(429, 'Too many sign-in attempts. Try again later.', { retry: ipHit.retry });
    const a = await db.one('admins', { username: d.username }, CI);
    const t = now();
    const generic = httpErr(401, 'Invalid username or password');
    if (!a) { await sec.verifyPassword(d.password, await sec.dummyHash()); await audit(ctx, 'login.failed', 'admin', null, { username: d.username.slice(0, 40), reason: 'unknown_user' }); throw generic; }
    if (a.locked_until > t) {
      await sec.verifyPassword(d.password, await sec.dummyHash());
      await audit(ctx, 'login.blocked', 'admin', a.id, { reason: 'locked' }, a);
      throw httpErr(429, 'This account is temporarily locked after repeated failed attempts. Try again in 15 minutes.', { retry: Math.ceil((a.locked_until - t) / 1000) });
    }
    const ok = await sec.verifyPassword(d.password, a.pass_hash);
    if (!ok || a.disabled) { if (!a.disabled) await lockout(a, t); await audit(ctx, 'login.failed', 'admin', a.id, { reason: a.disabled ? 'disabled' : 'bad_password' }, a); throw generic; }
    let counter = null;
    if (a.totp_enabled) {
      if (!d.totp) throw httpErr(401, 'Enter your authentication code', { need_totp: true });
      const secret = sec.decrypt(a.totp_secret, cfg.appSecret);
      const code = String(d.totp).trim();
      if (/^\d{6}$/.test(code)) counter = secret ? sec.totpVerify(secret, code, a.totp_last) : null;
      else {   // one-time recovery code (consumed on use)
        const norm = code.toUpperCase().replace(/[^A-Z0-9]/g, '');
        const used = norm.length === 10 && (await db.update('recovery_codes', { admin_id: a.id, hash: sec.sha256('rc:' + norm), used_at: null }, { used_at: t })) === 1;
        if (used) { counter = 0; await audit(ctx, 'login.recovery_code_used', 'admin', a.id, null, a); } else counter = null;
      }
      if (counter === null) { await lockout(a, t); await audit(ctx, 'login.failed', 'admin', a.id, { reason: 'bad_totp' }, a); throw httpErr(401, 'Invalid authentication code', { need_totp: true }); }
    }
    const upd = { failed: 0, locked_until: 0, last_login: t };
    if (counter > 0) upd.totp_last = counter;
    await db.update('admins', { id: a.id }, upd);
    const sid = sec.token(32), csrf = sec.token(24);
    await db.insert('sessions', { id: sec.sha256(sid), admin_id: a.id, csrf, created_at: t, last_seen: t, expires_at: t + cfg.sessionMaxMs, ip: ctx.ip, ua: String(ctx.req.headers['user-agent'] || '').slice(0, 200) });
    const stale = await db.find('sessions', { admin_id: a.id }, { sort: { last_seen: -1 }, skip: 8, projection: { id: 1 } });   // keep the 8 most recent
    if (stale.length) await db.deleteMany('sessions', { id: { $in: stale.map((x) => x.id) } });
    ctx.headers['Set-Cookie'] = cookie(sid);
    await audit(ctx, 'login.success', 'admin', a.id, null, a);
    return { ok: true };
  }, { public: true });

  add('POST', '/logout', null, async (ctx) => {
    await db.deleteOne('sessions', { id: ctx.session.id });
    ctx.headers['Set-Cookie'] = cookie('', true);
    await audit(ctx, 'logout', 'admin', ctx.admin.id);
    return { ok: true };
  }, { allowMustChange: true });

  add('GET', '/me', null, async (ctx) => {
    const a = ctx.admin;
    const left = a.totp_enabled ? await recoveryLeft(a.id) : 0;
    return { admin: { id: a.id, username: a.username, name: a.name, role: a.role, totp_enabled: !!a.totp_enabled, must_change: !!a.must_change, recovery_left: left },
      csrf: ctx.session.csrf, perms: permList(a.role), currency: await core.getSetting('currency'), statuses: STATUSES, next: NEXT, labels: LABEL, icons: ICONS };
  }, { allowMustChange: true });

  add('POST', '/password', null, async (ctx) => {
    const d = new F(ctx.body).str('current', { req: true, max: 300, trim: false }).str('next', { req: true, max: 300, trim: false }).done();
    if (!(await sec.verifyPassword(d.current, ctx.admin.pass_hash))) { await audit(ctx, 'password.change_failed', 'admin', ctx.admin.id); throw new VErr({ current: 'Current password is incorrect' }); }
    const prob = sec.passwordProblem(d.next, ctx.admin.username);
    if (prob) throw new VErr({ next: prob });
    if (d.next === d.current) throw new VErr({ next: 'Choose a different password' });
    await db.update('admins', { id: ctx.admin.id }, { pass_hash: await sec.hashPassword(d.next), must_change: 0 });
    await db.deleteMany('sessions', { admin_id: ctx.admin.id, id: { $ne: ctx.session.id } });
    await audit(ctx, 'password.changed', 'admin', ctx.admin.id);
    return { ok: true };
  }, { allowMustChange: true });

  add('POST', '/2fa/setup', null, async (ctx) => {
    if (ctx.admin.totp_enabled) throw httpErr(409, 'Two-factor authentication is already enabled');
    const secret = sec.newTotpSecret();
    await db.update('admins', { id: ctx.admin.id }, { totp_secret: sec.encrypt(secret, cfg.appSecret) });
    const issuer = encodeURIComponent('Cartitaz Admin');
    return { secret, uri: `otpauth://totp/${issuer}:${encodeURIComponent(ctx.admin.username)}?secret=${secret}&issuer=${issuer}&digits=6&period=30` };
  });
  add('POST', '/2fa/enable', null, async (ctx) => {
    const d = new F(ctx.body).str('code', { req: true, max: 8 }).done();
    if (ctx.admin.totp_enabled || !ctx.admin.totp_secret) throw httpErr(409, 'Start setup first');
    const secret = sec.decrypt(ctx.admin.totp_secret, cfg.appSecret);
    const c = secret ? sec.totpVerify(secret, d.code, 0) : null;
    if (c === null) throw new VErr({ code: 'That code is not correct' });
    await db.update('admins', { id: ctx.admin.id }, { totp_enabled: 1, totp_last: c });
    await db.deleteMany('sessions', { admin_id: ctx.admin.id, id: { $ne: ctx.session.id } });
    const recovery_codes = await newRecoveryCodes(ctx.admin.id);
    await audit(ctx, '2fa.enabled', 'admin', ctx.admin.id);
    return { ok: true, recovery_codes };
  });
  add('POST', '/2fa/disable', null, async (ctx) => {
    const d = new F(ctx.body).str('password', { req: true, max: 300, trim: false }).str('code', { req: true, max: 8 }).done();
    if (!(await sec.verifyPassword(d.password, ctx.admin.pass_hash))) throw new VErr({ password: 'Incorrect password' });
    const secret = ctx.admin.totp_secret ? sec.decrypt(ctx.admin.totp_secret, cfg.appSecret) : null;
    if (!ctx.admin.totp_enabled || !secret || sec.totpVerify(secret, d.code, ctx.admin.totp_last) === null) throw new VErr({ code: 'That code is not correct' });
    await db.update('admins', { id: ctx.admin.id }, { totp_enabled: 0, totp_secret: null, totp_last: 0 });
    await db.deleteMany('recovery_codes', { admin_id: ctx.admin.id });
    await audit(ctx, '2fa.disabled', 'admin', ctx.admin.id);
    return { ok: true };
  });
  add('POST', '/2fa/recovery', null, async (ctx) => {   // issue a fresh set; the old codes stop working
    const d = new F(ctx.body).str('password', { req: true, max: 300, trim: false }).str('code', { req: true, max: 8 }).done();
    if (!(await sec.verifyPassword(d.password, ctx.admin.pass_hash))) throw new VErr({ password: 'Incorrect password' });
    const secret = ctx.admin.totp_secret ? sec.decrypt(ctx.admin.totp_secret, cfg.appSecret) : null;
    const c = ctx.admin.totp_enabled && secret ? sec.totpVerify(secret, d.code, ctx.admin.totp_last) : null;
    if (c === null) throw new VErr({ code: 'That code is not correct' });
    await db.update('admins', { id: ctx.admin.id }, { totp_last: c });
    await audit(ctx, '2fa.recovery_regenerated', 'admin', ctx.admin.id);
    return { recovery_codes: await newRecoveryCodes(ctx.admin.id) };
  });

  // =====================================================================
  // CATEGORIES
  // =====================================================================
  const catInput = (b) => new F(b).str('name', { req: true, max: 40 }).num('sort', { int: true, min: 0, max: 9999 }).bool('published', 1)
    .en('icon', ICONS, { req: false }).str('tint', { re: HEX }).done();
  add('GET', '/categories', 'categories:r', async () => {
    const [rows, counts] = await Promise.all([db.find('categories', {}, { sort: { sort: 1, name: 1 } }), countBy('products', 'category_id')]);
    return rows.map((c) => ({ ...c, products: counts.get(c.id) || 0 }));
  });
  add('POST', '/categories', 'categories:w', async (ctx) => {
    const c = catInput(ctx.body), dup = new VErr({ name: 'A category with this name already exists' });
    if (await db.one('categories', { name: c.name }, { ...CI, projection: { id: 1 } })) throw dup;
    let id;
    try { id = await db.insert('categories', { name: c.name, sort: c.sort || 0, published: c.published, icon: c.icon || 'Bags', tint: c.tint || '#E8E5E0' }); }
    catch (e) { if (db.isDuplicate(e)) throw dup; throw e; }
    await audit(ctx, 'category.create', 'category', id, c); ctx.status = 201;
    return { id };
  });
  add('PUT', '/categories/:id', 'categories:w', async (ctx) => {
    const id = idParam(ctx), c = catInput(ctx.body), dup = new VErr({ name: 'A category with this name already exists' });
    if (!(await db.one('categories', { id }, { projection: { id: 1 } }))) throw httpErr(404, 'Category not found');
    if (await db.one('categories', { name: c.name, id: { $ne: id } }, { ...CI, projection: { id: 1 } })) throw dup;
    try { await db.update('categories', { id }, { name: c.name, sort: c.sort || 0, published: c.published, icon: c.icon || 'Bags', tint: c.tint || '#E8E5E0' }); }
    catch (e) { if (db.isDuplicate(e)) throw dup; throw e; }
    await audit(ctx, 'category.update', 'category', id, c); return { ok: true };
  });
  add('DELETE', '/categories/:id', 'categories:w', async (ctx) => {
    const id = idParam(ctx);
    if (await db.one('products', { category_id: id }, { projection: { id: 1 } })) throw httpErr(409, 'Move or delete the products in this category first');
    await db.deleteOne('categories', { id }); await audit(ctx, 'category.delete', 'category', id); return { ok: true };
  });

  // =====================================================================
  // SUPPLIERS (private)
  // =====================================================================
  const supInput = (b) => new F(b).str('name', { req: true, max: 80 }).str('contact', { max: 80 }).str('phone', { max: 30 })
    .str('email', { max: 120, re: /^[^\s@]+@[^\s@]+\.[^\s@]+$/, msg: 'Enter a valid email' })
    .str('website', { max: 200, re: /^https?:\/\/[^\s]+$/i, msg: 'Must start with http:// or https://' })
    .num('lead_days', { int: true, min: 0, max: 365 }).str('notes', { max: 2000 }).done();
  add('GET', '/suppliers', 'suppliers:r', async () => {
    const [rows, counts] = await Promise.all([db.find('suppliers', {}, { sort: { name: 1, id: 1 } }), countBy('products', 'supplier_id')]);
    return rows.map((s) => ({ ...s, products: counts.get(s.id) || 0 }));
  });
  add('POST', '/suppliers', 'suppliers:w', async (ctx) => {
    const s = supInput(ctx.body), t = now();
    const id = await db.insert('suppliers', { name: s.name, contact: s.contact, phone: s.phone, email: s.email, website: s.website, lead_days: s.lead_days, notes: s.notes, created_at: t, updated_at: t });
    await audit(ctx, 'supplier.create', 'supplier', id, { name: s.name }); ctx.status = 201; return { id };
  });
  add('PUT', '/suppliers/:id', 'suppliers:w', async (ctx) => {
    const id = idParam(ctx), s = supInput(ctx.body);
    if (!(await db.one('suppliers', { id }, { projection: { id: 1 } }))) throw httpErr(404, 'Supplier not found');
    await db.update('suppliers', { id }, { name: s.name, contact: s.contact, phone: s.phone, email: s.email, website: s.website, lead_days: s.lead_days, notes: s.notes, updated_at: now() });
    await audit(ctx, 'supplier.update', 'supplier', id, { name: s.name }); return { ok: true };
  });
  add('DELETE', '/suppliers/:id', 'suppliers:w', async (ctx) => {
    const id = idParam(ctx);
    await db.tx(async () => {
      await db.updateMany('products', { supplier_id: id }, { supplier_id: null });
      await db.updateMany('orders', { 'items.supplier_id': id }, { $set: { 'items.$[it].supplier_id': null } }, { arrayFilters: [{ 'it.supplier_id': id }] });
      await db.deleteOne('suppliers', { id });
    });
    await audit(ctx, 'supplier.delete', 'supplier', id); return { ok: true };
  });

  // =====================================================================
  // PRODUCTS
  // =====================================================================
  const scrubProduct = (p, role) => { if (!can(role, 'finance:r')) { delete p.cost_price; delete p.supplier_id; delete p.supplier_name; delete p.internal_notes; } return p; };
  add('GET', '/products', 'products:r', async (ctx) => {
    const q = ctx.query, and = [];
    if (q.q) and.push({ $or: [{ name: rx(q.q) }, { sku: rx(q.q) }, { brand: rx(q.q) }] });
    if (q.category_id) and.push({ category_id: Number(q.category_id) || 0 });
    if (q.status === 'published') and.push({ published: 1 }); else if (q.status === 'draft') and.push({ published: 0 });
    const { limit, offset } = page(q);
    const rows = await db.find('products', and.length ? { $and: and } : {}, { sort: { updated_at: -1, id: -1 }, skip: offset, limit });
    const ids = rows.map((r) => r.id);
    if (!ids.length) return [];
    const [cats, sups, vars, imgs] = await Promise.all([
      db.find('categories', { id: { $in: uniq(rows.map((r) => r.category_id)) } }, { projection: { id: 1, name: 1 } }),
      db.find('suppliers', { id: { $in: uniq(rows.map((r) => r.supplier_id)) } }, { projection: { id: 1, name: 1 } }),
      db.find('variants', { product_id: { $in: ids } }, { projection: { product_id: 1, stock: 1 } }),
      db.find('product_images', { product_id: { $in: ids } }, { sort: { sort: 1, id: 1 }, projection: { product_id: 1, media_id: 1 } }),
    ]);
    const cn = by(cats), sn = by(sups), vBy = new Map(), cover = new Map();
    for (const v of vars) (vBy.get(v.product_id) || vBy.set(v.product_id, []).get(v.product_id)).push(v);
    for (const i of imgs) if (!cover.has(i.product_id)) cover.set(i.product_id, i.media_id);
    return rows.map((r) => { const vs = vBy.get(r.id) || [];
      return scrubProduct({ ...r, category_name: cn.has(r.category_id) ? cn.get(r.category_id).name : null, supplier_name: sn.has(r.supplier_id) ? sn.get(r.supplier_id).name : null,
        variant_count: vs.length, stock_total: vs.length ? vs.reduce((s, v) => s + v.stock, 0) : r.stock, cover: cover.has(r.id) ? cover.get(r.id) : null }, ctx.admin.role); });
  });
  const loadProduct = async (id, role) => {
    const p = await db.one('products', { id });
    if (!p) throw httpErr(404, 'Product not found');
    const [c, s, variants, images] = await Promise.all([
      p.category_id != null ? db.one('categories', { id: p.category_id }, { projection: { name: 1 } }) : null,
      p.supplier_id != null ? db.one('suppliers', { id: p.supplier_id }, { projection: { name: 1 } }) : null,
      db.find('variants', { product_id: id }, { sort: { sort: 1, id: 1 }, projection: { id: 1, name: 1, sku: 1, stock: 1 } }),
      db.find('product_images', { product_id: id }, { sort: { sort: 1, id: 1 }, projection: { id: 1, media_id: 1 } }),
    ]);
    return scrubProduct({ ...p, category_name: c ? c.name : null, supplier_name: s ? s.name : null, variants, images }, role);
  };
  add('GET', '/products/:id', 'products:r', async (ctx) => loadProduct(idParam(ctx), ctx.admin.role));

  async function productInput(b) {
    const f = new F(b).str('name', { req: true, max: 120 }).str('brand', { max: 60 }).num('category_id', { int: true, min: 1 }).num('supplier_id', { int: true, min: 1 })
      .str('caption', { max: 200 }).str('description', { max: 4000 }).num('price', { req: true, min: 0.01, max: 10000000 })
      .num('compare_price', { min: 0.01, max: 10000000 }).num('cost_price', { min: 0, max: 10000000 }).str('sku', { max: 60 })
      .num('stock', { int: true, min: 0, max: 1000000 }).num('low_stock', { int: true, min: 0, max: 100000 })
      .en('icon', ICONS, { req: false }).str('tint', { re: HEX }).bool('published').str('internal_notes', { max: 4000 });
    const o = f.out;
    if (o.price != null && o.compare_price != null && o.compare_price <= o.price) f.bad('compare_price', 'Original price must be higher than the selling price');
    if (o.category_id && !(await db.one('categories', { id: o.category_id }, { projection: { id: 1 } }))) f.bad('category_id', 'Category not found');
    if (o.supplier_id && !(await db.one('suppliers', { id: o.supplier_id }, { projection: { id: 1 } }))) f.bad('supplier_id', 'Supplier not found');
    if (o.published && !o.category_id) f.bad('category_id', 'Choose a category before publishing');
    let variants = [];
    if (b && b.variants !== undefined) {
      if (!Array.isArray(b.variants) || b.variants.length > 40) f.bad('variants', 'Up to 40 variants allowed');
      else {
        const seen = new Set();
        variants = b.variants.map((v, i) => {
          const vf = new F(v).str('name', { req: true, max: 60 }).str('sku', { max: 40 }).num('stock', { int: true, min: 0, max: 1000000 }).num('id', { int: true, min: 1 });
          if (Object.keys(vf.err).length) { f.bad('variants', `Variant ${i + 1}: ${Object.values(vf.err)[0]}`); return null; }
          const k = vf.out.name.toLowerCase(); if (seen.has(k)) f.bad('variants', `Duplicate variant name "${vf.out.name}"`); seen.add(k);
          return { id: vf.out.id, name: vf.out.name, sku: vf.out.sku, stock: vf.out.stock || 0 };
        }).filter(Boolean);
      }
    }
    f.done();
    return { p: { ...o, stock: o.stock || 0, low_stock: o.low_stock == null ? 3 : o.low_stock, icon: o.icon || 'Bags', tint: o.tint || '#E8E5E0' }, variants: b && b.variants !== undefined ? variants : null };
  }
  async function syncVariants(pid, list, ctx) {
    const existing = new Map((await db.find('variants', { product_id: pid }, { projection: { id: 1, stock: 1 } })).map((r) => [r.id, r.stock]));
    const keep = new Set();
    for (let i = 0; i < list.length; i++) {
      const v = list[i];
      if (v.id && existing.has(v.id)) {
        await db.update('variants', { id: v.id }, { name: v.name, sku: v.sku, stock: v.stock, sort: i }); keep.add(v.id);
        if (v.stock !== existing.get(v.id)) await addMove({ ts: now(), product_id: pid, variant_id: v.id, delta: v.stock - existing.get(v.id), reason: 'Edited in product form', admin_id: ctx.admin.id });
      } else {
        const vid = await db.insert('variants', { product_id: pid, name: v.name, sku: v.sku, stock: v.stock, sort: i }); keep.add(vid);
        if (v.stock) await addMove({ ts: now(), product_id: pid, variant_id: vid, delta: v.stock, reason: 'Initial stock', admin_id: ctx.admin.id });
      }
    }
    const gone = [...existing.keys()].filter((id) => !keep.has(id));
    if (gone.length) await db.deleteMany('variants', { id: { $in: gone } });
  }
  add('POST', '/products', 'products:w', async (ctx) => {
    const { p, variants } = await productInput(ctx.body), t = now();
    const id = await db.tx(async () => {
      const pid = await db.insert('products', { name: p.name, brand: p.brand, category_id: p.category_id, supplier_id: p.supplier_id, caption: p.caption, description: p.description,
        price: p.price, compare_price: p.compare_price, cost_price: p.cost_price, sku: p.sku, stock: p.stock, low_stock: p.low_stock, icon: p.icon, tint: p.tint,
        published: p.published, internal_notes: p.internal_notes, created_at: t, updated_at: t });
      if (variants) await syncVariants(pid, variants, ctx);
      if (p.stock && !(variants && variants.length)) await addMove({ ts: t, product_id: pid, delta: p.stock, reason: 'Initial stock', admin_id: ctx.admin.id });
      return pid;
    });
    await audit(ctx, 'product.create', 'product', id, { name: p.name, price: p.price, cost_price: p.cost_price, published: p.published });
    ctx.status = 201; return { id };
  });
  add('PUT', '/products/:id', 'products:w', async (ctx) => {
    const id = idParam(ctx), before = await db.one('products', { id });
    if (!before) throw httpErr(404, 'Product not found');
    const { p, variants } = await productInput(ctx.body);
    await db.tx(async () => {
      await db.update('products', { id }, { name: p.name, brand: p.brand, category_id: p.category_id, supplier_id: p.supplier_id, caption: p.caption, description: p.description,
        price: p.price, compare_price: p.compare_price, cost_price: p.cost_price, sku: p.sku, stock: p.stock, low_stock: p.low_stock, icon: p.icon, tint: p.tint,
        published: p.published, internal_notes: p.internal_notes, updated_at: now() });
      if (p.stock !== before.stock) await addMove({ ts: now(), product_id: id, delta: p.stock - before.stock, reason: 'Edited in product form', admin_id: ctx.admin.id });
      if (variants) await syncVariants(id, variants, ctx);
    });
    const diff = {};
    for (const k of ['name', 'price', 'compare_price', 'cost_price', 'published', 'category_id', 'supplier_id']) if (before[k] !== p[k]) diff[k] = [before[k], p[k]];
    await audit(ctx, 'product.update', 'product', id, diff); return { ok: true };
  });
  add('POST', '/products/:id/publish', 'products:w', async (ctx) => {
    const id = idParam(ctx), pub = new F(ctx.body).bool('published').done().published;
    const p = await db.one('products', { id });
    if (!p) throw httpErr(404, 'Product not found');
    if (pub && !p.category_id) throw httpErr(409, 'Choose a category before publishing');
    await db.update('products', { id }, { published: pub, updated_at: now() });
    await audit(ctx, pub ? 'product.publish' : 'product.unpublish', 'product', id, { name: p.name }); return { ok: true, published: pub };
  });
  add('DELETE', '/products/:id', 'products:w', async (ctx) => {
    const id = idParam(ctx), p = await db.one('products', { id }, { projection: { name: 1 } });
    if (!p) throw httpErr(404, 'Product not found');
    await db.tx(async () => {
      const media = (await db.find('product_images', { product_id: id }, { projection: { media_id: 1 } })).map((r) => r.media_id);
      await db.deleteOne('products', { id });
      await db.deleteMany('variants', { product_id: id });
      await db.deleteMany('product_images', { product_id: id });
      if (media.length) await db.deleteMany('media', { id: { $in: media } });
    });
    await audit(ctx, 'product.delete', 'product', id, { name: p.name }); return { ok: true };
  });

  async function saveMedia(dataB64, maxBytes) {
    if (typeof dataB64 !== 'string' || !dataB64) throw new VErr({ data: 'Choose an image' });
    const buf = Buffer.from(dataB64.replace(/^data:[^,]+,/, ''), 'base64');
    if (!buf.length) throw new VErr({ data: 'Empty image' });
    if (buf.length > maxBytes) throw new VErr({ data: `Image is too large (max ${Math.round(maxBytes / 1024)} KB)` });
    const mime = sniff(buf);
    if (!mime) throw new VErr({ data: 'Only JPEG, PNG or WebP images are allowed' });
    const id = crypto.randomBytes(12).toString('hex');
    await db.insert('media', { id, mime, data: buf, created_at: now() });
    return id;
  }
  add('POST', '/products/:id/images', 'products:w', async (ctx) => {
    const id = idParam(ctx);
    if (!(await db.one('products', { id }, { projection: { id: 1 } }))) throw httpErr(404, 'Product not found');
    if ((await db.count('product_images', { product_id: id })) >= 8) throw httpErr(409, 'A product can have up to 8 images');
    const mid = await saveMedia(ctx.body && ctx.body.data, 1536 * 1024);
    const top = await db.one('product_images', { product_id: id }, { sort: { sort: -1 }, projection: { sort: 1 } });
    const imgId = await db.insert('product_images', { product_id: id, media_id: mid, sort: (top ? top.sort : 0) + 1 });
    await db.update('products', { id }, { updated_at: now() });
    await audit(ctx, 'product.image_add', 'product', id); ctx.status = 201; return { id: imgId, media_id: mid };
  }, { limit: 3 * 1024 * 1024 });
  add('POST', '/products/:id/images/:img/cover', 'products:w', async (ctx) => {
    const id = idParam(ctx), img = idParam(ctx, 'img');
    const low = await db.one('product_images', { product_id: id }, { sort: { sort: 1 }, projection: { sort: 1 } });
    const min = (low ? low.sort : 0) - 1;
    if (!(await db.update('product_images', { id: img, product_id: id }, { sort: min }))) throw httpErr(404, 'Image not found');
    await audit(ctx, 'product.image_cover', 'product', id); return { ok: true };
  });
  add('DELETE', '/products/:id/images/:img', 'products:w', async (ctx) => {
    const id = idParam(ctx), img = idParam(ctx, 'img');
    const row = await db.one('product_images', { id: img, product_id: id }, { projection: { media_id: 1 } });
    if (!row) throw httpErr(404, 'Image not found');
    await db.tx(async () => { await db.deleteOne('product_images', { id: img }); await db.deleteOne('media', { id: row.media_id }); });
    await audit(ctx, 'product.image_remove', 'product', id); return { ok: true };
  });
  add('GET', '/media/:id', null, async (ctx) => {
    const m = await db.one('media', { id: ctx.params.id });
    if (!m) throw httpErr(404, 'Not found');
    return { __raw: true, status: 200, headers: { 'Content-Type': m.mime, 'Content-Security-Policy': "default-src 'none'", 'Cache-Control': 'private, max-age=300' }, body: toBuffer(m.data) };
  });

  // =====================================================================
  // INVENTORY
  // =====================================================================
  add('GET', '/inventory', 'inventory:r', async () => {
    const [prods, vars] = await Promise.all([
      db.find('products', {}, { projection: { id: 1, name: 1, sku: 1, stock: 1, low_stock: 1, published: 1 } }),
      db.find('variants', {}, { projection: { id: 1, product_id: 1, name: 1, sku: 1, stock: 1 } }),
    ]);
    const pBy = by(prods), hasV = new Set(vars.map((v) => v.product_id)), out = [];
    for (const p of prods) if (!hasV.has(p.id)) out.push({ product_id: p.id, variant_id: null, name: p.name, variant_name: null, sku: p.sku, stock: p.stock, low_stock: p.low_stock, published: p.published });
    for (const v of vars) { const p = pBy.get(v.product_id); if (p) out.push({ product_id: p.id, variant_id: v.id, name: p.name, variant_name: v.name, sku: v.sku, stock: v.stock, low_stock: p.low_stock, published: p.published }); }
    const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
    return out.sort((a, b) => cmp(a.name, b.name) || cmp(a.variant_name || '', b.variant_name || ''));
  });
  add('POST', '/inventory/adjust', 'inventory:w', async (ctx) => {
    const d = new F(ctx.body).num('product_id', { req: true, int: true, min: 1 }).num('variant_id', { int: true, min: 1 })
      .num('delta', { req: true, int: true, min: -1000000, max: 1000000 }).str('reason', { req: true, min: 3, max: 120 }).done();
    if (!d.delta) throw new VErr({ delta: 'Enter a non-zero change' });
    const have = await core.stockOf(d.product_id, d.variant_id);
    if (have === null) throw httpErr(404, 'Stock item not found');
    if (have + d.delta < 0) throw httpErr(409, `Stock cannot go below zero (current: ${have})`);
    await db.tx(() => core.moveStock(d.product_id, d.variant_id, d.delta, d.reason, null, ctx.admin.id));
    await audit(ctx, 'inventory.adjust', 'product', d.product_id, { variant_id: d.variant_id, delta: d.delta, reason: d.reason });
    return { stock: have + d.delta };
  });
  add('GET', '/inventory/moves', 'inventory:r', async (ctx) => {
    const pid = Number(ctx.query.product_id) || 0;
    const rows = await db.find('stock_moves', pid ? { product_id: pid } : {}, { sort: { ts: -1, id: -1 }, limit: 100 });
    const [adm, vars, prods] = await Promise.all([
      db.find('admins', { id: { $in: uniq(rows.map((r) => r.admin_id)) } }, { projection: { id: 1, username: 1 } }),
      db.find('variants', { id: { $in: uniq(rows.map((r) => r.variant_id)) } }, { projection: { id: 1, name: 1 } }),
      db.find('products', { id: { $in: uniq(rows.map((r) => r.product_id)) } }, { projection: { id: 1, name: 1 } }),
    ]);
    const a = by(adm), v = by(vars), p = by(prods);
    return rows.map((m) => ({ ...m, username: a.has(m.admin_id) ? a.get(m.admin_id).username : null, variant_name: v.has(m.variant_id) ? v.get(m.variant_id).name : null, product_name: p.has(m.product_id) ? p.get(m.product_id).name : null }));
  });

  // =====================================================================
  // ORDERS & WHATSAPP REQUESTS
  // =====================================================================
  add('GET', '/orders', 'orders:r', async (ctx) => {
    const q = ctx.query, and = [];
    if (q.status) { const ss = q.status.split(',').filter((s) => STATUSES.includes(s)); if (ss.length) and.push({ status: { $in: ss } }); }
    if (q.group === 'requests') and.push({ status: { $in: REQUEST_STATUSES } });
    if (q.q) and.push({ $or: [{ code: rx(q.q) }, { name: rx(q.q) }, { phone: rx(q.q) }] });
    const { limit, offset } = page(q);
    const filter = and.length ? { $and: and } : {};
    const [total, rows] = await Promise.all([db.count('orders', filter),
      db.find('orders', filter, { sort: { created_at: -1, id: -1 }, skip: offset, limit, projection: { id: 1, code: 1, name: 1, phone: 1, status: 1, total: 1, created_at: 1, confirmed_at: 1, 'items.qty': 1 } })]);
    return { total, rows: rows.map(({ items, ...r }) => ({ ...r, items: (items || []).reduce((s, i) => s + i.qty, 0) })) };
  });
  async function orderDetail(id, role) {
    const o = await db.one('orders', { id });
    if (!o) throw httpErr(404, 'Order not found');
    const fin = can(role, 'finance:r');
    const raw = o.items || [], evRaw = [...(o.events || [])].sort((a, b) => b.ts - a.ts || b.id - a.id);
    const [sups, adm] = await Promise.all([
      db.find('suppliers', { id: { $in: uniq(raw.map((i) => i.supplier_id)) } }, { projection: { id: 1, name: 1, phone: 1, lead_days: 1 } }),
      db.find('admins', { id: { $in: uniq(evRaw.map((e) => e.admin_id)) } }, { projection: { id: 1, username: 1 } }),
    ]);
    const sBy = by(sups), aBy = by(adm);
    const items = raw.map((i) => { const s = sBy.get(i.supplier_id); return { ...i, order_id: o.id, supplier_name: s ? s.name : null, supplier_phone: s ? s.phone : null, supplier_lead_days: s ? s.lead_days : null }; });
    const events = evRaw.map((e) => ({ ...e, order_id: o.id, username: aBy.has(e.admin_id) ? aBy.get(e.admin_id).username : null }));
    const out = { ...o, items, events, allowed_next: NEXT[o.status] || [], label: LABEL[o.status] };
    if (fin) {
      const [expenses, refunds] = await Promise.all([db.find('expenses', { order_id: id }, { sort: { ts: -1, id: -1 } }), db.find('refunds', { order_id: id }, { sort: { ts: -1, id: -1 } })]);
      out.expenses = expenses; out.refunds = refunds;
      const missing = items.filter((i) => i.unit_cost == null).length;
      const cogs = items.reduce((s, i) => s + (i.unit_cost || 0) * i.qty, 0);
      const exp = out.expenses.reduce((s, e) => s + e.amount, 0), refunded = out.refunds.reduce((s, r) => s + r.amount, 0);
      out.profit = { complete: missing === 0, missing_costs: missing, revenue: o.total, cogs: money(cogs), expenses: money(exp), refunded: money(refunded),
        profit: missing === 0 ? money(o.total - cogs - exp - refunded) : null };
    } else {
      out.items = items.map(({ unit_cost, supplier_id, supplier_name, supplier_phone, supplier_lead_days, ...rest }) => rest);
    }
    return out;
  }
  add('GET', '/orders/:id', 'orders:r', async (ctx) => orderDetail(idParam(ctx), ctx.admin.role));
  add('PUT', '/orders/:id', 'orders:w', async (ctx) => {
    const id = idParam(ctx), o = await db.one('orders', { id });
    if (!o) throw httpErr(404, 'Order not found');
    const f = new F(ctx.body).str('name', { req: true, min: 2, max: 80 }).str('phone', { req: true, re: /^\+?[0-9\s\-()]{8,20}$/, msg: 'Enter a valid phone number' })
      .str('address', { req: true, min: 8, max: 300 }).str('pincode', { req: true, re: /^[A-Za-z0-9 \-]{3,10}$/, msg: 'Enter a valid pincode' })
      .str('internal_notes', { max: 4000 }).num('shipping', { req: true, min: 0, max: 1000000 }).num('discount', { req: true, min: 0, max: 10000000 });
    const items = [];
    if (Array.isArray(ctx.body.items)) {
      for (const it of ctx.body.items) {
        const itf = new F(it).num('id', { req: true, int: true, min: 1 }).num('unit_cost', { min: 0, max: 10000000 }).num('supplier_id', { int: true, min: 1 });
        if (Object.keys(itf.err).length) f.bad('items', 'Invalid item cost or supplier');
        else if (!(o.items || []).some((x) => x.id === itf.out.id)) f.bad('items', 'Item does not belong to this order');
        else if (itf.out.supplier_id && !(await db.one('suppliers', { id: itf.out.supplier_id }, { projection: { id: 1 } }))) f.bad('items', 'Supplier not found');
        else items.push(itf.out);
      }
    }
    const d = f.done(); d.phone = normPhone(d.phone);
    await db.tx(async () => {
      const set = { name: d.name, phone: d.phone, address: d.address, pincode: d.pincode, internal_notes: d.internal_notes, shipping: d.shipping, discount: d.discount, updated_at: now() };
      if (can(ctx.admin.role, 'finance:w') && items.length) {
        const patch = new Map(items.map((it) => [it.id, it]));
        set.items = o.items.map((x) => (patch.has(x.id) ? { ...x, unit_cost: patch.get(x.id).unit_cost, supplier_id: patch.get(x.id).supplier_id } : x));
      }
      await db.update('orders', { id }, { $set: set });
      await core.recalcTotal(id);
    });
    const diff = {};
    if (o.shipping !== d.shipping) diff.shipping = [o.shipping, d.shipping];
    if (o.discount !== d.discount) diff.discount = [o.discount, d.discount];
    if (items.length) diff.item_costs = items.map((i) => ({ id: i.id, unit_cost: i.unit_cost, supplier_id: i.supplier_id }));
    await audit(ctx, 'order.update', 'order', o.code, diff); return orderDetail(id, ctx.admin.role);
  });
  add('POST', '/orders/:id/status', 'orders:status', async (ctx) => {
    const id = idParam(ctx);
    const d = new F(ctx.body).en('status', STATUSES.filter((s) => s !== 'refunded')).str('note', { max: 500 }).str('public_note', { max: 300 })
      .str('country', { max: 80 }).str('state', { max: 80 }).str('district', { max: 80 }).str('place', { max: 80 }).done();
    const r = await core.changeStatus(id, d.status, d, ctx.admin.id);
    await audit(ctx, 'order.status', 'order', r.code, { from: r.from, to: r.to }); return orderDetail(id, ctx.admin.role);
  });
  add('POST', '/orders/:id/expenses', 'finance:w', async (ctx) => {
    const id = idParam(ctx);
    if (!(await db.one('orders', { id }, { projection: { id: 1 } }))) throw httpErr(404, 'Order not found');
    const d = new F(ctx.body).en('kind', EXPENSE_KINDS).num('amount', { req: true, min: 0.01, max: 10000000 }).str('note', { max: 200 }).done();
    await db.insert('expenses', { order_id: id, kind: d.kind, amount: d.amount, note: d.note, ts: now(), admin_id: ctx.admin.id });
    await audit(ctx, 'expense.create', 'order', id, d); ctx.status = 201; return orderDetail(id, ctx.admin.role);
  });
  add('POST', '/orders/:id/refund', 'finance:w', async (ctx) => {
    const id = idParam(ctx), o = await db.one('orders', { id });
    if (!o) throw httpErr(404, 'Order not found');
    if (!['confirmed', 'ordered_from_supplier', 'shipped', 'out_for_delivery', 'delivered', 'refunded'].includes(o.status)) throw httpErr(409, 'Only confirmed orders can be refunded');
    const d = new F(ctx.body).num('amount', { req: true, min: 0.01, max: 10000000 }).str('note', { max: 200 }).bool('restock').done();
    const already = (await db.find('refunds', { order_id: id }, { projection: { amount: 1 } })).reduce((s, r) => s + r.amount, 0);
    if (money(already + d.amount) > o.total) throw httpErr(409, `Refund exceeds the order total (already refunded ${money(already)})`);
    await db.tx(async () => {
      const t = now(), full = money(already + d.amount) >= o.total, set = {};
      await db.insert('refunds', { order_id: id, amount: d.amount, note: d.note, ts: t, admin_id: ctx.admin.id });
      if (full) { set.status = 'refunded'; set.updated_at = t; }
      const ev = await core.mkEvent({ ts: t, status: full ? 'refunded' : o.status, note: full ? d.note : 'Partial refund ' + d.amount + (d.note ? ': ' + d.note : ''), admin_id: ctx.admin.id });
      if (d.restock && o.stock_committed) {
        for (const it of o.items || []) {
          if (it.product_id && (await core.stockOf(it.product_id, it.variant_id)) !== null) await core.moveStock(it.product_id, it.variant_id, it.qty, 'Refund restock ' + o.code, id, ctx.admin.id);
        }
        set.stock_committed = 0;
      }
      const upd = { $push: { events: ev } }; if (Object.keys(set).length) upd.$set = set;
      await db.update('orders', { id }, upd);
    });
    await audit(ctx, 'order.refund', 'order', o.code, d); return orderDetail(id, ctx.admin.role);
  });
  add('GET', '/orders/:id/wa-template', 'orders:r', async (ctx) => {
    const id = idParam(ctx), o = await db.one('orders', { id });
    if (!o) throw httpErr(404, 'Order not found');
    const store = await core.getSetting('store_name'), cur = await core.getSetting('currency');
    const items = (o.items || []).map((i) => `• ${i.name}${i.variant_name ? ' (' + i.variant_name + ')' : ''} x${i.qty}`).join('\n');
    const kinds = {
      confirm: `Hi ${o.name}, this is ${store}. We received your request ${o.code}:\n${items}\nTotal: ${cur}${o.total}\nCan you confirm the delivery address and pincode?\n${o.address} - ${o.pincode}`,
      payment: `Hi ${o.name}, thank you for your request ${o.code} (total ${cur}${o.total}). Please complete the payment and reply with the payment reference so we can confirm your order.`,
      update: `Hi ${o.name}, an update on your order ${o.code} from ${store}: `,
      custom: `Hi ${o.name}, `,
    };
    const kind = kinds[ctx.query.kind] ? ctx.query.kind : 'custom';
    return { phone: normPhone(o.phone).replace(/^\+/, ''), text: kinds[kind] };
  });

  // =====================================================================
  // CUSTOMERS (personal data: view requires customers:r)
  // =====================================================================
  add('GET', '/customers', 'customers:r', async (ctx) => {
    const q = ctx.query, f = { anonymized: 0 };
    if (q.q) f.$or = [{ name: rx(q.q) }, { phone: rx(q.q) }];
    const { limit, offset } = page(q);
    const rows = await db.find('customers', f, { sort: { created_at: -1, id: -1 }, skip: offset, limit, projection: { id: 1, name: 1, phone: 1, email: 1, created_at: 1 } });
    if (!rows.length) return [];
    const orders = await db.find('orders', { customer_id: { $in: rows.map((r) => r.id) } }, { projection: { customer_id: 1, total: 1, confirmed_at: 1, status: 1 } });
    const n = new Map(), spent = new Map();
    for (const o of orders) {
      n.set(o.customer_id, (n.get(o.customer_id) || 0) + 1);
      if (o.confirmed_at != null && o.status !== 'cancelled' && o.status !== 'refunded') spent.set(o.customer_id, (spent.get(o.customer_id) || 0) + o.total);
    }
    return rows.map((c) => ({ ...c, orders: n.get(c.id) || 0, spent: spent.get(c.id) || 0 }));
  });
  add('GET', '/customers/:id', 'customers:r', async (ctx) => {
    const id = idParam(ctx), c = await db.one('customers', { id });
    if (!c) throw httpErr(404, 'Customer not found');
    return { ...c, orders: await db.find('orders', { customer_id: id }, { sort: { created_at: -1, id: -1 }, limit: 100, projection: { id: 1, code: 1, status: 1, total: 1, created_at: 1 } }) };
  });
  add('PUT', '/customers/:id', 'customers:w', async (ctx) => {
    const id = idParam(ctx), d = new F(ctx.body).str('name', { req: true, min: 2, max: 80 }).str('email', { max: 120, re: /^[^\s@]+@[^\s@]+\.[^\s@]+$/, msg: 'Enter a valid email' })
      .str('address', { max: 300 }).str('pincode', { max: 10 }).str('notes', { max: 2000 }).done();
    if (!(await db.update('customers', { id, anonymized: 0 }, { name: d.name, email: d.email, address: d.address, pincode: d.pincode, notes: d.notes }))) throw httpErr(404, 'Customer not found');
    await audit(ctx, 'customer.update', 'customer', id); return { ok: true };
  });
  add('POST', '/customers/:id/anonymize', 'customers:w', async (ctx) => {
    const id = idParam(ctx), c = await db.one('customers', { id, anonymized: 0 }, { projection: { id: 1 } });
    if (!c) throw httpErr(404, 'Customer not found');
    if (await db.one('orders', { customer_id: id, status: { $nin: ['delivered', 'cancelled', 'refunded'] } }, { projection: { id: 1 } })) throw httpErr(409, 'This customer has orders in progress');
    await db.tx(async () => {
      await db.updateMany('orders', { customer_id: id }, { name: 'Deleted customer', phone: 'deleted', address: 'deleted', pincode: '000000' });
      await db.update('customers', { id }, { name: 'Deleted customer', phone: 'deleted-' + id, email: null, address: null, pincode: null, notes: null, anonymized: 1 });
    });
    await audit(ctx, 'customer.anonymize', 'customer', id); return { ok: true };
  });

  // =====================================================================
  // PROMOTIONS
  // =====================================================================
  function promoInput(b) {
    const f = new F(b).str('code', { req: true, re: /^[A-Za-z0-9_-]{3,30}$/, msg: '3-30 letters, numbers, - or _' }).en('kind', ['percent', 'fixed'])
      .num('value', { req: true, min: 0.01, max: 10000000 }).num('min_subtotal', { min: 0, max: 10000000 }).num('usage_limit', { int: true, min: 1, max: 10000000 }).bool('active', 1)
      .str('starts', { re: /^\d{4}-\d{2}-\d{2}$/, msg: 'Use YYYY-MM-DD' }).str('ends', { re: /^\d{4}-\d{2}-\d{2}$/, msg: 'Use YYYY-MM-DD' });
    const o = f.out;
    if (o.kind === 'percent' && o.value > 100) f.bad('value', 'Percent cannot exceed 100');
    const s = o.starts ? dayMs(o.starts) : null, e = o.ends ? dayMs(o.ends, true) : null;
    if (o.starts && s === null) f.bad('starts', 'Invalid date'); if (o.ends && e === null) f.bad('ends', 'Invalid date');
    if (s && e && e <= s) f.bad('ends', 'End date must be after the start date');
    f.done(); return { ...o, starts_at: s, ends_at: e, min_subtotal: o.min_subtotal || 0 };
  }
  const promoFields = (p) => ({ code: p.code, kind: p.kind, value: p.value, min_subtotal: p.min_subtotal, starts_at: p.starts_at, ends_at: p.ends_at, usage_limit: p.usage_limit, active: p.active });
  add('GET', '/promotions', 'promotions:r', async () => db.find('promotions', {}, { sort: { created_at: -1, id: -1 } }));
  add('POST', '/promotions', 'promotions:w', async (ctx) => {
    const p = promoInput(ctx.body), dup = new VErr({ code: 'This code already exists' });
    if (await db.one('promotions', { code: p.code }, { ...CI, projection: { id: 1 } })) throw dup;
    let id;
    try { id = await db.insert('promotions', { ...promoFields(p), used: 0, created_at: now() }); }
    catch (e) { if (db.isDuplicate(e)) throw dup; throw e; }
    await audit(ctx, 'promotion.create', 'promotion', id, { code: p.code, kind: p.kind, value: p.value }); ctx.status = 201; return { id };
  });
  add('PUT', '/promotions/:id', 'promotions:w', async (ctx) => {
    const id = idParam(ctx), p = promoInput(ctx.body), dup = new VErr({ code: 'This code already exists' });
    if (await db.one('promotions', { code: p.code, id: { $ne: id } }, { ...CI, projection: { id: 1 } })) throw dup;
    let n;
    try { n = await db.update('promotions', { id }, promoFields(p)); }
    catch (e) { if (db.isDuplicate(e)) throw dup; throw e; }
    if (!n) throw httpErr(404, 'Promotion not found');
    await audit(ctx, 'promotion.update', 'promotion', id, { code: p.code, active: p.active }); return { ok: true };
  });
  add('DELETE', '/promotions/:id', 'promotions:w', async (ctx) => { const id = idParam(ctx); await db.deleteOne('promotions', { id }); await audit(ctx, 'promotion.delete', 'promotion', id); return { ok: true }; });

  // =====================================================================
  // FINANCE / OVERVIEW
  // =====================================================================
  function range(q, days = 30) {
    const to = q.to ? dayMs(q.to, true) : now() + 1, from = q.from ? dayMs(q.from) : to - days * 86400000;
    if (from === null || to === null || to <= from || to - from > 800 * 86400000) throw httpErr(400, 'Invalid date range');
    return [from, to];
  }
  add('GET', '/finance', 'finance:r', async (ctx) => { const [from, to] = range(ctx.query); return { from, to, ...(await core.finance(from, to)), daily: await core.dailySales(from, to) }; });
  add('GET', '/expenses', 'finance:r', async (ctx) => {
    const [from, to] = range(ctx.query, 90);
    const rows = await db.find('expenses', { ts: { $gte: from, $lt: to } }, { sort: { ts: -1, id: -1 }, limit: 200 });
    const [orders, adm] = await Promise.all([
      db.find('orders', { id: { $in: uniq(rows.map((r) => r.order_id)) } }, { projection: { id: 1, code: 1 } }),
      db.find('admins', { id: { $in: uniq(rows.map((r) => r.admin_id)) } }, { projection: { id: 1, username: 1 } }),
    ]);
    const o = by(orders), a = by(adm);
    return rows.map((e) => ({ ...e, order_code: o.has(e.order_id) ? o.get(e.order_id).code : null, username: a.has(e.admin_id) ? a.get(e.admin_id).username : null }));
  });
  add('POST', '/expenses', 'finance:w', async (ctx) => {
    const d = new F(ctx.body).en('kind', EXPENSE_KINDS).num('amount', { req: true, min: 0.01, max: 10000000 }).str('note', { max: 200 })
      .str('date', { re: /^\d{4}-\d{2}-\d{2}$/, msg: 'Use YYYY-MM-DD' }).done();
    const ts = d.date ? dayMs(d.date) : now();
    if (ts === null) throw new VErr({ date: 'Invalid date' });
    await db.insert('expenses', { order_id: null, kind: d.kind, amount: d.amount, note: d.note, ts, admin_id: ctx.admin.id });
    await audit(ctx, 'expense.create', 'expense', null, d); ctx.status = 201; return { ok: true };
  });
  add('DELETE', '/expenses/:id', 'finance:w', async (ctx) => { const id = idParam(ctx); await db.deleteOne('expenses', { id }); await audit(ctx, 'expense.delete', 'expense', id); return { ok: true }; });

  add('GET', '/overview', null, async (ctx) => {
    const role = ctx.admin.role, o = {};
    const cnt = (s) => db.count('orders', { status: s });
    if (can(role, 'orders:r')) {
      const [a, b, c, d, e] = await Promise.all(['new_request', 'contacted', 'awaiting_payment', 'confirmed', 'ordered_from_supplier'].map(cnt));
      o.requests = { new_request: a, contacted: b, awaiting_payment: c };
      o.to_ship = d + e;
      o.recent = await db.find('orders', {}, { sort: { created_at: -1, id: -1 }, limit: 8, projection: { id: 1, code: 1, name: 1, status: 1, total: 1, created_at: 1 } });
    }
    if (can(role, 'inventory:r')) {
      const [prods, vars] = await Promise.all([db.find('products', {}, { projection: { id: 1, stock: 1, low_stock: 1 } }), db.find('variants', {}, { projection: { product_id: 1, stock: 1 } })]);
      const hasV = new Set(vars.map((v) => v.product_id)), lim = new Map(prods.map((p) => [p.id, p.low_stock]));
      let n = 0;
      for (const p of prods) if (!hasV.has(p.id) && p.stock <= p.low_stock) n++;
      for (const v of vars) if (lim.has(v.product_id) && v.stock <= lim.get(v.product_id)) n++;
      o.low_stock = n;
    }
    if (can(role, 'products:r')) o.products = { total: await db.count('products'), published: await db.count('products', { published: 1 }) };
    if (can(role, 'finance:r')) {
      const to = now() + 1, from = to - 30 * 86400000;
      o.finance = await core.finance(from, to); o.daily = await core.dailySales(to - 14 * 86400000, to);
    }
    return o;
  });

  // =====================================================================
  // WEBSITE SETTINGS
  // =====================================================================
  const mediaOrEmpty = async (f, k) => {
    const v = f.i[k];
    if (v === '' || v == null) { f.out[k] = ''; return; }
    if (typeof v !== 'string' || !/^[0-9a-f]{24}$/.test(v) || !(await db.one('media', { id: v }, { projection: { id: 1 } }))) f.bad(k, 'Unknown image');
    else f.out[k] = v;
  };
  const SETTING_VALIDATORS = {
    store_name: (v) => new F({ v }).str('v', { req: true, max: 60 }).done().v,
    whatsapp_number: (v) => { const d = String(v || '').replace(/[^\d]/g, ''); if (v !== '' && v != null && (d.length < 8 || d.length > 15)) throw new VErr({ whatsapp_number: 'Enter the number with country code, digits only (8-15 digits)' }); return d; },
    currency: (v) => new F({ v }).str('v', { req: true, max: 4 }).done().v,
    free_over: (v) => new F({ v }).num('v', { req: true, min: 0, max: 10000000 }).done().v,
    shipping: (v) => new F({ v }).num('v', { req: true, min: 0, max: 10000000 }).done().v,
    announcement: (v) => { if (!Array.isArray(v) || v.length > 8) throw new VErr({ announcement: 'Up to 8 messages' }); return v.map((s) => { const x = new F({ s }).str('s', { req: true, max: 120 }).done().s; return x; }); },
    contact: (v) => new F(v).str('email', { max: 120, re: /^[^\s@]+@[^\s@]+\.[^\s@]+$/, msg: 'Enter a valid email' }).str('phone', { max: 30 }).str('address', { max: 300 }).str('hours', { max: 120 }).done(),
    policies: (v) => { const o = new F(v).str('returns', { max: 8000 }).str('shipping', { max: 8000 }).str('privacy', { max: 8000 }).str('terms', { max: 8000 }).done(); return Object.fromEntries(Object.entries(o).map(([k, x]) => [k, x || ''])); },
    banners: async (v) => {
      if (!Array.isArray(v) || v.length > 6) throw new VErr({ banners: 'Up to 6 banners' });
      const out = [];
      for (let i = 0; i < v.length; i++) {
        const f = new F(v[i]).str('title', { req: true, max: 80 }).str('subtitle', { max: 160 }).str('category', { max: 40 }).str('c1', { re: HEX }).str('c2', { re: HEX }); await mediaOrEmpty(f, 'media');
        if (Object.keys(f.err).length) throw new VErr({ banners: `Banner ${i + 1}: ${Object.values(f.err)[0]}` });
        out.push({ title: f.out.title, subtitle: f.out.subtitle || '', category: f.out.category || '', c1: f.out.c1 || '#1F2A24', c2: f.out.c2 || '#3B5246', media: f.out.media });
      }
      return out;
    },
    home_sections: (v) => {
      if (!Array.isArray(v) || v.length > 14) throw new VErr({ home_sections: 'Up to 14 sections' });
      return v.map((s, i) => { const f = new F(s).en('type', ['categories', 'deals', 'bestsellers', 'category', 'each_category']).str('title', { max: 60 }).str('category', { max: 40 }).bool('enabled', 1);
        if (Object.keys(f.err).length) throw new VErr({ home_sections: `Section ${i + 1}: ${Object.values(f.err)[0]}` });
        if (f.out.type === 'category' && !f.out.category) throw new VErr({ home_sections: `Section ${i + 1}: choose a category` });
        return { type: f.out.type, title: f.out.title || '', category: f.out.category || '', enabled: !!f.out.enabled }; });
    },
    logo_icon: async (v) => { const f = new F({}); f.i = { v }; await mediaOrEmpty(f, 'v'); f.done(); return f.out.v; },
    logo_wordmark: async (v) => { const f = new F({}); f.i = { v }; await mediaOrEmpty(f, 'v'); f.done(); return f.out.v; },
  };
  add('GET', '/settings', 'settings:r', async () => core.allSettings());
  add('PUT', '/settings', 'settings:w', async (ctx) => {
    const b = ctx.body, keys = Object.keys(b || {});
    if (!keys.length) throw httpErr(400, 'Nothing to update');
    const out = {}, errs = {};
    for (const k of keys) {
      if (!Object.prototype.hasOwnProperty.call(SETTING_VALIDATORS, k)) { errs[k] = 'Unknown setting'; continue; }
      try { out[k] = await SETTING_VALIDATORS[k](b[k]); } catch (e) { if (e instanceof VErr) Object.assign(errs, e.fields); else throw e; }
    }
    if (Object.keys(errs).length) throw new VErr(errs);
    const before = {};
    await db.tx(async () => { for (const k of keys) { before[k] = await core.getSetting(k); await core.setSetting(k, out[k]); } });
    const short = (x) => JSON.stringify(x).slice(0, 200);
    await audit(ctx, 'settings.update', 'settings', keys.join(','), Object.fromEntries(keys.map((k) => [k, k === 'policies' ? 'updated' : { from: short(before[k]), to: short(out[k]) }]))); return core.allSettings();
  }, { limit: 256 * 1024 });
  add('POST', '/media', 'settings:w', async (ctx) => {
    const id = await saveMedia(ctx.body && ctx.body.data, 1536 * 1024);
    await audit(ctx, 'media.upload', 'media', id); ctx.status = 201; return { id, url: '/media/' + id };
  }, { limit: 3 * 1024 * 1024 });

  // =====================================================================
  // SECURITY: audit log, sessions, users
  // =====================================================================
  add('GET', '/security/audit', 'security:r', async (ctx) => {
    const q = ctx.query, and = [], { limit, offset } = page(q);
    if (q.action) and.push({ action: rx(q.action) });
    if (q.user) and.push({ username: String(q.user) });
    return db.find('audit', and.length ? { $and: and } : {}, { sort: { id: -1 }, skip: offset, limit });
  });
  add('GET', '/security/sessions', null, async (ctx) => {
    const all = ctx.query.all === '1' && can(ctx.admin.role, 'security:r');
    const rows = await db.find('sessions', all ? {} : { admin_id: ctx.admin.id }, { sort: { last_seen: -1 }, projection: { id: 1, admin_id: 1, created_at: 1, last_seen: 1, expires_at: 1, ip: 1, ua: 1 } });
    const adm = by(await db.find('admins', { id: { $in: uniq(rows.map((r) => r.admin_id)) } }, { projection: { id: 1, username: 1 } }));
    return rows.filter((s) => adm.has(s.admin_id)).map(({ admin_id, ...s }) => ({ ...s, username: adm.get(admin_id).username, current: s.id === ctx.session.id }));
  });
  add('DELETE', '/security/sessions/:id', null, async (ctx) => {
    const s = await db.one('sessions', { id: ctx.params.id });
    if (!s || (s.admin_id !== ctx.admin.id && !can(ctx.admin.role, 'security:w'))) throw httpErr(404, 'Session not found');
    await db.deleteOne('sessions', { id: s.id }); await audit(ctx, 'session.revoke', 'admin', s.admin_id); return { ok: true };
  });
  add('GET', '/security/status', 'security:r', async () => {
    const admins = await db.find('admins', {}, { projection: { role: 1, totp_enabled: 1, disabled: 1 } });
    const checks = [
      { ok: cfg.cookieSecure, label: 'Secure cookies (HTTPS only)', fix: 'Set NODE_ENV=production and serve the site over HTTPS' },
      { ok: cfg.prod, label: 'Production mode', fix: 'Set NODE_ENV=production' },
      { ok: cfg.appSecret.length >= 32 && !!process.env.APP_SECRET, label: 'APP_SECRET configured', fix: 'Set APP_SECRET to 32+ random characters' },
      { ok: admins.filter((a) => !a.disabled).every((a) => a.totp_enabled), label: 'Two-factor enabled for every active admin', fix: 'Each admin can enable 2FA under Security' },
      { ok: !!(await core.getSetting('whatsapp_number')), label: 'WhatsApp number configured', fix: 'Set it in Website Settings' },
    ];
    return { checks, admin_path: cfg.adminPath, trust_proxy: cfg.trustProxy, admins: admins.length, rate_limiting: 'in-memory (per server process)' };
  });
  const roleEn = ['owner', 'manager', 'support'];
  add('GET', '/security/users', 'security:r', async () =>
    db.find('admins', {}, { sort: { id: 1 }, projection: { id: 1, username: 1, name: 1, role: 1, totp_enabled: 1, disabled: 1, must_change: 1, failed: 1, locked_until: 1, created_at: 1, last_login: 1 } }));
  add('POST', '/security/users', 'security:w', async (ctx) => {
    const d = new F(ctx.body).str('username', { req: true, re: /^[a-zA-Z0-9._-]{3,40}$/, msg: '3-40 letters, numbers, . _ -' }).str('name', { req: true, max: 80 })
      .en('role', roleEn).str('password', { req: true, max: 300, trim: false }).done();
    const prob = sec.passwordProblem(d.password, d.username); if (prob) throw new VErr({ password: prob });
    const dup = new VErr({ username: 'Username already exists' });
    if (await db.one('admins', { username: d.username }, { ...CI, projection: { id: 1 } })) throw dup;
    let id;
    try {
      id = await db.insert('admins', { username: d.username, name: d.name, role: d.role, pass_hash: await sec.hashPassword(d.password), totp_secret: null, totp_enabled: 0, totp_last: 0,
        failed: 0, locked_until: 0, disabled: 0, must_change: 1, created_at: now(), last_login: null });
    } catch (e) { if (db.isDuplicate(e)) throw dup; throw e; }
    await audit(ctx, 'user.create', 'admin', id, { username: d.username, role: d.role }); ctx.status = 201; return { id };
  });
  const ownersLeft = (exceptId) => db.count('admins', { role: 'owner', disabled: 0, id: { $ne: exceptId } });
  add('PUT', '/security/users/:id', 'security:w', async (ctx) => {
    const id = idParam(ctx), u = await db.one('admins', { id });
    if (!u) throw httpErr(404, 'User not found');
    const d = new F(ctx.body).str('name', { req: true, max: 80 }).en('role', roleEn).bool('disabled').done();
    if (id === ctx.admin.id && (d.role !== u.role || d.disabled)) throw httpErr(409, 'You cannot change your own role or disable yourself');
    if (u.role === 'owner' && (d.role !== 'owner' || d.disabled) && (await ownersLeft(id)) === 0) throw httpErr(409, 'There must be at least one active owner');
    await db.update('admins', { id }, { name: d.name, role: d.role, disabled: d.disabled });
    if (d.disabled || d.role !== u.role) await db.deleteMany('sessions', { admin_id: id });
    await audit(ctx, 'user.update', 'admin', id, { role: [u.role, d.role], disabled: [u.disabled, d.disabled] }); return { ok: true };
  });
  add('POST', '/security/users/:id/reset-password', 'security:w', async (ctx) => {
    const id = idParam(ctx), u = await db.one('admins', { id });
    if (!u) throw httpErr(404, 'User not found');
    const d = new F(ctx.body).str('password', { req: true, max: 300, trim: false }).done();
    const prob = sec.passwordProblem(d.password, u.username); if (prob) throw new VErr({ password: prob });
    await db.update('admins', { id }, { pass_hash: await sec.hashPassword(d.password), must_change: 1, failed: 0, locked_until: 0 });
    await db.deleteMany('sessions', { admin_id: id });
    await audit(ctx, 'user.reset_password', 'admin', id); return { ok: true };
  });
  add('POST', '/security/users/:id/unlock', 'security:w', async (ctx) => {
    const id = idParam(ctx); await db.update('admins', { id }, { failed: 0, locked_until: 0 }); await audit(ctx, 'user.unlock', 'admin', id); return { ok: true };
  });
  add('POST', '/security/users/:id/disable-2fa', 'security:w', async (ctx) => {
    const id = idParam(ctx); if (id === ctx.admin.id) throw httpErr(409, 'Use the Security page to disable your own 2FA');
    await db.update('admins', { id }, { totp_enabled: 0, totp_secret: null, totp_last: 0 }); await db.deleteMany('recovery_codes', { admin_id: id }); await db.deleteMany('sessions', { admin_id: id });
    await audit(ctx, 'user.disable_2fa', 'admin', id); return { ok: true };
  });

  return routes;
}

module.exports = { register, can, permList, sniff };
