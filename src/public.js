'use strict';
const { F, VErr, httpErr, money, normPhone } = require('./http');
const { LABEL } = require('./core');
const { toBuffer } = require('./db');

function register({ db, core, limiter }) {
  const routes = [];
  const add = (method, path, handler, opts = {}) => routes.push({ method, path, handler, ...opts });

  const publicSettings = async () => {
    const s = await core.allSettings();
    return { store_name: s.store_name, whatsapp_number: s.whatsapp_number, currency: s.currency, free_over: s.free_over, shipping: s.shipping,
      announcement: s.announcement, contact: s.contact, policies: s.policies, banners: s.banners.map((b) => ({ ...b, media: b.media ? '/media/' + b.media : '' })),
      home_sections: s.home_sections, logo_icon: s.logo_icon ? '/media/' + s.logo_icon : '', logo_wordmark: s.logo_wordmark ? '/media/' + s.logo_wordmark : '' };
  };

  // Only published products in published categories. Never includes cost, supplier, notes or exact stock.
  add('GET', '/catalog', async () => {
    const cats = await db.find('categories', { published: 1 }, { sort: { sort: 1, name: 1 }, projection: { id: 1, name: 1, icon: 1, tint: 1 } });
    const catName = new Map(cats.map((c) => [c.id, c.name]));
    const prods = (await db.find('products', { published: 1 }, { sort: { id: 1 },
      projection: { id: 1, name: 1, brand: 1, category_id: 1, caption: 1, description: 1, price: 1, compare_price: 1, icon: 1, tint: 1, low_stock: 1, stock: 1 } }))
      .filter((p) => catName.has(p.category_id)).map((p) => ({ ...p, category: catName.get(p.category_id) }));
    const ids = prods.map((p) => p.id);
    const vars = ids.length ? await db.find('variants', { product_id: { $in: ids } }, { sort: { sort: 1, id: 1 }, projection: { id: 1, product_id: 1, name: 1, stock: 1 } }) : [];
    const imgs = ids.length ? await db.find('product_images', { product_id: { $in: ids } }, { sort: { sort: 1, id: 1 }, projection: { product_id: 1, media_id: 1 } }) : [];
    const sold = Object.fromEntries((await db.aggregate('orders', [{ $match: { stock_committed: 1 } }, { $unwind: '$items' },
      { $group: { _id: '$items.product_id', s: { $sum: '$items.qty' } } }])).map((r) => [r._id, r.s]));
    const vBy = {}, iBy = {};
    for (const v of vars) (vBy[v.product_id] = vBy[v.product_id] || []).push(v);
    for (const i of imgs) (iBy[i.product_id] = iBy[i.product_id] || []).push('/media/' + i.media_id);
    return {
      settings: await publicSettings(), categories: cats,
      products: prods.map((p) => {
        const vs = vBy[p.id] || [], total = vs.length ? vs.reduce((s, v) => s + v.stock, 0) : p.stock;
        return { id: p.id, name: p.name, brand: p.brand || '', category: p.category, caption: p.caption || '', description: p.description || p.caption || '',
          price: p.price, compare_price: p.compare_price, icon: p.icon, tint: p.tint, images: iBy[p.id] || [], sold: sold[p.id] || 0,
          in_stock: total > 0, low_stock: total > 0 && total <= p.low_stock, variants: vs.map((v) => ({ id: v.id, name: v.name, in_stock: v.stock > 0 })) };
      }),
    };
  });

  async function priceCart(items, promo, { checkStock = true } = {}) {
    if (!Array.isArray(items) || !items.length || items.length > 30) throw httpErr(400, 'Your cart is empty');
    const merged = new Map();
    for (const it of items) {
      const f = new F(it).num('product_id', { req: true, int: true, min: 1 }).num('variant_id', { int: true, min: 1 }).num('qty', { req: true, int: true, min: 1, max: 20 });
      if (Object.keys(f.err).length) throw httpErr(400, 'One of the items is invalid');
      const key = f.out.product_id + ':' + (f.out.variant_id || 0);
      const cur = merged.get(key);
      if (cur) cur.qty += f.out.qty; else merged.set(key, { ...f.out });
    }
    const lines = []; let subtotal = 0;
    for (const it of merged.values()) {
      const p = await db.one('products', { id: it.product_id });
      const cat = p && p.category_id != null ? await db.one('categories', { id: p.category_id }, { projection: { published: 1 } }) : null;
      if (!p || !p.published || !cat || !cat.published) throw httpErr(409, 'One of the items is no longer available', { product_id: it.product_id });
      const hasVariants = !!(await db.one('variants', { product_id: p.id }, { projection: { id: 1 } }));
      let vname = null;
      if (hasVariants) {
        const v = it.variant_id ? await db.one('variants', { id: it.variant_id, product_id: p.id }) : null;
        if (!v) throw httpErr(400, `Please choose an option for "${p.name}"`, { product_id: p.id });
        vname = v.name;
      } else if (it.variant_id) throw httpErr(400, 'Invalid option');
      if (it.qty > 20) throw httpErr(400, 'Maximum 20 per item');
      const have = await core.stockOf(p.id, hasVariants ? it.variant_id : null);
      if (checkStock && have !== null && have < it.qty) throw httpErr(409, have > 0 ? `Only ${have} left of "${p.name}"` : `"${p.name}" is out of stock`, { product_id: p.id });
      lines.push({ p, variant_id: hasVariants ? it.variant_id : null, vname, qty: it.qty, price: p.price });
      subtotal += p.price * it.qty;
    }
    subtotal = money(subtotal);
    const pr = await core.calcPromo(promo, subtotal);
    if (!pr.ok) throw httpErr(400, pr.message, { field: 'promo' });
    const freeOver = await core.getSetting('free_over'), ship = await core.getSetting('shipping');
    const shipping = subtotal >= freeOver ? 0 : ship;
    return { lines, subtotal, discount: pr.discount, promo: pr.code, shipping, total: money(subtotal - pr.discount + shipping) };
  }

  add('POST', '/promo', async (ctx) => {
    const h = limiter.hit('promo:' + ctx.ip, 20, 10 * 60 * 1000);
    if (!h.ok) throw httpErr(429, 'Too many attempts. Please wait a few minutes.', { retry: h.retry });
    const d = new F(ctx.body).str('code', { req: true, max: 30 }).num('subtotal', { req: true, min: 0, max: 10000000 }).done();
    const r = await core.calcPromo(d.code, d.subtotal);
    return r.ok ? { ok: true, discount: r.discount } : { ok: false, message: r.message };
  });

  add('POST', '/requests', async (ctx) => {
    const h = limiter.hit('req:' + ctx.ip, 6, 10 * 60 * 1000);
    if (!h.ok) throw httpErr(429, 'Too many requests from your connection. Please wait a few minutes.', { retry: h.retry });
    const b = ctx.body || {};
    if (b.website) throw httpErr(400, 'Invalid request');            // honeypot field must stay empty
    const wa = await core.getSetting('whatsapp_number');
    if (!wa) throw httpErr(503, 'Ordering is not available right now. Please try again later.');
    const f = new F(b).str('name', { req: true, min: 2, max: 80 }).str('phone', { req: true, max: 24 }).str('address', { req: true, min: 8, max: 300 })
      .str('pincode', { req: true, re: /^[A-Za-z0-9 \-]{3,10}$/, msg: 'Enter a valid pincode' }).str('promo', { max: 30 });
    const phone = normPhone(f.out.phone || '');
    if (f.out.phone && !/^\+?[0-9]{8,15}$/.test(phone)) f.bad('phone', 'Enter a valid phone number');
    const d = f.done();
    const cart = await priceCart(b.items, d.promo);
    const code = await core.genCode(), t = Date.now();
    const orderId = await db.tx(async () => {
      let cust = await db.one('customers', { phone, anonymized: 0 }, { projection: { id: 1 } });
      if (cust) await db.update('customers', { id: cust.id }, { name: d.name, address: d.address, pincode: d.pincode });
      else cust = { id: await db.insert('customers', { name: d.name, phone, email: null, address: d.address, pincode: d.pincode, notes: null, anonymized: 0, created_at: t }) };
      const items = [];
      for (const l of cart.lines) items.push({ id: await db.nextId('order_items'), product_id: l.p.id, variant_id: l.variant_id, name: l.p.name, variant_name: l.vname, qty: l.qty,
        unit_price: l.price, unit_cost: l.p.cost_price == null ? null : l.p.cost_price, supplier_id: l.p.supplier_id == null ? null : l.p.supplier_id });
      const events = [await core.mkEvent({ ts: t, status: 'new_request', public_note: 'We received your request and will confirm it on WhatsApp.' })];
      return db.insert('orders', { code, customer_id: cust.id, name: d.name, phone, address: d.address, pincode: d.pincode, status: 'new_request', source: 'whatsapp',
        subtotal: cart.subtotal, discount: cart.discount, shipping: cart.shipping, total: cart.total, promo_code: cart.promo, internal_notes: null, stock_committed: 0,
        confirmed_at: null, created_at: t, updated_at: t, items, events });
    });
    const cur = await core.getSetting('currency'), store = await core.getSetting('store_name');
    const lines = cart.lines.map((l) => `• ${l.p.name}${l.vname ? ' (' + l.vname + ')' : ''} x${l.qty} – ${cur}${money(l.price * l.qty)}`).join('\n');
    const message = `Hello ${store}, I'd like to place an order (Order ID: ${code}):\n\n${lines}\n\nItems: ${cur}${cart.subtotal}` +
      (cart.discount ? `\nDiscount (${cart.promo}): -${cur}${cart.discount}` : '') + `\nDelivery: ${cart.shipping ? cur + cart.shipping : 'Free'}\nTotal: ${cur}${cart.total}\n\n` +
      `Name: ${d.name}\nPhone: ${phone}\nAddress: ${d.address}\nPincode: ${d.pincode}\n\nThis is an order request. Please confirm availability and payment.`;
    ctx.status = 201;
    return { code, order_id: orderId, subtotal: cart.subtotal, discount: cart.discount, shipping: cart.shipping, total: cart.total, whatsapp_number: wa, message };
  }, { limit: 32 * 1024 });

  add('GET', '/track', async (ctx) => {
    const h = limiter.hit('track:' + ctx.ip, 30, 10 * 60 * 1000);
    if (!h.ok) throw httpErr(429, 'Too many lookups. Please wait a few minutes.', { retry: h.retry });
    const code = String(ctx.query.code || '').toUpperCase(), last4 = String(ctx.query.last4 || '');
    if (!/^CT-[A-Z0-9]{7}$/.test(code) || !/^\d{4}$/.test(last4)) throw httpErr(404, 'Order not found');
    const r = await core.publicTrack(code, last4);
    if (!r) throw httpErr(404, 'Order not found');
    return r;
  });

  // images are public only when used by a published product or by a site setting (logo/banners)
  async function mediaPublic(id) {
    if (!/^[0-9a-f]{24}$/.test(id)) return null;
    const m = await db.one('media', { id });
    if (!m) return null;
    const s = await core.allSettings();
    let isPublic = s.logo_icon === id || s.logo_wordmark === id || s.banners.some((b) => b.media === id);
    if (!isPublic) {
      for (const i of await db.find('product_images', { media_id: id }, { projection: { product_id: 1 } })) {
        const p = await db.one('products', { id: i.product_id, published: 1 }, { projection: { category_id: 1 } });
        if (p && p.category_id != null && await db.one('categories', { id: p.category_id, published: 1 }, { projection: { id: 1 } })) { isPublic = true; break; }
      }
    }
    return isPublic ? { mime: m.mime, data: toBuffer(m.data) } : null;
  }
  return { routes, mediaPublic, LABEL };
}
module.exports = { register };
