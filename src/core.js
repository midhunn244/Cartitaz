'use strict';
const crypto = require('crypto');
const { httpErr, money } = require('./http');
const { COLLATION } = require('./db');

const STATUSES = ['new_request', 'contacted', 'awaiting_payment', 'confirmed', 'ordered_from_supplier', 'shipped', 'out_for_delivery', 'delivered', 'cancelled', 'refunded'];
const NEXT = {
  new_request: ['contacted', 'awaiting_payment', 'confirmed', 'cancelled'],
  contacted: ['awaiting_payment', 'confirmed', 'cancelled'],
  awaiting_payment: ['confirmed', 'cancelled'],
  confirmed: ['ordered_from_supplier', 'shipped', 'cancelled'],
  ordered_from_supplier: ['shipped', 'cancelled'],
  shipped: ['out_for_delivery', 'delivered', 'cancelled'],
  out_for_delivery: ['delivered', 'cancelled'],
  delivered: [], cancelled: [], refunded: [],
};
const REQUEST_STATUSES = ['new_request', 'contacted', 'awaiting_payment'];
// Orders that count as real sales once a human has confirmed them
const SALE_STATUSES = ['confirmed', 'ordered_from_supplier', 'shipped', 'out_for_delivery', 'delivered', 'refunded'];
const STAGE = { new_request: 0, contacted: 0, awaiting_payment: 0, confirmed: 1, ordered_from_supplier: 2, shipped: 3, out_for_delivery: 4, delivered: 5 };
const LABEL = { new_request: 'Request received', contacted: 'We have contacted you', awaiting_payment: 'Awaiting payment', confirmed: 'Confirmed',
  ordered_from_supplier: 'Processing', shipped: 'Shipped', out_for_delivery: 'Out for delivery', delivered: 'Delivered', cancelled: 'Cancelled', refunded: 'Refunded' };

const DEFAULT_SECTIONS = [
  { type: 'categories', title: 'Shop by category', category: '', enabled: true },
  { type: 'deals', title: 'Deals of the day', category: '', enabled: true },
  { type: 'bestsellers', title: 'Best sellers', category: '', enabled: true },
  { type: 'each_category', title: 'Best of', category: '', enabled: true },
];
const DEFAULTS = {
  store_name: 'Cartitaz', whatsapp_number: '', currency: '$', free_over: 100, shipping: 4,
  announcement: ['Order in minutes on WhatsApp', '7-day easy returns'],
  contact: { email: '', phone: '', address: '', hours: '' },
  policies: { returns: '', shipping: '', privacy: '', terms: '' },
  banners: [], home_sections: DEFAULT_SECTIONS, logo_icon: '', logo_wordmark: '',
};

function makeCore(db) {
  const now = () => Date.now();

  async function getSetting(key) {
    const r = await db.one('settings', { key });
    return r && r.value !== undefined && r.value !== null ? r.value : DEFAULTS[key];
  }
  async function setSetting(key, val) {
    await db.update('settings', { key }, { $set: { value: val } }, { upsert: true });
  }
  async function allSettings() {
    const keys = Object.keys(DEFAULTS);
    const rows = await db.find('settings', { key: { $in: keys } });
    const m = new Map(rows.map((r) => [r.key, r.value]));
    return Object.fromEntries(keys.map((k) => [k, m.has(k) && m.get(k) != null ? m.get(k) : DEFAULTS[k]]));
  }

  async function genCode() {
    const A = 'ABCDEFGHJKMNPQRSTVWXYZ23456789';
    for (let t = 0; t < 8; t++) {
      const b = crypto.randomBytes(7); let s = 'CT-';
      for (const x of b) s += A[x % A.length];
      if (!(await db.one('orders', { code: s }, { projection: { id: 1 } }))) return s;
    }
    throw httpErr(500, 'Could not allocate an order code');
  }

  async function calcPromo(code, subtotal) {
    if (!code) return { ok: true, discount: 0, code: null };
    const p = await db.one('promotions', { code }, { collation: COLLATION });
    const t = now();
    if (!p || !p.active) return { ok: false, message: 'This promo code is not valid' };
    if ((p.starts_at && t < p.starts_at) || (p.ends_at && t > p.ends_at)) return { ok: false, message: 'This promo code is not active right now' };
    if (p.usage_limit != null && p.used >= p.usage_limit) return { ok: false, message: 'This promo code has been fully used' };
    if (subtotal < p.min_subtotal) return { ok: false, message: `Minimum order for this code is ${p.min_subtotal}` };
    let d = p.kind === 'percent' ? subtotal * p.value / 100 : p.value;
    d = money(Math.min(d, subtotal));
    return { ok: true, discount: d, code: p.code, id: p.id };
  }

  // stock rows for a product (variant-aware)
  async function stockOf(productId, variantId) {
    if (variantId) {
      const v = await db.one('variants', { id: variantId, product_id: productId }, { projection: { stock: 1 } });
      return v ? v.stock : null;
    }
    const hasVariants = await db.one('variants', { product_id: productId }, { projection: { id: 1 } });
    if (hasVariants) return null; // must choose a variant
    const p = await db.one('products', { id: productId }, { projection: { stock: 1 } });
    return p ? p.stock : null;
  }
  // Every decrease is a single guarded update ("stock >= amount"), so concurrent requests can never drive stock below zero.
  async function moveStock(productId, variantId, delta, reason, orderId, adminId) {
    const guard = delta < 0 ? { stock: { $gte: -delta } } : {};
    const n = variantId
      ? await db.update('variants', { id: variantId, ...guard }, { $inc: { stock: delta } })
      : await db.update('products', { id: productId, ...guard }, { $inc: { stock: delta }, $set: { updated_at: now() } });
    if (!n && delta < 0) throw httpErr(409, 'Not enough stock. Adjust inventory first.');
    await db.insert('stock_moves', { ts: now(), product_id: productId, variant_id: variantId == null ? null : variantId, delta, reason, order_id: orderId == null ? null : orderId, admin_id: adminId == null ? null : adminId });
  }

  const mkEvent = async (o) => ({ id: await db.nextId('order_events'), ts: o.ts, status: o.status, note: o.note == null ? null : o.note, public_note: o.public_note == null ? null : o.public_note,
    country: o.country == null ? null : o.country, state: o.state == null ? null : o.state, district: o.district == null ? null : o.district,
    place: o.place == null ? null : o.place, admin_id: o.admin_id == null ? null : o.admin_id });

  // Manual status change. Stock is only committed when a human moves an order to "confirmed".
  async function changeStatus(orderId, to, body, adminId) {
    return db.tx(async () => {
      const o = await db.one('orders', { id: orderId });
      if (!o) throw httpErr(404, 'Order not found');
      if (!(NEXT[o.status] || []).includes(to)) throw httpErr(409, `Cannot change an order from "${o.status}" to "${to}"`);
      const t = now(), items = o.items || [];
      const live = async (it) => !!(it.product_id && await db.one('products', { id: it.product_id }, { projection: { id: 1 } })); // product deleted later: nothing to track
      const set = { status: to, updated_at: t };
      const restock = to === 'cancelled' && o.stock_committed, commit = to === 'confirmed' && !o.stock_committed;
      if (commit) {
        const short = [];
        for (const it of items) {
          if (!(await live(it))) continue;
          const have = await stockOf(it.product_id, it.variant_id);
          if (have !== null && have < it.qty) short.push(`${it.name}${it.variant_name ? ' (' + it.variant_name + ')' : ''}: need ${it.qty}, have ${have}`);
        }
        if (short.length) throw httpErr(409, 'Not enough stock: ' + short.join('; ') + '. Adjust inventory first.');
        set.stock_committed = 1; set.confirmed_at = o.confirmed_at == null ? t : o.confirmed_at;
      }
      if (restock) set.stock_committed = 0;
      const ev = await mkEvent({ ts: t, status: to, note: body.note, public_note: body.public_note, country: body.country, state: body.state, district: body.district, place: body.place, admin_id: adminId });
      // Claim the transition first: if someone else changed this order meanwhile, nothing else happens.
      if (!(await db.update('orders', { id: o.id, status: o.status }, { $set: set, $push: { events: ev } }))) throw httpErr(409, 'This order was just changed by someone else. Reload and try again.');
      if (commit) {
        for (const it of items) {
          if (!(await live(it))) continue;
          if ((await stockOf(it.product_id, it.variant_id)) !== null) await moveStock(it.product_id, it.variant_id, -it.qty, 'Order confirmed ' + o.code, o.id, adminId);
        }
        if (o.promo_code) await db.update('promotions', { code: o.promo_code }, { $inc: { used: 1 } }, { collation: COLLATION });
      }
      if (restock) {
        for (const it of items) {
          if (!(await live(it))) continue;
          if ((await stockOf(it.product_id, it.variant_id)) !== null) await moveStock(it.product_id, it.variant_id, it.qty, 'Order cancelled ' + o.code, o.id, adminId);
        }
        if (o.promo_code) await db.update('promotions', { code: o.promo_code, used: { $gt: 0 } }, { $inc: { used: -1 } }, { collation: COLLATION });
      }
      return { from: o.status, to, code: o.code };
    });
  }

  async function recalcTotal(orderId) {
    const o = await db.one('orders', { id: orderId }, { projection: { items: 1, discount: 1, shipping: 1 } });
    const subtotal = money((o.items || []).reduce((s, i) => s + i.qty * i.unit_price, 0));
    const total = money(Math.max(0, subtotal - o.discount + o.shipping));
    await db.update('orders', { id: orderId }, { subtotal, total, updated_at: now() });
  }

  // ---------- Finance: only from recorded data ----------
  const missingCosts = (items) => (items || []).filter((i) => i.unit_cost == null).length;
  async function finance(from, to) {
    const rows = await db.find('orders', { status: { $in: SALE_STATUSES }, confirmed_at: { $gte: from, $lt: to } },
      { projection: { id: 1, subtotal: 1, discount: 1, shipping: 1, total: 1, confirmed_at: 1, items: 1 } });
    const oexp = new Map();
    if (rows.length) for (const e of await db.find('expenses', { order_id: { $in: rows.map((r) => r.id) } }, { projection: { order_id: 1, amount: 1 } })) oexp.set(e.order_id, (oexp.get(e.order_id) || 0) + e.amount);
    const refunds = await db.find('refunds', { ts: { $gte: from, $lt: to } }, { projection: { order_id: 1, amount: 1 } });
    const refOrders = new Map();
    if (refunds.length) for (const o of await db.find('orders', { id: { $in: [...new Set(refunds.map((r) => r.order_id))] } }, { projection: { id: 1, items: 1 } })) refOrders.set(o.id, missingCosts(o.items));
    const general = (await db.find('expenses', { order_id: null, ts: { $gte: from, $lt: to } }, { projection: { amount: 1 } })).reduce((s, e) => s + e.amount, 0);
    const f = { orders: rows.length, subtotal: 0, discounts: 0, shipping_charged: 0, net_sales: 0, refunds: 0, cogs: 0, order_expenses: 0,
      general_expenses: money(general), complete_orders: 0, incomplete_orders: 0, incomplete_sales: 0, profit_basis_sales: 0, net_profit: 0, margin: null };
    let profitOrders = 0, refundsComplete = 0;
    for (const r of rows) {
      const cogs = (r.items || []).reduce((s, i) => s + (i.unit_cost == null ? 0 : i.unit_cost * i.qty), 0), missing = missingCosts(r.items);
      f.subtotal += r.subtotal; f.discounts += r.discount; f.shipping_charged += r.shipping; f.net_sales += r.total;
      if (missing === 0) {
        const ox = oexp.get(r.id) || 0;
        f.complete_orders++; f.cogs += cogs; f.order_expenses += ox; f.profit_basis_sales += r.total;
        profitOrders += r.total - cogs - ox;
      } else { f.incomplete_orders++; f.incomplete_sales += r.total; }
    }
    for (const r of refunds) { f.refunds += r.amount; if (refOrders.get(r.order_id) === 0) refundsComplete += r.amount; }
    f.net_profit = profitOrders - refundsComplete - general;
    for (const k of ['subtotal', 'discounts', 'shipping_charged', 'net_sales', 'refunds', 'cogs', 'order_expenses', 'incomplete_sales', 'profit_basis_sales', 'net_profit']) f[k] = money(f[k]);
    f.margin = f.profit_basis_sales > 0 ? Math.round(f.net_profit / f.profit_basis_sales * 1000) / 10 : null;
    const pend = await db.find('orders', { status: { $in: REQUEST_STATUSES } }, { projection: { total: 1 } });
    f.pipeline_orders = pend.length; f.pipeline_value = money(pend.reduce((s, o) => s + o.total, 0));
    return f;
  }
  async function dailySales(from, to) {
    const rows = await db.find('orders', { status: { $in: SALE_STATUSES }, confirmed_at: { $gte: from, $lt: to } }, { projection: { total: 1, confirmed_at: 1 } });
    const by = new Map();
    for (const r of rows) {
      const d = new Date(r.confirmed_at).toISOString().slice(0, 10), v = by.get(d) || { sales: 0, n: 0 };
      v.sales += r.total; v.n++; by.set(d, v);
    }
    return [...by.keys()].sort().map((d) => ({ d, sales: money(by.get(d).sales), n: by.get(d).n }));
  }

  async function publicTrack(code, last4) {
    const o = await db.one('orders', { code });
    if (!o || !String(o.phone).endsWith(String(last4))) return null;
    const ev = [...(o.events || [])].sort((a, b) => a.ts - b.ts || a.id - b.id);
    const t = [null, null, null, null, null, null], loc = [null, null, null, null, null, null];
    for (const e of ev) {
      const k = STAGE[e.status];
      if (k === undefined) continue;
      t[k] = new Date(e.ts).toISOString();
      if (e.country || e.state || e.district || e.place) loc[k] = { c: e.country || '', s: e.state || '', d: e.district || '', p: e.place || '' };
    }
    const last = ev[ev.length - 1];
    return { code: o.code, status: o.status, label: LABEL[o.status], stage: STAGE[o.status] === undefined ? 0 : STAGE[o.status],
      final: (o.status === 'cancelled' || o.status === 'refunded') ? o.status : null, t, loc,
      note: last && last.public_note ? last.public_note : '', total: o.total };
  }

  return { getSetting, setSetting, allSettings, genCode, calcPromo, stockOf, moveStock, changeStatus, recalcTotal, finance, dailySales, publicTrack, mkEvent, now };
}

module.exports = { makeCore, STATUSES, NEXT, REQUEST_STATUSES, SALE_STATUSES, LABEL, DEFAULTS, DEFAULT_SECTIONS };
