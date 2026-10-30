'use strict';
const { MongoClient } = require('mongodb');
const { AsyncLocalStorage } = require('node:async_hooks');

// Case-insensitive equality for usernames, category names and promo codes.
const COLLATION = { locale: 'en', strength: 2 };

// Collections whose documents carry a small numeric `id` (allocated from the `counters` collection).
const ID_COLLECTIONS = new Set(['admins', 'audit', 'categories', 'suppliers', 'products', 'product_images', 'variants', 'stock_moves',
  'customers', 'orders', 'expenses', 'refunds', 'promotions', 'order_items', 'order_events']);

const U = { unique: true };
const INDEXES = {
  admins: [[{ id: 1 }, U], [{ username: 1 }, { unique: true, collation: COLLATION, name: 'username_ci' }]],
  sessions: [[{ id: 1 }, U], [{ admin_id: 1, last_seen: -1 }], [{ expires_at: 1 }]],
  recovery_codes: [[{ admin_id: 1, hash: 1 }]],
  audit: [[{ id: 1 }, U], [{ ts: -1 }]],
  categories: [[{ id: 1 }, U], [{ name: 1 }, { unique: true, collation: COLLATION, name: 'name_ci' }]],
  suppliers: [[{ id: 1 }, U]],
  media: [[{ id: 1 }, U]],
  products: [[{ id: 1 }, U], [{ category_id: 1 }], [{ supplier_id: 1 }], [{ published: 1 }], [{ updated_at: -1 }]],
  product_images: [[{ id: 1 }, U], [{ product_id: 1, sort: 1, id: 1 }], [{ media_id: 1 }]],
  variants: [[{ id: 1 }, U], [{ product_id: 1, sort: 1, id: 1 }]],
  stock_moves: [[{ id: 1 }, U], [{ product_id: 1, ts: -1 }], [{ ts: -1, id: -1 }]],
  customers: [[{ id: 1 }, U], [{ phone: 1 }, { unique: true, partialFilterExpression: { anonymized: 0 }, name: 'phone_active' }]],
  orders: [[{ id: 1 }, U], [{ code: 1 }, U], [{ status: 1, created_at: -1 }], [{ customer_id: 1 }], [{ confirmed_at: 1 }], [{ stock_committed: 1 }]],
  expenses: [[{ id: 1 }, U], [{ order_id: 1 }], [{ ts: 1 }]],
  refunds: [[{ id: 1 }, U], [{ order_id: 1 }], [{ ts: 1 }]],
  promotions: [[{ id: 1 }, U], [{ code: 1 }, { unique: true, collation: COLLATION, name: 'code_ci' }]],
  settings: [[{ key: 1 }, U]],
};

const nn = (v) => (v === undefined ? null : v);
const nnObj = (o) => { const r = {}; for (const k of Object.keys(o)) r[k] = nn(o[k]); return r; };
const isOps = (u) => Object.keys(u).some((k) => k.startsWith('$'));
function normUpdate(u) {
  if (!isOps(u)) return { $set: nnObj(u) };
  const out = { ...u };
  if (out.$set) out.$set = nnObj(out.$set);
  return out;
}
// Binary data comes back from the driver as a BSON Binary; hand the app a plain Buffer.
function toBuffer(d) {
  if (Buffer.isBuffer(d)) return d;
  if (d && d.buffer) return Buffer.from(d.buffer.subarray(0, typeof d.position === 'number' ? d.position : d.buffer.length));
  return Buffer.from(d || []);
}

async function open(cfg) {
  const client = new MongoClient(cfg.mongoUri, { appName: 'cartitaz', serverSelectionTimeoutMS: 10000 });
  await client.connect();
  const mdb = client.db(cfg.mongoDb);
  const als = new AsyncLocalStorage();

  let txOk = false;
  try {
    const h = await client.db('admin').command({ hello: 1 });
    txOk = !!(h.setName || h.msg === 'isdbgrid');
  } catch { txOk = false; }

  await Promise.all(Object.entries(INDEXES).map(async ([coll, list]) => { for (const [spec, opts] of list) await mdb.collection(coll).createIndex(spec, opts || {}); }));

  const col = (name) => mdb.collection(name);
  const withSession = (o = {}) => { const s = als.getStore(); return s ? { ...o, session: s } : o; };
  const readOpts = (o = {}) => {
    const r = { projection: { ...(o.projection || {}), _id: 0 } };
    for (const k of ['sort', 'skip', 'limit', 'collation']) if (o[k] !== undefined) r[k] = o[k];
    return withSession(r);
  };
  const writeOpts = (o = {}) => withSession(o);

  async function nextId(name) {
    const r = await col('counters').findOneAndUpdate({ _id: name }, { $inc: { seq: 1 } }, { upsert: true, returnDocument: 'after' });   // deliberately outside any transaction
    const doc = r && Object.prototype.hasOwnProperty.call(r, 'value') && Object.prototype.hasOwnProperty.call(r, 'ok') ? r.value : r;
    return doc.seq;
  }

  const api = {
    COLLATION, toBuffer, nextId,
    isDuplicate: (e) => !!e && e.code === 11000,
    transactional: txOk,

    find: (coll, filter = {}, o = {}) => col(coll).find(filter, readOpts(o)).toArray(),
    one: (coll, filter = {}, o = {}) => col(coll).findOne(filter, readOpts(o)),
    count: (coll, filter = {}, o = {}) => col(coll).countDocuments(filter, writeOpts(o.collation ? { collation: o.collation } : {})),
    aggregate: (coll, pipeline) => col(coll).aggregate(pipeline, writeOpts()).toArray(),

    // Inserts one document; allocates the numeric `id` when the collection uses them. Returns the id.
    async insert(coll, doc) {
      const d = nnObj(doc);
      if (d.id == null && ID_COLLECTIONS.has(coll)) d.id = await nextId(coll);
      await col(coll).insertOne(d, writeOpts());
      return d.id;
    },
    async insertMany(coll, docs) { if (docs.length) await col(coll).insertMany(docs.map(nnObj), writeOpts()); },

    // `update` is either a full operator document ({$set, $inc, $push...}) or a plain object meaning $set.
    // Returns the number of documents MATCHED.
    async update(coll, filter, update, o = {}) { return (await col(coll).updateOne(filter, normUpdate(update), writeOpts(o))).matchedCount; },
    async updateMany(coll, filter, update, o = {}) { return (await col(coll).updateMany(filter, normUpdate(update), writeOpts(o))).matchedCount; },
    async deleteOne(coll, filter) { return (await col(coll).deleteOne(filter, writeOpts())).deletedCount; },
    async deleteMany(coll, filter) { return (await col(coll).deleteMany(filter, writeOpts())).deletedCount; },

    // Runs fn atomically. Multi-document transactions need a replica set (MongoDB Atlas always is one).
    // On a standalone server fn simply runs without a transaction (every stock change is still individually guarded).
    async tx(fn) {
      if (!txOk || als.getStore()) return fn();
      const session = client.startSession();
      try {
        let result;
        await session.withTransaction(async () => { result = await als.run(session, fn); }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' } });
        return result;
      } finally { await session.endSession(); }
    },

    drop: () => mdb.dropDatabase(),
    close: () => client.close(),
  };
  return api;
}
module.exports = { open, COLLATION, toBuffer };
