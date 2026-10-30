'use strict';
// Optional: adds a few DRAFT sample products so you can try the dashboard. Nothing is published to customers.
const { load } = require('../src/config');
const { open } = require('../src/db');
const cfg = load({ ...process.env, NODE_ENV: process.env.NODE_ENV || 'development' });
(async () => {
  const db = await open(cfg);
  if (await db.one('products', {}, { projection: { id: 1 } })) { console.error('Products already exist. Nothing seeded.'); await db.close(); process.exit(1); }
  const t = Date.now();
  const cats = { Bags: 'Bags', Watches: 'Watches', Home: 'Home' };
  const ids = {};
  let sort = 1;
  for (const [name, icon] of Object.entries(cats)) ids[name] = await db.insert('categories', { name, sort: sort++, published: 1, icon, tint: '#E8E5E0' });
  const items = [['Leather Tote', 'Bags', 96, 130, 55], ['Crossbody Bag', 'Bags', 74, 99, 40], ['Slim Watch', 'Watches', 89, null, 48], ['Ceramic Vase', 'Home', 42, 58, 18]];
  for (const [name, cat, price, was, cost] of items) {
    await db.insert('products', { name, brand: null, category_id: ids[cat], supplier_id: null, caption: 'Sample product', description: 'Sample description. Replace with your own.', price, compare_price: was,
      cost_price: cost, sku: null, stock: 10, low_stock: 3, icon: cats[cat], tint: '#E8E5E0', published: 0, internal_notes: null, created_at: t, updated_at: t });
  }
  console.log('Seeded 3 categories and 4 DRAFT products. Review them in the dashboard, then publish what you want.');
  await db.close();
})().catch((e) => { console.error(e.message); process.exit(1); });
