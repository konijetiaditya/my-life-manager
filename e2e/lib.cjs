const { chromium } = require('playwright');
const URL = 'http://localhost:4173/';
const addDays = (t, n) => { const [y, m, d] = t.split('-').map(Number); const x = new Date(y, m - 1, d + n); return `${x.getFullYear()}-${String(x.getMonth() + 1).padStart(2, '0')}-${String(x.getDate()).padStart(2, '0')}`; };
const fixture = (T) => ({
  settings: { name: 'Aditya' },
  bills: [
    { id: 'b1', name: 'Rent', amount: 10000, category: 'Housing & EMI', dueDate: addDays(T, 5), recurrence: 'monthly', status: 'unpaid', history: [] },
    { id: 'b2', name: 'Laptop repair', amount: 2500, category: 'Other', dueDate: addDays(T, -2), recurrence: 'none', status: 'paid', paidDate: addDays(T, -2), history: [{ date: addDays(T, -2), amount: 2500 }] },
  ],
  ins: [{ id: 'i1', type: 'Health', provider: 'Acme Insurance', name: 'Family Floater', number: 'POL-998877', coverage: 500000, premium: 12000, freq: 'annual', start: addDays(T, -300), expiry: addDays(T, 65), renewal: addDays(T, 65), beneficiary: 'Spouse', owner: 'Self' }],
  inv: [
    { id: 'v1', name: 'Index Fund', category: 'Mutual fund', invested: 150000, units: 10.5, sip: 5000, sipDay: 10, nominee: 'Spouse', txns: [] },
    { id: 'v2', name: 'Stock A', category: 'Stock', invested: 50000, units: 5, sip: 0, sipDay: 0, txns: [] },
  ],
  gold: [{ id: 'g1', name: 'Gold chain', kind: 'Jewellery', purity: '22K', weight: 25.5, amount: 150000, date: addDays(T, -100), making: 5000, gst: 3000 }],
  silver: [{ id: 's1', name: 'Silver coins', kind: 'Coin', purity: '999', weight: 1000, amount: 80000, date: addDays(T, -50) }],
  docs: [{ id: 'd1', name: 'Passport', category: 'Passport & visa', owner: 'Self', expiry: addDays(T, 40), remind: 30 }],
  rem: [{ id: 'r1', title: 'Call plumber', date: addDays(T, 3), time: '10:00', recurrence: 'none', advance: 0, done: false }],
  loans: [{ id: 'l1', name: 'Home loan', kind: 'Home', lender: 'Big Bank', principal: 3000000, outstanding: 2500000, rate: 8.5, emi: 30000, emiDay: 5, start: addDays(T, -700), end: addDays(T, 3000) }],
});
async function launch() { return chromium.launch(); }
async function newPage(browser, opts = {}) {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 820 }, acceptDownloads: true });
  const p = await ctx.newPage();
  p.errs = []; p.on('pageerror', (e) => p.errs.push(e.message));
  if (opts.stubs) await p.addInitScript((s) => { window.__mlmStubs = s; }, opts.stubs);
  await p.goto(URL);
  return p;
}
const tap = async (p, pin) => { for (const c of pin) await p.click(`.pad button[data-p="${c}"]`); await p.waitForTimeout(350); };
async function onboard(p, name = 'Aditya', pin = '4827') {
  await p.fill('#obName', name); await p.click('#obGo');
  await tap(p, pin); await p.waitForSelector('#ptitle:has-text("Confirm")'); await tap(p, pin);
}
async function toHome(p) { await p.waitForSelector('#view h1', { timeout: 20000 }); }
async function setup(browser, opts) { const p = await newPage(browser, opts); await onboard(p); if (opts && opts.skipExtras) {} await toHome(p); return p; }
async function inject(p, extra = {}) { const T = await p.evaluate(() => window.__mlm.today()); const f = { ...fixture(T), ...extra }; await p.evaluate((o) => window.__mlm.inject(o), f); await p.waitForTimeout(300); return T; }
async function unlock(p, pin = '4827') { await p.waitForSelector('.pad'); await tap(p, pin); await p.waitForSelector('#view h1', { timeout: 20000 }); }
async function dumpIDB(p) {
  return p.evaluate(() => new Promise((res, rej) => {
    const r = indexedDB.open('mlm-vault'); r.onerror = () => rej(r.error);
    r.onsuccess = async () => { const db = r.result; const out = {};
      for (const n of Array.from(db.objectStoreNames)) { out[n] = await new Promise((ok) => { const rows = {}; const c = db.transaction(n).objectStore(n).openCursor(); c.onsuccess = () => { const cur = c.result; if (cur) { const v = cur.value; rows[cur.key] = v instanceof Uint8Array ? Array.from(v) : JSON.stringify(v); cur.continue(); } else ok(rows); }; }); }
      db.close(); res(out); };
  }));
}
module.exports = { URL, addDays, fixture, launch, newPage, onboard, tap, toHome, setup, inject, unlock, dumpIDB };
