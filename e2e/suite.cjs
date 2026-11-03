// End-to-end tests against the TEST build in desktop Chromium. They exercise the real app code
// (vault, PIN lock, validation, backup, rendering). They CANNOT test Android-only features.
const fs = require('fs'); const os = require('os'); const path = require('path');
const L = require('./lib.cjs');
const results = []; const only = process.argv[2];
async function t(name, fn, opts) {
  if (only && !name.includes(only)) return;
  const b = await L.launch(); const t0 = Date.now();
  try { await fn(b); results.push({ name, ok: true, ms: Date.now() - t0 }); console.log('PASS', name); }
  catch (e) { results.push({ name, ok: false, error: String(e.stack || e).split('\n').slice(0,4).join(' | ') }); console.log('FAIL', name, '-', String(e.stack || e).split('\n').slice(0, 5).join(' | ')); }
  await b.close();
}
const eq = (a, b, m) => { if (a !== b) throw new Error(`${m || 'eq'}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`); };
const ok = (c, m) => { if (!c) throw new Error(m || 'assertion failed'); };
const tmp = (n, buf) => { const f = path.join(os.tmpdir(), 'mlm-' + n); fs.writeFileSync(f, buf); return f; };
const MARK = 'ZEBRA-MARKER-9137';
const dbText = (d) => JSON.stringify(d);

(async () => {
  await t('onboarding: weak/mismatched PINs rejected, strong PIN accepted', async (b) => {
    const p = await L.newPage(b); await p.fill('#obName', 'Aditya'); await p.click('#obGo');
    await L.tap(p, '1234'); ok((await p.textContent('#lmsg')).includes('too easy'), 'weak PIN message');
    await L.tap(p, '0000'); ok((await p.textContent('#lmsg')).includes('too easy'));
    await L.tap(p, '4827'); await p.waitForSelector('#ptitle:has-text("Confirm")');
    await L.tap(p, '4828'); ok((await p.textContent('#lmsg')).includes('did not match'), 'mismatch');
    await L.tap(p, '4827'); await p.waitForSelector('#ptitle:has-text("Confirm")'); await L.tap(p, '4827');
    await L.toHome(p); ok((await p.textContent('#view h1')).includes('Aditya')); eq(p.errs.length, 0, 'page errors');
  });

  await t('lock: reload shows lock screen with no data in the page; wrong PIN rejected; right PIN restores data', async (b) => {
    const p = await L.setup(b); await L.inject(p); await p.reload();
    await p.waitForSelector('.pad'); const body = await p.content();
    ok(!body.includes('Rent') && !body.includes('Aditya') && !body.includes('Index Fund'), 'data visible while locked');
    eq(await p.innerHTML('#view'), '', 'view must be empty while locked');
    await L.tap(p, '9999'); ok((await p.textContent('#lmsg')).includes('Incorrect PIN'));
    await L.tap(p, '4827'); await p.waitForSelector('#view h1');
    ok((await p.innerText('#view')).includes('Rent'), 'data persisted across reload');
  });

  await t('lockout: 3 wrong PINs cause a wait that survives a reload and blocks the right PIN', async (b) => {
    const p = await L.setup(b); await p.reload(); await p.waitForSelector('.pad');
    for (let i = 0; i < 3; i++) { await L.tap(p, '1111'); await p.waitForTimeout(400); }
    await p.waitForSelector('#lmsg:has-text("Try again in")'); ok(await p.isDisabled('.pad button[data-p="1"]'), 'keys disabled');
    await p.reload(); await p.waitForSelector('.pad'); await p.waitForSelector('#lmsg:has-text("Try again in")', { timeout: 5000 });
    ok(await p.isDisabled('.pad button[data-p="4"]'), 'still disabled after reload');
    await p.evaluate(() => document.querySelectorAll('.pad button').forEach((x) => (x.disabled = false)));
    await L.tap(p, '4827'); await p.waitForTimeout(800);
    eq(await p.locator('#view h1').count(), 0, 'correct PIN must not open during the wait (even with keys force-enabled)');
  });

  await t('storage: no readable data in IndexedDB/localStorage; files are encrypted', async (b) => {
    const p = await L.setup(b);
    const T = await L.inject(p, { bills: [{ id: 'b9', name: MARK, amount: 1, category: 'Other', dueDate: '2030-01-01', recurrence: 'none', status: 'unpaid', history: [] }] });
    await p.waitForTimeout(500);
    const pdf = await (async () => { const q = await b.newPage(); await q.setContent('<h1>Secret passport text ' + MARK + '</h1>'); const x = await q.pdf(); await q.close(); return x; })();
    await p.evaluate(() => (location.hash = 'docs')); await p.click('[data-a="addDoc"]');
    await p.fill('#f_name', 'Doc1'); await p.setInputFiles('#f_file', tmp('a.pdf', pdf)); await p.click('#mform button[type=submit]'); await p.waitForTimeout(900);
    const db = await L.dumpIDB(p); const txt = dbText(db);
    for (const s of [MARK, 'Aditya', 'Rent', '%PDF', 'Passport']) ok(!txt.includes(s), 'plaintext found in IndexedDB: ' + s);
    ok(Object.keys(db.files).length === 1, 'one encrypted file stored');
    const bytes = Object.values(db.files)[0]; const asText = Buffer.from(bytes).toString('latin1'); ok(!asText.includes('%PDF') && !asText.includes(MARK), 'file bytes readable');
    eq(await p.evaluate(() => localStorage.length), 0, 'localStorage must be empty');
  });

  await t('tamper: a modified vault is detected, not opened', async (b) => {
    const p = await L.setup(b); await L.inject(p); await p.waitForTimeout(500);
    await p.evaluate(() => new Promise((res) => { const r = indexedDB.open('mlm-vault'); r.onsuccess = () => { const db = r.result; const tx = db.transaction('vault', 'readwrite'); const s = tx.objectStore('vault'); const g = s.get('main'); g.onsuccess = () => { const v = g.result; v[v.length - 3] ^= 0xff; s.put(v, 'main'); }; tx.oncomplete = () => { db.close(); res(); }; }; }));
    await p.reload(); await p.waitForSelector('.pad'); await L.tap(p, '4827');
    await p.waitForSelector('h1:has-text("cannot be read")', { timeout: 8000 });
    eq(await p.locator('#view h1').count(), 0);
  });

  await t('upload validation: bad names, fake PDFs, wrong types, oversize are refused', async (b) => {
    const p = await L.setup(b); await p.evaluate(() => (location.hash = 'docs'));
    const tryUp = async (name, buf) => { await p.click('[data-a="addDoc"]'); await p.fill('#f_name', 'X'); await p.setInputFiles('#f_file', tmp(name, buf)); await p.click('#mform button[type=submit]'); await p.waitForTimeout(500); const e = await p.textContent('.fld[data-k="file"] .err'); await p.click('[data-a="close"]'); return e; };
    ok((await tryUp('fake.pdf', Buffer.from('MZ this is not a pdf'))).length > 0, 'text renamed .pdf');
    ok((await tryUp('run.exe', Buffer.from('%PDF-1.4 hi'))).length > 0, 'exe extension');
    const png = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex'); ok((await tryUp('wrong.pdf', png)).length > 0, 'png content with .pdf name');
    ok((await tryUp('big.pdf', Buffer.concat([Buffer.from('%PDF-1.4\n'), Buffer.alloc(11 * 1048576)]))).length > 0, '11 MB file');
    eq(Object.keys(await L.dumpIDB(p).then((d) => d.files)).length, 0, 'no refused file may be stored');
  });

  await t('attachments: PDF and PNG are stored encrypted and open in the viewer', async (b) => {
    const p = await L.setup(b); await p.evaluate(() => (location.hash = 'docs'));
    const q = await b.newPage(); await q.setContent('<h1>Hello viewer</h1>'); const pdf = await q.pdf(); const png = await q.screenshot(); await q.close();
    for (const [n, buf] of [['one.pdf', pdf], ['two.png', png]]) { await p.click('[data-a="addDoc"]'); await p.fill('#f_name', n); await p.setInputFiles('#f_file', tmp(n, buf)); await p.click('#mform button[type=submit]'); await p.waitForTimeout(700); }
    const rows = p.locator('[data-a="doc"]'); eq(await rows.count(), 2);
    await rows.nth(0).click(); await p.click('[data-a="openDoc"]'); await p.waitForSelector('#vbody canvas, #vbody img', { timeout: 15000 });
    await p.click('[data-a="close2"]'); await p.click('[data-a="close"]'); await rows.nth(1).click(); await p.click('[data-a="openDoc"]');
    await p.waitForSelector('#vbody canvas, #vbody img', { timeout: 15000 }); eq(p.errs.length, 0, 'page errors: ' + p.errs.join(';'));
  });

  await t('XSS: script payloads in every text field are shown as text and never run', async (b) => {
    const p = await L.setup(b); const X = '"><img src=x onerror="window.__pwn=1"><script>window.__pwn=2<\/script>';
    const f = L.fixture('2026-11-02'); const bad = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, typeof v === 'string' && !/^\d{4}-\d{2}-\d{2}$/.test(v) && !['id', 'recurrence', 'status', 'freq', 'time', 'category', 'type', 'kind', 'purity', 'owner'].includes(k) ? X : v]));
    const T = await p.evaluate(() => window.__mlm.today()); const fx = L.fixture(T);
    const data = { settings: { name: 'Aditya' } }; for (const c of ['bills', 'ins', 'inv', 'gold', 'silver', 'docs', 'rem', 'loans']) data[c] = fx[c].map(bad);
    await p.evaluate((o) => window.__mlm.inject(o), data); await p.waitForTimeout(300);
    for (const h of ['home', 'bills', 'loans', 'yearplan', 'insurance', 'invest', 'gold', 'silver', 'metals', 'docs', 'reminders', 'more', 'prefs']) {
      await p.evaluate((h) => (location.hash = h), h); await p.waitForTimeout(150);
      for (const a of ['bill', 'ins', 'inv', 'metal', 'doc', 'loan', 'remEdit']) { const n = await p.locator(`[data-a="${a}"]`).count(); for (let i = 0; i < Math.min(n, 2); i++) { await p.locator(`[data-a="${a}"]`).nth(i).click(); await p.waitForTimeout(100); await p.evaluate(() => { document.getElementById('modalRoot').innerHTML = ''; document.getElementById('modal2').innerHTML = ''; }); } }
    }
    eq(await p.evaluate(() => window.__pwn), undefined, 'payload executed');
    eq(await p.locator('img[src="x"], [onerror]').count(), 0, 'injected element exists');
  });

  await t('CSP: eval, inline script and outside network requests are blocked', async (b) => {
    const p = await L.setup(b); const viol = []; await p.exposeFunction('__v', (x) => viol.push(x));
    await p.evaluate(() => document.addEventListener('securitypolicyviolation', (e) => window.__v(e.violatedDirective)));
    const csp = await p.getAttribute('meta[http-equiv="Content-Security-Policy"]', 'content'); ok(csp && !/'unsafe-eval'|script-src[^;]*'unsafe-inline'/.test(csp), 'CSP string weak: ' + csp);
    const r = await p.evaluate(async () => { const o = {};
      const s = document.createElement('script'); s.textContent = 'window.__inl=1'; document.body.appendChild(s); o.inline = window.__inl ? 'ran' : 'blocked';
      const h = document.createElement('div'); h.innerHTML = '<img src=x onerror="window.__inl2=1">'; document.body.appendChild(h); await new Promise((r) => setTimeout(r, 300)); o.handler = window.__inl2 ? 'ran' : 'blocked';
      try { await fetch('https://example.com/'); o.net = 'ran'; } catch { o.net = 'blocked'; }
      return o; });
    await p.waitForTimeout(300); eq(r.inline, 'blocked'); eq(r.net, 'blocked'); ok(viol.includes('script-src-elem') || viol.includes('script-src'), 'no script violation reported: ' + viol.join(','));
    ok(viol.includes('connect-src'), 'no connect violation: ' + viol.join(','));
    // eval / new Function: run from a script file on a probe page carrying the app's exact CSP.
    await p.route('**/csp-probe.html', (rt) => rt.fulfill({ contentType: 'text/html', body: `<!doctype html><meta http-equiv="Content-Security-Policy" content="${csp}"><script src="/csp-probe.js"></script>` }));
    await p.route('**/csp-probe.js', (rt) => rt.fulfill({ contentType: 'text/javascript', body: `const o={};try{eval('1+1');o.eval='ran'}catch(e){o.eval='blocked'}try{new Function('return 1')();o.fn='ran'}catch(e){o.fn='blocked'}try{setTimeout('window.__t=1',0);o.st='scheduled'}catch(e){o.st='blocked'}window.__res=o;` }));
    await p.goto(L.URL + 'csp-probe.html'); const q = await p.evaluate(() => window.__res); eq(q.eval, 'blocked', 'eval'); eq(q.fn, 'blocked', 'Function');
  });

  await t('re-authentication: policy number stays hidden until the PIN is confirmed', async (b) => {
    const p = await L.setup(b); await L.inject(p); await p.evaluate(() => (location.hash = 'insurance')); await p.click('[data-a="ins"]');
    ok((await p.textContent('#pn')).includes('••••') && !(await p.textContent('#pn')).includes('998877'), 'masked');
    await p.click('[data-a="reveal"]'); await p.waitForSelector('.pad'); await L.tap(p, '1357'); ok((await p.textContent('#lmsg')).includes('Incorrect'));
    ok(!(await p.textContent('#pn')).includes('POL-998877'), 'revealed after wrong PIN');
    await L.tap(p, '4827'); await p.waitForFunction(() => document.getElementById('pn').textContent.includes('POL-998877'));
  });

  await t('auto-lock: leaving the app (immediately setting) and inactivity both lock and wipe the screen', async (b) => {
    const p = await L.setup(b); await L.inject(p); await p.evaluate(() => (location.hash = 'prefs'));
    await p.selectOption('[data-sel="leave"]', '0');
    await p.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, get: () => true }); document.dispatchEvent(new Event('visibilitychange')); });
    await p.waitForSelector('.pad'); eq(await p.innerHTML('#view'), '', 'screen must be blank'); ok(!(await p.content()).includes('Rent'));
    await L.unlock(p).catch(() => {});
  });
  await t('auto-lock: inactivity timer', async (b) => {
    const p = await L.newPage(b); await p.clock.install(); await L.onboard(p); await L.toHome(p); await p.clock.fastForward(6 * 60 * 1000);
    await p.waitForSelector('.pad', { timeout: 5000 }); eq(await p.innerHTML('#view'), '');
  });

  await t('change PIN: old PIN stops working, new PIN works', async (b) => {
    const p = await L.setup(b); await p.evaluate(() => (location.hash = 'prefs')); await p.click('[data-a="chgPin"]'); await p.waitForSelector('.pad'); await L.tap(p, '4827');
    await p.waitForSelector('#ptitle:has-text("new PIN")'); await L.tap(p, '7391'); await p.waitForSelector('#ptitle:has-text("Confirm")'); await L.tap(p, '7391'); await p.waitForTimeout(1200);
    await p.reload(); await p.waitForSelector('.pad'); await L.tap(p, '4827'); ok((await p.textContent('#lmsg')).includes('Incorrect'), 'old PIN accepted');
    await L.tap(p, '7391'); await p.waitForSelector('#view h1');
  });

  await t('backup: encrypted round trip incl. files; wrong password, tampering and junk files refused', async (b) => {
    const p = await L.setup(b); await L.inject(p, { bills: [{ id: 'b7', name: MARK, amount: 123, category: 'Other', dueDate: '2030-01-01', recurrence: 'none', status: 'unpaid', history: [] }] });
    const q = await b.newPage(); await q.setContent('<h1>Doc in backup</h1>'); const pdf = await q.pdf(); await q.close();
    await p.evaluate(() => (location.hash = 'docs')); await p.click('[data-a="addDoc"]'); await p.fill('#f_name', 'InBackup'); await p.setInputFiles('#f_file', tmp('bk.pdf', pdf)); await p.click('#mform button[type=submit]'); await p.waitForTimeout(800);
    await p.evaluate(() => (location.hash = 'prefs')); await p.click('[data-a="export"]'); await p.waitForSelector('.pad'); await L.tap(p, '4827');
    await p.waitForSelector('#bkPw'); await p.fill('#bkPw', 'short'); await p.fill('#bkPw2', 'short'); await p.click('[data-a="doExport"]'); ok((await p.textContent('#bkErr')).length > 0, 'short password accepted');
    await p.fill('#bkPw', 'correct horse battery'); await p.fill('#bkPw2', 'correct horse battery');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 60000 }), p.click('[data-a="doExport"]')]); const file = tmp('backup.mlmbackup', fs.readFileSync(await dl.path()));
    const raw = fs.readFileSync(file); ok(!raw.includes(Buffer.from(MARK)) && !raw.includes(Buffer.from('%PDF')) && !raw.includes(Buffer.from('InBackup')), 'backup is not encrypted');
    // wipe everything, then restore
    await p.evaluate(() => (location.hash = 'prefs')); await p.click('[data-a="wipe"]'); await p.waitForSelector('.pad'); await L.tap(p, '4827'); await p.fill('#ctyped', 'DELETE'); await p.click('#cyes');
    await p.waitForSelector('#obName'); const idb = await L.dumpIDB(p); eq(Object.keys(idb.files).length + Object.keys(idb.vault).length + Object.keys(idb.meta).length, 0, 'wipe left data behind'); eq(Object.keys(idb.secure).length, 0, 'wipe left secrets behind');
    await L.onboard(p, 'Newname', '2846'); await L.toHome(p); await p.evaluate(() => (location.hash = 'prefs'));
    const attempt = async (f, pw) => { await p.click('[data-a="restore"]'); await p.waitForSelector('.pad'); await L.tap(p, '2846'); await p.waitForSelector('#rsFile'); await p.setInputFiles('#rsFile', f); await p.fill('#rsPw', pw); await p.click('[data-a="doRestore"]'); await p.waitForTimeout(2500); };
    await attempt(file, 'wrong password!!'); ok((await p.textContent('#resErr')).length > 0, 'wrong password accepted'); await p.click('[data-a="close"]');
    const bad = Buffer.from(raw); bad[bad.length - 5] ^= 0xff; await attempt(tmp('tampered.mlmbackup', bad), 'correct horse battery'); ok((await p.textContent('#resErr')).length > 0, 'tampered backup accepted'); await p.click('[data-a="close"]');
    await attempt(tmp('junk.mlmbackup', Buffer.from('{"bills":[]}')), 'correct horse battery'); ok((await p.textContent('#resErr')).length > 0, 'junk accepted'); await p.click('[data-a="close"]');
    await attempt(tmp('trunc.mlmbackup', raw.subarray(0, raw.length - 40)), 'correct horse battery'); ok((await p.textContent('#resErr')).length > 0, 'truncated accepted'); await p.click('[data-a="close"]');
    await attempt(file, 'correct horse battery'); await p.click('#cyes'); await p.waitForTimeout(2500);
    await p.evaluate(() => (location.hash = 'bills')); ok((await p.innerText('#view')).includes(MARK), 'restored data missing');
    await p.evaluate(() => (location.hash = 'docs')); await p.locator('[data-a="doc"]', { hasText: 'InBackup' }).click(); await p.click('[data-a="openDoc"]'); await p.waitForSelector('#vbody canvas', { timeout: 15000 }).catch(async (e) => { throw new Error('viewer: modal=' + (await p.innerText('#modalRoot')).slice(0,200) + ' modal2=' + (await p.innerText('#modal2')).slice(0,200) + ' | files=' + JSON.stringify(Object.keys((await L.dumpIDB(p)).files)) + ' | rec=' + JSON.stringify((await p.evaluate(() => window.__mlm.state().docs)))); });
  });

  await t('calculations: totals shown match the figures entered', async (b) => {
    const p = await L.setup(b); await L.inject(p); const txt = async (h) => { await p.evaluate((h) => (location.hash = h), h); await p.waitForTimeout(200); return p.innerText('#view'); };
    let s = await txt('home'); for (const x of ['₹16,000', '₹2,00,000', '25.5 g', '₹1,50,000 paid', '₹80,000 paid']) ok(s.includes(x), 'home: ' + x);
    s = await txt('invest'); ok(s.includes('₹2,00,000') && s.includes('₹60,000') && !/gain|loss|current value/i.test(s.replace('gains or losses', '')), 'invest');
    s = await txt('metals'); ok(s.includes('₹2,30,000') && s.includes('65%') && s.includes('35%'), 'metals');
    s = await txt('loans'); ok(s.includes('₹25,00,000') && s.includes('₹30,000'), 'loans');
    s = await txt('yearplan'); ok(s.includes('₹1,92,000') && s.includes('₹16,000') && s.includes('₹27,000'), 'yearplan');
    s = await txt('bills'); ok(s.includes('₹10,000'), 'bills');
    await p.click('[data-a="bill"]').catch(() => {}); eq(p.errs.length, 0);
  });

  await t('notifications (stubbed OS): scheduled only when allowed; generic text by default; detailed when chosen; capped; no past dates', async (b) => {
    const stubs = { notifications: { permission: 'granted', scheduled: [] } };
    const p = await L.newPage(b, { stubs }); await L.onboard(p); await L.toHome(p); await L.inject(p);
    eq(await p.evaluate(() => window.__mlmStubs.notifications.scheduled.length), 0, 'nothing scheduled before opt-in');
    await p.evaluate(() => (location.hash = 'prefs')); await p.click('[data-a="toggleNotif"]'); await p.waitForTimeout(1600);
    let sc = await p.evaluate(() => window.__mlmStubs.notifications.scheduled); ok(sc.length >= 4, 'scheduled ' + sc.length);
    ok(sc.every((n) => !/Rent|Passport|Family|Index|plumber/.test(n.title + n.body)), 'names leaked in generic mode');
    ok(sc.every((n) => n.at > Date.now()), 'past notification'); eq(new Set(sc.map((n) => n.id)).size, sc.length, 'duplicate ids');
    await p.click('[data-k="hideNotif"]'); await p.waitForTimeout(1600); sc = await p.evaluate(() => window.__mlmStubs.notifications.scheduled);
    ok(sc.some((n) => n.body.includes('Rent')), 'details missing when hide is off');
    const many = Array.from({ length: 90 }, (_, i) => ({ id: 'm' + i, title: 'R' + i, date: L.addDays('2026-11-02', 5 + i), time: '09:00', recurrence: 'none', advance: 0, done: false }));
    await p.evaluate((m) => { const s = window.__mlm.state(); s.rem = m; window.__mlm.inject(s); }, many); await p.waitForTimeout(1600);
    ok((await p.evaluate(() => window.__mlmStubs.notifications.scheduled.length)) <= 60, 'cap exceeded');
    await p.click('[data-a="toggleNotif"]').catch(() => {}); 
  });
  await t('notifications: denied permission schedules nothing', async (b) => {
    const p = await L.newPage(b, { stubs: { notifications: { permission: 'denied', scheduled: [] } } }); await L.onboard(p); await L.toHome(p); await L.inject(p);
    await p.evaluate(() => (location.hash = 'prefs')); await p.click('[data-a="toggleNotif"]'); await p.waitForTimeout(1200);
    eq(await p.evaluate(() => window.__mlmStubs.notifications.scheduled.length), 0); eq(await p.evaluate(() => window.__mlm.state().settings.notif), false);
  });

  await t('fingerprint (stubbed OS prompt): unlocks only when the prompt succeeds', async (b) => {
    const stubs = { bio: { available: true, result: true } }; const p = await L.newPage(b, { stubs });
    await p.fill('#obName', 'A'); await p.click('#obGo'); await L.tap(p, '4827'); await p.waitForSelector('#ptitle:has-text("Confirm")'); await L.tap(p, '4827');
    await p.waitForSelector('#at:has-text("fingerprint")'); await p.click('#ay'); await L.toHome(p);
    await p.reload(); await p.waitForSelector('#view h1', { timeout: 10000 }); // unlocked by the (stubbed) OS prompt alone, no PIN typed
  });
  await t('fingerprint: refused prompt keeps the app locked', async (b) => {
    const ctx = await b.newContext(); const p = await ctx.newPage(); await p.addInitScript(() => { if (!sessionStorage.getItem('r')) window.__mlmStubs = { bio: { available: true, result: true } }; else window.__mlmStubs = { bio: { available: true, result: false } }; });
    await p.goto(L.URL); await p.fill('#obName', 'A'); await p.click('#obGo'); await L.tap(p, '4827'); await p.waitForSelector('#ptitle:has-text("Confirm")'); await L.tap(p, '4827'); await p.waitForSelector('#at:has-text("fingerprint")'); await p.click('#ay'); await L.toHome(p);
    ok(await p.evaluate(() => window.__mlm.state().settings.bio), 'bio not enabled');
    await p.evaluate(() => sessionStorage.setItem('r', '1')); await p.reload(); await p.waitForSelector('.pad'); await p.waitForTimeout(1500);
    eq(await p.locator('#view h1').count(), 0, 'opened despite refused fingerprint'); await L.tap(p, '4827'); await p.waitForSelector('#view h1');
  });

  await t('forgot PIN: erasing needs typed confirmation and removes everything', async (b) => {
    const p = await L.setup(b); await L.inject(p); await p.reload(); await p.waitForSelector('.pad'); await p.click('[data-p="extra"]'); await p.waitForSelector('#etype');
    ok(await p.isDisabled('#eyes')); await p.fill('#etype', 'erase'); ok(await p.isDisabled('#eyes')); await p.fill('#etype', 'ERASE'); await p.click('#eyes'); await p.waitForSelector('#obName');
    const d = await L.dumpIDB(p); eq(Object.keys(d.vault).length + Object.keys(d.meta).length + Object.keys(d.files).length + Object.keys(d.secure).length, 0);
  });

  await t('forms: validation errors, saving, editing and deleting a record', async (b) => {
    const p = await L.setup(b); await p.evaluate(() => (location.hash = 'bills')); await p.click('[data-a="addBill"]'); await p.click('#mform button[type=submit]');
    ok((await p.textContent('.fld[data-k="name"] .err')).length > 0); await p.fill('#f_name', 'Water'); await p.fill('#f_amount', '-5'); await p.fill('#f_dueDate', '2026-12-01'); await p.click('#mform button[type=submit]'); ok((await p.textContent('.fld[data-k="amount"] .err')).length > 0);
    await p.fill('#f_amount', '450'); await p.click('#mform button[type=submit]'); await p.waitForTimeout(400); ok((await p.innerText('#view')).includes('Water'));
    await p.reload(); await L.unlock(p); await p.evaluate(() => (location.hash = 'bills')); ok((await p.innerText('#view')).includes('Water'), 'not persisted');
    await p.locator('[data-a="bill"]').first().click(); await p.click('[data-a="del"]'); await p.click('#cyes'); await p.waitForTimeout(400); ok(!(await p.innerText('#view')).includes('Water'));
  });

  const pass = results.filter((r) => r.ok).length;
  fs.writeFileSync(path.join(__dirname, 'results.json'), JSON.stringify({ ranAt: new Date().toISOString(), pass, fail: results.length - pass, results }, null, 2));
  console.log(`\n${pass} passed, ${results.length - pass} failed`); process.exit(results.length - pass ? 1 : 0);
})();
