const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch(); const p = await b.newPage({ viewport: { width: 390, height: 800 } });
  const errs = []; p.on('pageerror', e => errs.push('PAGEERR ' + e.message)); p.on('console', m => { if (m.type() === 'error') errs.push('CONSOLE ' + m.text()) });
  await p.goto('http://localhost:4173/');
  await p.fill('#obName', 'Aditya'); await p.click('#obGo');
  const tap = async (s) => { for (const c of s) { await p.click(`.pad button[data-p="${c}"]`) } await p.waitForTimeout(400) };
  await tap('4827'); await p.waitForTimeout(300); await tap('4827');
  await p.waitForSelector('#view h1', { timeout: 15000 });
  console.log('home:', (await p.textContent('#view h1')).slice(0, 60));
  console.log('errors', errs);
  await b.close();
})();
