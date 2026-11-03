const L = require('./lib.cjs');
(async () => { const b = await L.launch(); const p = await L.setup(b); await L.inject(p);
  for (const h of ['home','bills','invest','metals','loans','yearplan','docs','reminders']) { await p.evaluate((h)=>{location.hash=h},h); await p.waitForTimeout(250); console.log('=== '+h+'\n'+(await p.innerText('#view')).replace(/\n+/g,' | ').slice(0,700)); }
  console.log(p.errs); await b.close(); })();
