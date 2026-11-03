const L=require('./lib.cjs');const fs=require('fs');
(async()=>{const b=await L.launch();const p=await L.setup(b);await L.inject(p);
await p.evaluate(()=>location.hash='prefs');await p.click('[data-a="export"]');await p.waitForSelector('.pad');await L.tap(p,'4827');
await p.waitForSelector('#bkPw');await p.fill('#bkPw','correct horse battery');await p.fill('#bkPw2','correct horse battery');
const [dl]=await Promise.all([p.waitForEvent('download',{timeout:60000}),p.click('[data-a="doExport"]')]);console.log('downloaded',dl.suggestedFilename());
await p.click('[data-a="wipe"]').catch(e=>console.log('wipe click',e.message.slice(0,80)));
await p.waitForTimeout(500);console.log(await p.evaluate(()=>document.body.innerText.slice(0,300)));
await b.close()})();
