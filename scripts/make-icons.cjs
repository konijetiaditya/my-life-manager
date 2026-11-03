// Renders the logo to the legacy launcher PNGs (Android 7.x). Newer phones use the vector icon.
const { chromium } = require('playwright'); const fs = require('fs');
const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 34 34"><circle cx="17" cy="17" r="17" fill="#174B35"/><circle cx="17" cy="17" r="9" fill="none" stroke="#CBAA62" stroke-width="2.6" stroke-linecap="round" stroke-dasharray="42 14.6" transform="rotate(-90 17 17)"/><circle cx="8" cy="17" r="2.4" fill="#16A765"/><circle cx="17" cy="17" r="2.6" fill="#F5F3EC"/></svg>`;
(async () => {
  const b = await chromium.launch(); const p = await b.newPage();
  for (const [d, px] of [['mdpi', 48], ['hdpi', 72], ['xhdpi', 96], ['xxhdpi', 144], ['xxxhdpi', 192]]) {
    await p.setViewportSize({ width: px, height: px });
    await p.setContent(`<body style="margin:0;background:transparent">${svg.replace('<svg ', `<svg width="${px}" height="${px}" `)}</body>`);
    const buf = await p.screenshot({ omitBackground: true });
    for (const n of ['ic_launcher.png', 'ic_launcher_round.png']) fs.writeFileSync(`android/app/src/main/res/mipmap-${d}/${n}`, buf);
    fs.rmSync(`android/app/src/main/res/mipmap-${d}/ic_launcher_foreground.png`, { force: true });
  }
  await b.close();
})();
