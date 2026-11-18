// Release gate: open the GitHub Pages site (docs/*.html) in a headless browser, offline, in every language: no script
// error, every hero button has its text, ?lang= takes effect and the language menu switches. (0.4.90-0.4.92 shipped a
// page whose script did not even parse: an apostrophe in a single-quoted string.)
// Usage: node tools/check_pages.cjs [docs dir]
const fs = require('fs');
const path = require('path');
const NM = process.env.JTWAF_NODE_MODULES || '/opt/jt-ipam/frontend/node_modules';
const { chromium } = require(path.join(NM, '@playwright/test'));
(async () => {
  const dir = path.resolve(process.argv[2] || path.join(__dirname, '..', 'docs'));
  const pages = fs.readdirSync(dir).filter((f) => f.endsWith('.html')).map((f) => path.join(dir, f));
  const browser = await chromium.launch();
  const problems = [];
  for (const file of pages) {
    for (const lang of ['en', 'zh-TW', 'ja']) {
      const page = await browser.newPage();
      const errors = [];
      page.on('pageerror', (e) => errors.push(String(e)));
      await page.route(/^https?:/, (r) => r.abort());
      await page.goto('file://' + file + '?lang=' + lang);
      await page.waitForTimeout(300);
      const r = await page.evaluate(() => ({
        lang: document.documentElement.lang,
        empty: [...document.querySelectorAll('a.btn, button.btn')].filter((b) => b.offsetParent && !b.textContent.trim()
          && !b.querySelector('svg, img') && !b.getAttribute('aria-label')).length,
      }));
      const name = path.basename(file) + ' ?lang=' + lang;
      for (const e of errors) problems.push(name + ': script error: ' + e);
      if (r.lang !== lang) problems.push(name + ': page language is ' + r.lang);
      if (r.empty) problems.push(name + ': ' + r.empty + ' buttons without text');
      await page.close();
    }
  }
  await browser.close();
  if (problems.length) { console.log(problems.join('\n')); console.log('pages check: FAILED'); process.exit(1) }
  console.log('pages check: OK (' + pages.length + ' pages x 3 languages)');
})().catch((e) => { console.log('pages check: FAILED ' + e); process.exit(1) });
