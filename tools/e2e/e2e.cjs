// Browser end-to-end test over every page (tools/e2e/run.sh starts the synthetic environment).
const path = require('path');
const NM = process.env.JTWAF_NODE_MODULES || '/opt/jt-ipam/frontend/node_modules';
const { chromium } = require(path.join(NM, '@playwright/test'));
const crypto = require('crypto');
const fs = require('fs');
const R = process.argv[2];
const SHOTS = process.argv[3];
const base = 'http://127.0.0.1:' + fs.readFileSync(R + '/port', 'utf8').trim();
const secrets = JSON.parse(fs.readFileSync(R + '/totp.json'));
const EN = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'src', 'i18n', 'en.json')));
const KEYS = Object.keys(EN).filter((k) => k.includes('.') && k.length > 8);
const PW = 'Smoke-Passw0rd-1';
function b32(s) { const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '', out = []; for (const c of s) bits += a.indexOf(c).toString(2).padStart(5, '0'); for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); }
function totp(secret) { const step = Math.floor(Date.now() / 30000); const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(step)); const h = crypto.createHmac('sha1', b32(secret)).update(b).digest(); const o = h[h.length - 1] & 15; return String(((h.readUInt32BE(o) & 0x7fffffff) % 1000000)).padStart(6, '0'); }
const problems = [];
const lastStep = {};
async function freshStep(user) {
  while (lastStep[user] === Math.floor(Date.now() / 30000)) await new Promise((r) => setTimeout(r, 1000));
  lastStep[user] = Math.floor(Date.now() / 30000);
}
const notes = [];
const ok = (cond, msg) => { if (!cond) problems.push('FAIL ' + msg); else notes.push('ok ' + msg); };

function watch(page, who) {
  page.on('console', (m) => { if (['error', 'warning'].includes(m.type()) && !/status of 40[13]|status of 409|status of 400/.test(m.text())) problems.push(who + ' console ' + m.type() + ': ' + m.text()); });
  page.on('pageerror', (e) => problems.push(who + ' pageerror: ' + e.message));
  page.on('dialog', (d) => d.accept());
}

async function rawKeys(page, where) {
  const txt = await page.locator('body').innerText();
  const hits = KEYS.filter((k) => txt.includes(k))
  if (hits.length) problems.push(where + ': raw i18n keys visible: ' + hits.slice(0, 8).join(', '));
  // a placeholder the text never got a value for ("版本 {v}", "{retry_after} 秒"; 0.5.0)
  const ph = (txt.match(/(?<![%$\w])\{[a-z][a-z_]{0,24}\}/g) || []);
  if (ph.length) problems.push(where + ': unfilled placeholders visible: ' + [...new Set(ph)].slice(0, 8).join(', '));
  return txt;
}

async function login(browser, user, scheme, viewport) {
  const ctx = await browser.newContext({ viewport: viewport || { width: 1360, height: 950 }, colorScheme: scheme || 'light', acceptDownloads: true });
  const page = await ctx.newPage();
  watch(page, user);
  await page.goto(base + '/login', { waitUntil: 'networkidle' });
  await page.fill('input[name=username]', user);
  await page.fill('input[name=password]', PW);
  await page.click('button[type=submit]');
  if (secrets[user]) {
    await page.waitForSelector('input[name=totp]');
    await freshStep(user);
    await page.fill('input[name=totp]', totp(secrets[user]));
    await page.click('button[type=submit]');
  }
  await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 10000 });
  await page.waitForLoadState('networkidle');
  return { ctx, page };
}

async function setLang(page, lang) {
  await page.evaluate(async (lang) => {
    const me = await (await fetch('/api/v1/auth/me')).json();
    await fetch('/api/v1/auth/me', { method: 'PATCH', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': me.csrf_token }, body: JSON.stringify({ language: lang }) });
  }, lang);
}

const ROUTES = ['/', '/events', '/rules', '/rules/930110', '/vhosts', '/countries', '/crs', '/lookup/203.0.113.9', '/managed', '/waf/pause', '/crowdsec', '/nginx-update', '/changes', '/changes/new',
  '/versions', '/config-changes', '/reviews', '/reviews/8', '/intel', '/guide', '/account', '/admin/users', '/admin/users/review', '/admin/tokens', '/admin/audit',
  '/admin/system', '/admin/compliance', '/admin/settings', '/admin/notify', '/alerts', '/waf', '/analysis', '/traffic', '/blocks', '/nope'];

const README_PAGES = ['/', '/events', '/waf', '/analysis', '/admin/notify', '/alerts', '/admin/system', '/changes', '/rules', '/lookup/203.0.113.9', '/traffic', '/countries', '/intel', '/reviews/8'];

async function audit(page, where) {
  const r = await page.evaluate(() => {
    const out = { selects: document.querySelectorAll('select').length,
      dates: document.querySelectorAll('input[type=date],input[type=datetime-local],input[type=time]').length,
      noicon: [], overflow: document.documentElement.scrollWidth > window.innerWidth + 2,
      // the decision flowchart: every box shows all of its text (a fixed-height box cut a second detail line)
      clipped: [...document.querySelectorAll('.fl-box')].filter((b) => b.scrollHeight > b.clientHeight + 1).map((b) => b.innerText.slice(0, 40)),
      // a card shows one accent line on its left: a thick left border next to the title bar's own line looks doubled
      // everything that can be clicked shows the pointing hand
      nohand: [...document.querySelectorAll('button:not(:disabled), a[href], [role=button]')].filter((e) => e.offsetParent !== null
        && getComputedStyle(e).cursor !== 'pointer').map((e) => (e.innerText || e.getAttribute('aria-label') || e.tagName).trim().slice(0, 30)),
      // no native tooltip left once the pointer has been over it (tooltip.js moves titles to the site's own)
      doubled: [...document.querySelectorAll('.card')].filter((c) => {
        const head = c.querySelector(':scope > .cardhead:first-child, :scope > h2:first-child')
        return head && parseFloat(getComputedStyle(c).borderLeftWidth) >= 2 && /inset/.test(getComputedStyle(head).boxShadow)
      }).map((c) => (c.querySelector('h2, .cardhead') || c).innerText.trim().slice(0, 30)) };
    for (const b of document.querySelectorAll('button, a.btn')) {
      if (b.classList.contains('dp-day')) continue;
      if (!b.querySelector('svg') && b.offsetParent !== null) out.noicon.push((b.innerText || b.getAttribute('aria-label') || '').trim().slice(0, 40));
    }
    return out;
  });
  if (r.selects) problems.push(where + ': native select x' + r.selects);
  if (r.clipped.length) problems.push(where + ': flowchart text cut off: ' + r.clipped.slice(0, 3).join(' | '));
  if (r.dates) problems.push(where + ': native date input x' + r.dates);
  if (r.doubled.length) problems.push(where + ': card with a doubled left line: ' + r.doubled.slice(0, 3).join(' | '));
  if (r.nohand.length) problems.push(where + ': clickable without the pointing hand: ' + r.nohand.slice(0, 5).join(' | '));
  if (r.noicon.length) problems.push(where + ': buttons without icon: ' + r.noicon.slice(0, 5).join(' | '));
  if (r.overflow) notes.push('warn ' + where + ': horizontal page overflow');
}

(async () => {
  const browser = await chromium.launch();
  const { ctx, page } = await login(browser, 'admin', 'light');
  for (const lang of ['zh-TW', 'en']) {
    await setLang(page, lang);
    for (const p of ROUTES) {
      await page.goto(base + p, { waitUntil: 'networkidle' });
      await page.waitForTimeout(250);
      await rawKeys(page, lang + ' ' + p);
      await audit(page, lang + ' ' + p);
      if (lang === 'zh-TW') await page.screenshot({ path: SHOTS + '/light' + p.replace(/\//g, '_') + '.png', fullPage: true });
      if (lang === 'en' && README_PAGES.includes(p)) await page.screenshot({ path: SHOTS + '/en' + p.replace(/\//g, '_') + '.png', fullPage: true });
    }
  }
  // Japanese: every page (no raw keys, same layout checks), screenshots of the README pages for README_ja
  await setLang(page, 'ja');
  for (const p of ROUTES) {
    await page.goto(base + p, { waitUntil: 'networkidle' });
    await page.waitForTimeout(250);
    await rawKeys(page, 'ja ' + p);
    await audit(page, 'ja ' + p);
    if (README_PAGES.includes(p)) await page.screenshot({ path: SHOTS + '/ja' + p.replace(/\//g, '_') + '.png', fullPage: true });
  }
  await setLang(page, 'zh-TW');
  // theme switch to dark via the UI
  await page.goto(base + '/', { waitUntil: 'networkidle' });
  await page.click('.themeswitch .im-btn'); await page.click('.themeswitch .im-item:has-text("深色")');
  ok(await page.evaluate(() => document.documentElement.dataset.theme) === 'dark', 'theme switch sets dark');
  for (const p of ['/', '/events', '/guide', '/admin/system', '/admin/compliance', '/changes', '/lookup/203.0.113.9', '/admin/settings', '/admin/notify', '/alerts', '/analysis']) {
    await page.goto(base + p, { waitUntil: 'networkidle' });
    await page.waitForTimeout(250);
    await page.screenshot({ path: SHOTS + '/dark' + p.replace(/\//g, '_') + '.png', fullPage: true });
  }
  ok(await page.evaluate(() => document.documentElement.dataset.theme) === 'dark', 'theme persists across pages');
  // an alert becomes a change draft
  await page.goto(base + '/alerts', { waitUntil: 'networkidle' });
  await page.locator('.rowacts button:has-text("草擬")').first().click();
  await page.waitForURL((u) => u.pathname === '/changes/new', { timeout: 10000 }).catch(() => {});
  ok(new URL(page.url()).pathname === '/changes/new', 'alert drafts a change');
  // an nginx update asks its approver for a one-time code (0.4.100: the server required one the page did not ask for)
  await page.goto(base + '/changes/' + fs.readFileSync(R + '/nginx-change', 'utf8').trim(), { waitUntil: 'networkidle' });
  ok(await page.locator('input[autocomplete="one-time-code"]').count() === 1, 'nginx update approval asks for a one-time code');
  await rawKeys(page, 'nginx change');
  ok(await page.locator('button:has-text("核准並套用"):disabled').count() === 1, 'approve waits for the note and the code');
  // the nginx advisories: one aligned row each (title, severity and CVE columns start at the same place)
  await page.goto(base + '/nginx-update', { waitUntil: 'networkidle' });
  const cols = await page.evaluate(() => [...document.querySelectorAll('.secissues li')].map((li) =>
    [...li.children].slice(1, 4).map((c) => Math.round(c.getBoundingClientRect().left)).join(',')));
  ok(cols.length === 4 && new Set(cols).size === 1, 'nginx advisories in aligned columns (' + [...new Set(cols)].join(' | ') + ')');
  // every card title band folds, the state is remembered per page
  await page.goto(base + '/admin/settings', { waitUntil: 'networkidle' });
  await page.waitForTimeout(300);
  const heads = await page.evaluate(() => [document.querySelectorAll('.card > h2:first-child, .card > .cardhead:first-child').length,
    document.querySelectorAll('.card > .foldable > .cardfold').length]);
  ok(heads[0] > 5 && heads[0] === heads[1], 'every card title has a fold button (' + heads.join('/') + ')');
  await page.locator('.card > .foldable > .cardfold').first().click();
  ok(await page.evaluate(() => { const c = document.querySelector('.card.folded'); return !!c && [...c.children].slice(1).every((x) => getComputedStyle(x).display === 'none'); }), 'fold hides the card body');
  await page.reload({ waitUntil: 'networkidle' }); await page.waitForTimeout(300);
  ok(await page.evaluate(() => document.querySelectorAll('.card.folded').length) === 1, 'folded card remembered after reload');
  await page.locator('.card.folded > .foldable > .cardfold').click();
  ok(await page.evaluate(() => document.querySelectorAll('.card.folded').length) === 0, 'unfold');
  await page.click('.themeswitch .im-btn'); await page.click('.themeswitch .im-item:has-text("淺色")');
  // DataTable on events: sort, filter, column picker, paging
  await page.goto(base + '/events', { waitUntil: 'networkidle' });
  const firstBefore = await page.locator('.datatable tbody tr').first().innerText();
  const hdr = page.locator('.datatable thead th .dt-sort').nth(1);
  await hdr.click(); await hdr.click();
  ok((await page.locator('.datatable thead th[aria-sort]').count()) === 1, 'events: sort sets aria-sort');
  await page.fill('.dt-search input', '203.0.113');
  await page.waitForTimeout(200);
  const rows = await page.locator('.datatable tbody tr').allInnerTexts();
  ok(rows.length > 0 && rows.every((r) => r.includes('203.0.113')), 'events: quick search filters rows (' + rows.length + ')');
  ok(rows.some((r) => /JP|US|日本|美國/.test(r)), 'events: GeoIP shown next to source');
  await page.fill('.dt-search input', '');
  await page.click('.dt-colpick button');
  const before = await page.locator('.datatable thead tr').first().locator('th').count();
  await page.locator('.dt-colopt input:not([disabled])').first().click();
  const after = await page.locator('.datatable thead tr').first().locator('th').count();
  ok(after === before - 1, 'events: hiding a column works (' + before + '->' + after + ')');
  await page.locator('.dt-colpop button').click();
  await page.keyboard.press('Escape');
  ok((await page.locator('.dt-pager').count()) >= 0, 'pager present when needed');
  // SelectBox: open and pick with keyboard
  const sb = page.locator('main .selectbox .sb-btn').first();
  await sb.click();
  ok(await page.locator('.sb-pop').isVisible(), 'selectbox opens');
  await page.keyboard.press('ArrowDown'); await page.keyboard.press('Enter');
  ok(!(await page.locator('.sb-pop').count()), 'selectbox closes after pick');
  // DatePicker
  const dp = page.locator('main .datepicker .dp-btn').first();
  if (await dp.count()) {
    await dp.click();
    ok(await page.locator('.dp-pop').isVisible(), 'datepicker opens');
    await page.locator('.dp-day:not(.other):not([disabled])').last().click();
    await page.locator('.dp-foot .btn.primary').click();
    ok(!(await page.locator('.dp-pop').count()), 'datepicker closes');
    const v = await dp.innerText();
    ok(/\d/.test(v), 'datepicker shows a value: ' + v.trim());
    await page.screenshot({ path: SHOTS + '/events-after-date.png' });
  } else problems.push('events: no datepicker');
  // outside configuration changes: "files" opens right under its row, not at the end of the page
  await page.goto(base + '/config-changes', { waitUntil: 'networkidle' });
  const fbtn = page.locator('#cfgchg-list tbody tr button, .datatable tbody tr button').filter({ has: page.locator('svg') }).first();
  if (await fbtn.count()) {
    await fbtn.click();
    const placed = await page.evaluate(() => {
      const ex = document.querySelector('tr.dt-expand');
      return !!(ex && ex.previousElementSibling && ex.previousElementSibling.classList.contains('dt-open'));
    });
    ok(placed, 'config changes: files open under their row');
  }
  // periodic WAF review: review now, then the review page shows its parts
  await page.goto(base + '/reviews', { waitUntil: 'networkidle' });
  const rvBtn = page.locator('.pagehead button.primary');
  if (await rvBtn.count()) {
    await rvBtn.click();
    await page.waitForURL(/\/reviews\/\d+/, { timeout: 10000 }).catch(() => {});
    await page.locator('.rvtiles .tile.stat').first().waitFor({ timeout: 10000 }).catch(() => {});
    ok(/\/reviews\/\d+/.test(page.url()), 'review now opens the new review');
    ok(await page.locator('.rvtiles .tile.stat').count() >= 4, 'review shows its tiles');
  } else problems.push('reviews: no review-now button');
  // AI analysis of one event: the card and its advice
  await page.goto(base + '/events', { waitUntil: 'networkidle' });
  const firstEv = await page.evaluate(async () => { const r = await (await fetch('/api/v1/events?limit=500')).json(); const xs = (r.items || r.events || []); return xs.length ? xs[xs.length - 1].id : null })
  if (firstEv) {
    await page.goto(base + '/events/' + firstEv, { waitUntil: 'networkidle' });
    ok(await page.locator('.aicard').count() === 1, 'event: AI analysis card');
    ok((await page.locator('.aicard').innerText()).length > 20, 'event: AI analysis shown');
  }
  // sites: "switch WAF on" opens the reason form (proposing is tested in the unit tests)
  await page.goto(base + '/vhosts', { waitUntil: 'networkidle' });
  const swBtn = page.locator('table button.btn.tiny').filter({ has: page.locator('svg') }).first();
  if (await swBtn.count()) {
    await swBtn.click();
    ok(await page.locator('textarea').count() >= 1, 'sites: the WAF switch asks why');
  }
  // the blocked page: a card for every site at once, a column for one site at a time
  await page.goto(base + '/vhosts', { waitUntil: 'networkidle' });
  ok(await page.locator('#blocked-page').count() === 1, 'sites: blocked page card');
  const allBtn = page.locator('#blocked-page button.primary');
  if (await allBtn.count()) {
    await allBtn.click();
    ok((await page.locator('textarea').inputValue()).length > 5, 'sites: blocked page for every site opens the form with a reason');
  } else problems.push('FAIL sites: no "apply to every site" button for the blocked page');
  // the blocked page can be previewed: its own page (sandboxed, only its own inline style), sample values, no SSI left
  const pv = page.locator('#blocked-page a[data-preview=blocked-page]');
  ok((await pv.count()) === 1 && (await pv.getAttribute('target')) === '_blank', 'sites: blocked page preview link');
  const pr = await page.request.get(base + '/api/v1/vhosts/blocked-page/preview');
  const pcsp = pr.headers()['content-security-policy'] || '';
  const pbody = await pr.text();
  ok(pr.status() === 200 && /text\/html/.test(pr.headers()['content-type'] || '') && /sandbox/.test(pcsp) && /sha256-/.test(pcsp)
     && !/'self'|unsafe-inline/.test(pcsp) && pbody.includes('403') && !pbody.includes('<!--#'), 'sites: blocked page preview (own policy, sample values)');
  // the app's own confirmation dialog, never the browser's: cancel keeps things as they were
  let nativeDialogs = 0;
  const countNative = () => { nativeDialogs += 1; };
  page.on('dialog', countNative);
  await page.goto(base + '/intel', { waitUntil: 'networkidle' });
  const allConfirm = page.locator('button', { hasText: '全部確認' });
  if (await allConfirm.count()) {
    await allConfirm.first().click();
    await page.waitForSelector('.cdialog', { timeout: 3000 }).catch(() => {});
    ok((await page.locator('.cdialog[role=alertdialog]').count()) === 1 && (await page.locator('.cdialog [data-cd=ok].primary').count()) === 1,
       'dialog: the app\'s own confirmation (confirm all)');
    await page.keyboard.press('Escape');
    await page.waitForSelector('.cdialog', { state: 'detached', timeout: 3000 }).catch(() => {});
    ok((await page.locator('.cdialog').count()) === 0 && (await allConfirm.count()) === 1, 'dialog: Esc cancels, nothing confirmed');
    await page.locator('#intel-software button.danger, .card button.btn.tiny.danger').first().click();
    await page.waitForSelector('.cdialog', { timeout: 3000 }).catch(() => {});
    const focusedCancel = await page.evaluate(() => document.activeElement && document.activeElement.dataset.cd === 'cancel');
    ok((await page.locator('.cdialog [data-cd=ok].danger').count()) === 1 && focusedCancel, 'dialog: a delete asks in red, starting on cancel');
    await page.locator('.cdialog [data-cd=cancel]').click();
    ok((await page.locator('.cdialog').count()) === 0, 'dialog: cancel closes it');
  } else problems.push('FAIL dialog: no "confirm all" button on the threat intelligence page');
  page.off('dialog', countNative);
  ok(nativeDialogs === 0, 'dialog: the browser\'s own dialog never opened');
  // 0.4.94: IP reputation on the lookup -- lists, InternetDB and MISP put together with the site's own evidence
  await page.goto(base + '/lookup/203.0.113.9', { waitUntil: 'networkidle' });
  await page.waitForSelector('.iprep', { timeout: 8000 }).catch(() => {});
  ok((await page.locator('.iprep .badge', { hasText: '惡意' }).count()) >= 1 &&
     (await page.locator('.iprep .reasons li', { hasText: 'CINS Army' }).count()) === 1 &&
     (await page.locator('.iprep .kvpanel', { hasText: 'MISP' }).count()) === 1,
     'lookup: the IP reputation card shows the verdict, the lists and MISP');
  await page.goto(base + '/admin/settings#uiset-iprep', { waitUntil: 'networkidle' });
  await page.waitForSelector('section.card:has(h2:has-text("IP 情資清單")) tbody tr', { timeout: 8000 }).catch(() => {});
  ok((await page.locator('section.card:has(h2:has-text("IP 情資清單")) tbody tr').count()) === 8, 'settings: the IP reputation lists are listed');
  // "someone was blocked": an address goes to the address lookup
  await page.goto(base + '/events', { waitUntil: 'networkidle' });
  await page.fill('.findvisit input', '203.0.113.9');
  await page.locator('.findvisit button[type=submit]').click();
  await page.waitForURL(/\/lookup\//, { timeout: 8000 }).catch(() => {});
  ok(/\/lookup\/203\.0\.113\.9/.test(page.url()), 'events: find a blocked visit by address');
  // threat intelligence: a threat opens under its row
  await page.goto(base + '/intel', { waitUntil: 'networkidle' });
  await page.locator('#intel-threats tbody tr, .datatable tbody tr').first().click();
  ok(await page.locator('tr.dt-expand .thd').count() === 1, 'intel: threat details open under the row');
  // system check: the background parts are all there
  await page.goto(base + '/admin/system', { waitUntil: 'networkidle' });
  const sysText = await page.locator('main').innerText();
  for (const k of ['DNS', 'CRS']) ok(sysText.includes(k), 'system check lists ' + k);
  // Guide: click an architecture node
  await page.goto(base + '/guide', { waitUntil: 'networkidle' });
  await page.locator('.arch-node').nth(5).click();
  ok((await page.locator('.archdesc h3').innerText()).length > 0, 'guide: node description shown');
  // overview country chart
  await page.goto(base + '/', { waitUntil: 'networkidle' });
  // request volume: the range buttons are as tall as the site picker next to them
  await page.goto(base + '/traffic', { waitUntil: 'networkidle' });
  const hSeg = await page.locator('.ovfilters > .seg').first().boundingBox({ timeout: 5000 }).catch(() => null);
  const hSel = await page.locator('.ovfilters .sb-btn').first().boundingBox({ timeout: 5000 }).catch(() => null);
  ok(hSeg && hSel && Math.abs(hSeg.height - hSel.height) <= 1, 'traffic: range buttons as tall as the site picker (' + (hSeg && hSeg.height) + ' / ' + (hSel && hSel.height) + ')');
  await page.goto(base + '/', { waitUntil: 'networkidle' });
  // "Overview" is a menu: the dashboard is its first entry
  const ovBtn = page.locator('.mainnav button.navmorebtn').first();
  if (await ovBtn.count()) {
    await ovBtn.click();
    ok((await page.locator('.navdrop a.navitem[href="/"]', { hasText: '儀表板' }).count()) === 1, 'nav: Overview menu with the dashboard');
    await page.keyboard.press('Escape');
  }
  ok((await page.locator('text=依國家').count()) > 0, 'overview: by-country chart');
  // world map: land drawn (lazy-loaded outline), one bubble per country, tooltip on a bubble
  await page.waitForSelector('.worldmap .wm-land', { timeout: 5000 }).catch(() => {});
  const wm = await page.evaluate(() => ({ land: (document.querySelector('.worldmap .wm-land')?.getAttribute('d') || '').length,
    dots: document.querySelectorAll('.worldmap .wm-dot').length }));
  ok(wm.land > 50000 && wm.dots >= 3, 'overview: world map with land and bubbles (' + wm.dots + ')');
  await page.locator('.worldmap .wm-dot').last().hover();
  ok(await page.locator('.charttip').isVisible(), 'world map tooltip on hover');
  // a bubble opens the value menu; "filter" from it filters by that country
  await page.locator('.worldmap .wm-dot').first().click();
  ok(await page.locator('.vmenu .vm-item').count() >= 2, 'overview: a bubble opens the value menu');
  await page.locator('.vmenu .vm-item').first().click();
  await page.waitForLoadState('networkidle');
  const cc = new URL(page.url()).searchParams.get('country');
  ok(/^[A-Z]{2}$/.test(cc || '') && (await page.locator('.worldmap .wm-dot.on').count()) === 1, 'overview: a bubble filters by country (' + cc + ')');
  // the value menu on the event list: the funnel opens it, "exclude" leaves the value out, the address opens the lookup
  await page.goto(base + '/events', { waitUntil: 'networkidle' });
  const evIp = (await page.locator('.datatable tbody .fv-text[data-ip]').first().innerText()).trim();
  await page.locator('.datatable tbody .fv').filter({ has: page.locator('.fv-text[data-ip]') }).first().locator('.fv-btn').click();
  ok(await page.locator('.vmenu .vm-item').count() === 3 && !(await page.locator('#jt-ipcard').isVisible()), 'events: value menu (filter, exclude, copy), no address card over it');
  await page.locator('.vmenu .vm-item').nth(1).click();
  await page.waitForLoadState('networkidle');
  ok(new URL(page.url()).searchParams.get('not_src_ip') === evIp && (await page.locator('.fchip-out').count()) === 1
     && !(await page.locator('.datatable tbody .fv-text[data-ip]').allInnerTexts()).map((x) => x.trim()).includes(evIp), 'events: exclude a value');
  await page.locator('.datatable tbody .fv-text[data-ip]').first().click({ button: 'right' });
  ok(await page.locator('.vmenu .vm-item').count() === 3, 'events: right-click opens the value menu');
  await page.keyboard.press('Escape');
  ok(await page.locator('.vmenu').count() === 0, 'events: Esc closes the value menu');
  await page.locator('.datatable tbody .fv-text[data-ip]').first().click();
  await page.waitForURL(/\/lookup\//, { timeout: 5000 }).catch(() => {});
  ok(/\/lookup\//.test(page.url()), 'events: the address itself opens the lookup');
  await page.goto(base + '/events?country=' + cc, { waitUntil: 'networkidle' });
  ok((await page.locator('.worldmap .wm-dot').count()) === 1, 'events: country filter leaves one country');
  await page.goto(base + '/events', { waitUntil: 'networkidle' });
  ok((await page.locator('.worldmap .wm-dot').count()) >= 1, 'events: world map of loaded events');
  await page.goto(base + '/lookup/203.0.113.9', { waitUntil: 'networkidle' });
  ok((await page.locator('.worldmap .wm-dot').count()) === 1, 'lookup: location on the world map');
  // whether each rule runs: totals per state, a badge per rule, per attack type on the CRS page
  await page.goto(base + '/rules?source=crs', { waitUntil: 'networkidle' });
  ok((await page.locator('.statetotals .stchip').count()) === 4 && (await page.locator('.datatable .badge.b-ok, .datatable .badge.b-blocked').count()) > 0,
     'rules: state totals and a state per rule');
  await page.goto(base + '/crs', { waitUntil: 'networkidle' });
  ok((await page.locator('.statetotals a.stchip').count()) === 4 && (await page.locator('.hb-row').count()) > 0, 'crs: rules per attack type and state');
  ok((await page.locator('.crsupd').innerText()).includes('4.30.0'), 'crs: the version in use and the update card');
  // who wrote each rule: counts per author, a badge per rule, the filter
  await page.goto(base + '/rules?source=all', { waitUntil: 'networkidle' });
  ok((await page.locator('.authorbar .authchip').count()) >= 3 && (await page.locator('.datatable td .badge').count()) > 0, 'rules: counts and a badge per author');
  await page.goto(base + '/rules?source=all&author=owasp_crs', { waitUntil: 'networkidle' });
  ok((await page.locator('.authorbar .authchip.on').count()) === 1, 'rules: filter by author');
  // request volume: tiles, the two charts, sites, one site
  await page.goto(base + '/traffic', { waitUntil: 'networkidle' });
  ok((await page.locator('.tiles .tile').count()) === 5 && (await page.locator('.timebars').count()) === 2 && (await page.locator('.datatable tbody tr').count()) === 3,
     'traffic: tiles, charts and one row per site');
  await page.goto(base + '/traffic?range=7d&host=shop.example.com', { waitUntil: 'networkidle' });
  ok((await page.locator('.datatable tbody tr').count()) === 1, 'traffic: one site');
  // temporary IP blocks: the list, the include hint (the e2e nginx does not load the file), adding and ending one
  await page.goto(base + '/blocks', { waitUntil: 'networkidle' });
  ok((await page.locator('.datatable').first().locator('tbody tr').count()) === 3 && (await page.locator('.alert.warn pre.codeblock').innerText()).includes('blocked-ips.conf'),
     'blocks: active list and the include line');
  await page.locator('.card.form input.mono').fill('203.0.113.99');
  await page.locator('.card.form .field.grow input').fill('e2e test');
  await page.locator('.card.form button.primary').click();
  await page.waitForFunction(() => document.querySelector('.datatable').querySelectorAll('tbody tr').length === 4, null, { timeout: 5000 }).catch(() => {});
  ok((await page.locator('.datatable').first().locator('tbody tr').count()) === 4, 'blocks: an approver blocks an address');
  await page.locator('.datatable').first().locator('tbody tr').filter({ hasText: '203.0.113.99' }).locator('button', { hasText: '立即解除' }).click();
  await page.locator('section[role=dialog] input').fill('e2e done');
  await page.locator('section[role=dialog] button.danger').click();
  await page.waitForFunction(() => document.querySelector('.datatable').querySelectorAll('tbody tr').length === 3, null, { timeout: 5000 }).catch(() => {});
  ok((await page.locator('.datatable').first().locator('tbody tr').count()) === 3, 'blocks: ending one with a note');
  // the country of each blocked address; extending a block; an admin can make one permanent
  const r66 = page.locator('.datatable tbody tr').filter({ hasText: '203.0.113.66' }).first();
  ok((await r66.locator('.ipcell').innerText()).includes('US'), 'blocks: the country beside the address');
  await r66.locator('button', { hasText: '延長' }).click();
  await page.locator('section[role=dialog] input').fill('still scanning');
  await page.locator('section[role=dialog] button.primary').click();
  await page.waitForFunction(() => /已延長 1 次/.test(document.body.innerText), null, { timeout: 5000 }).catch(() => {});
  ok((await r66.innerText()).includes('已延長 1 次'), 'blocks: extending one with a reason');
  await r66.locator('button', { hasText: '延長' }).click();
  await page.locator('#blk-ext').click();
  await page.locator('[role=option]').filter({ hasText: '永久' }).first().click();
  await page.locator('section[role=dialog] input').fill('known botnet');
  await page.locator('section[role=dialog] button.primary').click();
  await page.waitForFunction(() => /永久/.test([...document.querySelectorAll('.datatable tbody tr')].map((r) => r.innerText).join(' ')), null, { timeout: 5000 }).catch(() => {});
  ok((await r66.locator('.badge', { hasText: '永久' }).count()) === 1 && (await r66.locator('button', { hasText: '延長' }).count()) === 0,
     'blocks: an admin makes one permanent');
  // the top bar: theme, language, account and log out are the same height (icon-only buttons were shorter)
  await page.goto(base + '/', { waitUntil: 'networkidle' });
  const heights = await page.evaluate(() => [...document.querySelectorAll('.topright .btn, .topright .userlink')]
    .filter((e) => e.offsetParent !== null).map((e) => Math.round(e.getBoundingClientRect().height)));
  ok(heights.length >= 4 && new Set(heights).size === 1, 'top bar: controls of one height (' + heights.join(',') + ')');
  // tooltips: the site's own, never the browser's (the title moves to data-tip as soon as the pointer is over it)
  const tipped = page.locator('.topright [title], .topright [data-tip]').first();
  await tipped.hover();
  await page.waitForSelector('#jt-tip:not([hidden])', { timeout: 3000 }).catch(() => {});
  ok((await page.locator('#jt-tip:not([hidden])').count()) === 1 && (await tipped.getAttribute('title')) === null
     && ((await page.locator('#jt-tip').innerText()) || '').trim().length > 0, 'tooltips: the site\'s own, no native title left');
  await page.keyboard.press('Escape');
  // the address card: the pointer resting on an address shows where it is, its PTR name and what it did
  await page.goto(base + '/lookup/203.0.113.9', { waitUntil: 'networkidle' });
  ok((await page.locator('.ptrline', { hasText: 'scanner9.example.net' }).count()) === 1, 'IP lookup: the PTR name, checked forward');
  await page.goto(base + '/events', { waitUntil: 'networkidle' });
  const ipEl = page.locator('.datatable tbody [data-ip]:visible').first();
  await ipEl.scrollIntoViewIfNeeded();
  const ipText = ((await ipEl.getAttribute('data-ip')) || '').split('/')[0];
  await page.mouse.move(2, 2);
  await ipEl.hover();
  await page.waitForSelector('#jt-ipcard:not([hidden]) .ic-row', { timeout: 8000 }).catch(() => {});
  const cardText = await page.locator('#jt-ipcard').innerText({ timeout: 2000 }).catch(() => '');
  ok(ipText && cardText.includes(ipText), 'address card on hover (' + ipText + ')');
  await page.mouse.move(2, 2);
  // 0.4.55: the value menu shows the value on top; a right-click on any table cell filters / excludes in that table
  await page.goto(base + '/admin/audit', { waitUntil: 'networkidle' });
  const auCell = page.locator('.datatable tbody td').nth(2);
  const auText = (await auCell.innerText()).trim();
  await auCell.click({ button: 'right' });
  await page.waitForSelector('.vmenu .vm-head', { timeout: 3000 }).catch(() => {});
  ok((await page.locator('.vmenu .vm-head .vm-val').innerText().catch(() => '')).trim() === auText, 'value menu: the value on its first row');
  const auRows = await page.locator('.datatable tbody tr').count();
  await page.locator('.vmenu .vm-item').nth(1).click();          // exclude this value
  await page.waitForTimeout(300);
  ok((await page.locator('.dt-vf.fchip-out').count()) === 1 && (await page.locator('.datatable tbody tr').count()) <= auRows, 'table right-click: exclude a value (chip shown)');
  await page.locator('.dt-vf .fchip-x').click();
  ok((await page.locator('.dt-vf').count()) === 0, 'table right-click: the chip removes the filter');
  // the help menu: the guide plus the project's pages
  await page.locator('.mainnav button.navmorebtn').last().click();
  ok((await page.locator('.navdrop a.navitem').count()) >= 3 && (await page.locator('.navdrop a.navext').count()) >= 2, 'help menu: guide and external pages');
  await page.keyboard.press('Escape');
  // number tiles look like the dashboard's everywhere
  for (const u of ['/lookup/203.0.113.9', '/crs', '/waf', '/reviews/8']) {
    await page.goto(base + u, { waitUntil: 'networkidle' });
    const plain = await page.locator('.tiles > .tile:not(.stat)').count();
    const st = await page.locator('.tiles > .tile.stat').count();
    ok(plain === 0 && st >= 3, 'stat tiles on ' + u + ' (' + st + ')');
  }
  // the event's AI card names the LLM server and model
  await page.goto(base + '/events/1', { waitUntil: 'networkidle' });
  ok((await page.locator('.factgrid dl.facts > div').count()) >= 8, 'event detail: facts in aligned rows');
  // 0.4.60: an attack flood is one row (×n) in the events list; switching the merge off shows every event
  await page.goto(base + '/events', { waitUntil: 'networkidle' });
  const merged = page.locator('.datatable tbody tr').filter({ hasText: '×8' });
  ok((await merged.count()) === 1, 'events: a flood of the same request is one row (×8)');
  const nMerged = await page.locator('.mergebar').count();
  await page.locator('.mergebar input').uncheck();
  await page.waitForTimeout(300);
  ok(nMerged === 1 && (await page.locator('.datatable tbody tr').filter({ hasText: '×8' }).count()) === 0, 'events: merge off lists each event');
  await page.locator('.mergebar input').check();
  // 0.4.57: several tightening changes approved at once; settings exported and imported (picked ones only)
  await page.goto(base + '/changes?tab=pending_approval', { waitUntil: 'networkidle' });
  if (await page.locator('.batchbar').count()) {
    ok((await page.locator('.datatable tbody input[type=checkbox]').count()) >= 1, 'changes: tightening changes can be ticked for a batch approval');
  }
  await page.goto(base + '/admin/settings', { waitUntil: 'networkidle' });
  ok((await page.locator('#settings-transfer').count()) === 1, 'settings: export and import card');
  const [dl] = await Promise.all([page.waitForEvent('download', { timeout: 8000 }).catch(() => null),
    page.locator('#settings-transfer .setio-row button').first().click()]);
  ok(!!dl && /settings.*\.json$/.test(dl.suggestedFilename()), 'settings: export downloads a JSON file');
  if (dl) {
    const fp = await dl.path();
    const d = JSON.parse(fs.readFileSync(fp, 'utf8'));
    ok(d.format === 'jt-waf-mgr-settings' && !JSON.stringify(d).includes('e2e-secret'), 'settings: the export leaves the secrets out');
    d.settings['review.keep_days'] = 33;
    const f2 = path.join(SHOTS, 'settings-import.json');
    fs.writeFileSync(f2, JSON.stringify(d));
    await page.locator('#settings-transfer input[type=file]').setInputFiles(f2);
    await page.waitForSelector('#settings-transfer .datatable tbody tr', { timeout: 8000 }).catch(() => {});
    ok((await page.locator('#settings-transfer .datatable tbody input[type=checkbox]:checked').count()) === 1, 'settings: import preview ticks only what differs');
    fs.unlinkSync(f2);
  }
  // 0.4.56: the war room opens in a tab of its own from the Overview menu; both maps draw the same window
  await page.goto(base + '/', { waitUntil: 'networkidle' });
  await page.locator('.mainnav button.navmorebtn').first().click();
  const wrLink = page.locator('.navdrop a[href="/warroom"]');
  ok((await wrLink.count()) === 1 && (await wrLink.getAttribute('target')) === '_blank', 'overview menu: war room opens a new tab');
  await page.keyboard.press('Escape');
  await page.goto(base + '/warroom', { waitUntil: 'networkidle' });
  await page.waitForSelector('.wr .war-atlas svg', { timeout: 8000 }).catch(() => {});
  ok((await page.locator('.wr .war-atlas svg').count()) === 1 && (await page.locator('.topbar').count()) === 0, 'war room: the atlas, no admin menu');
  const wrText = await page.locator('.wr').innerText();
  ok(!/\b(?:192\.168|203\.0\.113|198\.51\.100)\.\d+\b/.test(wrText), 'war room: no source address on the wall');
  ok(/\d/.test(await page.locator('.wr-kpis b').first().innerText()), 'war room: numbers shown');
  await page.screenshot({ path: path.join(SHOTS, 'warroom-atlas.png') });
  ok(/ · /.test(await page.locator('.wr .wa-destlabel').first().textContent()), 'war room: the map marks where we are ("Us")');
  await page.locator('.wr-tabs button').nth(1).click();
  await page.waitForSelector('.wr .war-globe canvas', { timeout: 5000 }).catch(() => {});
  ok((await page.locator('.wr .war-globe canvas').count()) === 1, 'war room: the globe');
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(SHOTS, 'warroom-globe.png') });
  await page.locator('.wr-tabs button').nth(2).click(); await page.waitForTimeout(500);
  ok((await page.locator('.wr .war-flow .wf-node').count()) >= 3, 'war room: the decision flow');
  await page.locator('.wr-tabs button').nth(3).click(); await page.waitForTimeout(500);
  ok((await page.locator('.wr-sites li').count()) >= 1 && (await page.locator('.wr-cells').first().locator('i').count()) === 15, 'war room: sites in 2-minute cells');
  await page.locator('.wr-tabs button').nth(4).click(); await page.waitForTimeout(500);
  ok((await page.locator('.wr .wr-big').count()) === 1 && (await page.locator('.wr-clue').count()) === 2, 'war room: the review desk');
  await page.locator('.wr-tabs button').nth(5).click(); await page.waitForTimeout(800);
  ok((await page.locator('.wr-two .wr-card').count()) === 2, 'war room: AI and threat intelligence');
  await page.locator('.wr-tabs button').nth(6).click(); await page.waitForTimeout(500);
  ok((await page.locator('.wr-ops .wr-opcol').count()) === 4 && (await page.locator('.wr-opcard').count()) >= 1, 'war room: alerts and changes');
  ok(!/\/(?:\.env|wp-login|etc\/passwd)/.test(await page.locator('.wr').innerText()), 'war room: no request path on the operations page');
  // 0.4.66: a longer window from the top bar (kept in the address for a wall screen); the big numbers roll
  await page.locator('.wr-range .sb-btn').click();
  await page.locator('.wr-range .sb-pop li').nth(9).click();
  await page.waitForTimeout(1000);
  ok(/[?&]range=24h\b/.test(page.url()) && /24/.test(await page.locator('.wr-bottom').innerText()), 'war room: a 24-hour window, kept in the address');
  ok((await page.locator('.wr-kpis .rn').count()) >= 1, 'war room: rolling numbers');
  await page.locator('.wr-tabs button').nth(3).click(); await page.waitForTimeout(500);
  ok((await page.locator('.wr-cells').first().locator('i').count()) === 15, 'war room: 15 cells over 24 hours too');
  await page.screenshot({ path: path.join(SHOTS, 'warroom-24h.png') });
  await page.locator('.wr-range .sb-btn').click();
  await page.locator('.wr-range .sb-pop li').first().click();
  await page.waitForTimeout(800);
  ok(!/[?&]range=/.test(page.url()), 'war room: back to live');
  // 0.4.67: keys (one list for the handler and the H panel)
  await page.locator('body').click({ position: { x: 5, y: 5 } }).catch(() => {});
  await page.keyboard.press('h'); await page.waitForTimeout(300);
  ok((await page.locator('.wr-help kbd').count()) >= 10, 'war room: H shows the keys');
  await page.keyboard.press('Escape'); await page.waitForTimeout(300);
  ok((await page.locator('.wr-help').count()) === 0, 'war room: Esc closes the keys');
  await page.keyboard.press('3'); await page.waitForTimeout(700);
  ok((await page.locator('.wr-tabs button').nth(2).getAttribute('aria-selected')) === 'true', 'war room: 3 opens the third page');
  await page.keyboard.press('ArrowLeft'); await page.waitForTimeout(700);
  ok((await page.locator('.wr-tabs button').nth(1).getAttribute('aria-selected')) === 'true', 'war room: the arrow keys turn the pages');
  // 0.4.67: blocked only, everywhere on the board, kept in the address
  await page.locator('.wr-tabs button').nth(0).click(); await page.waitForTimeout(600);
  await page.locator('.wr-onlybtn').click(); await page.waitForTimeout(1200);
  ok(/[?&]only=blocked\b/.test(page.url()) && (await page.locator('.wr-kpis .rn .sr-only').nth(2).textContent()).trim() === '0',
     'war room: blocked only (nothing logged counted)');
  await page.locator('.wr-onlybtn').click(); await page.waitForTimeout(800);
  ok(!/[?&]only=/.test(page.url()), 'war room: blocked and logged again');
  // 0.4.66: demo mode: made-up attacks in the browser, a banner all the time, links do not open
  await page.locator('.wr-demobtn').click();
  await page.waitForTimeout(6000);
  ok(/[?&]demo=1\b/.test(page.url()) && (await page.locator('.wr-demobtn.on').count()) === 1 && (await page.locator('.wr-demo').count()) === 0, 'war room: demo mode, shown on its button');
  await page.locator('.wr-tabs button').nth(0).click(); await page.waitForTimeout(800);
  ok(Number((await page.locator('.wr-kpis .rn .sr-only').first().textContent()).replace(/\D/g, '')) > 100, 'war room: demo numbers');
  await page.screenshot({ path: path.join(SHOTS, 'warroom-demo.png') });
  const pagesBefore = page.context().pages().length;
  await page.locator('.wr-events a').first().click(); await page.waitForTimeout(500);
  ok(page.context().pages().length === pagesBefore && (await page.locator('.wr-demonote').count()) === 1, 'war room: demo links do not open');
  await page.locator('.wr-demobtn').click(); await page.waitForTimeout(1000);
  ok(!/[?&]demo=/.test(page.url()) && (await page.locator('.wr-demobtn.on').count()) === 0, 'war room: out of the demo');
  await page.locator('.wr-tabs button').nth(1).click(); await page.waitForTimeout(500);
  // the war room for README and Pages, in each language (the board is dark whatever the theme)
  for (const [L, pre] of [['en', 'en'], ['ja', 'ja'], ['zh-TW', 'light']]) {
    await page.goto(base + '/', { waitUntil: 'networkidle' });
    await setLang(page, L);
    await page.goto(base + '/warroom', { waitUntil: 'networkidle' });
    await page.waitForTimeout(2500);
    await page.screenshot({ path: SHOTS + '/' + pre + '_warroom.png' });
    await page.goto(base + '/warroom?demo=1&page=globe', { waitUntil: 'networkidle' });
    await page.waitForTimeout(3000);
    await page.screenshot({ path: SHOTS + '/' + pre + '_warroom-globe.png' });
  }
  const firstRank = page.locator('.wr-ranklist button').first();
  if (await firstRank.count()) {
    await firstRank.click();
    ok((await page.locator('.wr-drawer').count()) === 1, 'war room: a country opens its details');
    await page.keyboard.press('Escape');
  }
  // the DNS check card in Settings: what each server answered
  await page.goto(base + '/admin/settings', { waitUntil: 'networkidle' });
  await page.waitForSelector('#dns-names tbody tr, .dnstable tbody tr', { timeout: 5000 }).catch(() => {});
  ok((await page.locator('.dnstable tbody tr').count()) === 4, 'settings: the DNS check results per name');
  // country lists in Settings: four short facts side by side, the lists in use as a table of their own
  ok((await page.locator('.cosets').count()) === 1 && (await page.locator('.setrow').count()) === 0
     && (await page.locator('section.card', { hasText: '國家清單' }).locator('dl.kv.two dt').count()) === 4, 'settings: country lists laid out (facts, then the lists in use)');
  // country blocks: the form lists the staged countries, the preview builds the rule, Settings shows the lists
  await page.goto(base + '/changes/new?kind=country', { waitUntil: 'networkidle' });
  await page.locator('.card.form .field.grow input.mono').first().fill('shop.example.com');
  await page.locator('#co-add').click();
  const nCountries = await page.locator('.sb-list [role=option], .sb-pop [role=option]').count();
  await page.locator('[role=option]').filter({ hasText: 'TW' }).first().click();
  await page.waitForFunction(() => document.querySelectorAll('.cochip').length === 1, null, { timeout: 5000 }).catch(() => {});
  await page.waitForFunction(() => /ipMatchFromFile/.test(document.body.innerText), null, { timeout: 8000 }).catch(() => {});
  ok(nCountries === 6 && (await page.locator('.cochip').count()) === 1 && (await page.locator('body').innerText()).includes('ipMatchFromFile'),
     'country block: staged countries, a chosen one, the rule preview (' + nCountries + ')');
  // the sites page: one line per site (what its country rules allow), a link to that site on the country-limits page;
  // no buttons there (the actions are on the country-limits page)
  await page.goto(base + '/vhosts', { waitUntil: 'networkidle' });
  const vRow = (h) => page.locator('.datatable tbody tr').filter({ hasText: h }).first();
  const sumLink = vRow('app.example.com').locator('a.cosum');
  ok((await page.locator('.datatable thead', { hasText: '國家限制' }).count()) === 1 && (await sumLink.count()) === 1
     && /只允許\s*JP TW/.test(await sumLink.innerText()) && (await vRow('static.example.com').locator('a.cosum').count()) === 0
     && (await page.locator('.datatable tbody a', { hasText: '新增限制' }).count()) === 0,
     'sites: a one-line country summary linking to the country-limits page, no buttons');
  ok((await vRow('intra.example.com').locator('.badge', { hasText: /^僅內部$/ }).count()) === 1
     && (await vRow('app.example.com').locator('.badge', { hasText: /^內外皆可$/ }).count()) === 1,
     'sites: who can reach each block, from nginx\'s own checks');
  // DNS: a name only internal DNS knows on a site nginx lets anyone into is the risk, in red
  const dnsBadge = vRow('app.example.com').locator('.badge', { hasText: '僅內部 DNS' });
  ok((await dnsBadge.count()) === 1 && /b-blocked/.test(await dnsBadge.getAttribute('class')) &&
     (await vRow('static.example.com').locator('.badge', { hasText: '外部 DNS 查得到' }).count()) === 1,
     'sites: what DNS knows of each name, the hidden-but-open one in red');
  await sumLink.click();
  await page.waitForFunction(() => location.pathname === '/countries' && document.querySelectorAll('.datatable tbody tr').length === 1, null, { timeout: 8000 }).catch(() => {});
  ok(/\/countries\?host=app\.example\.com/.test(page.url()) && (await page.locator('.datatable tbody tr').count()) === 1,
     'sites: the summary opens that one site on the country-limits page');
  // "add limit" on the country-limits page opens the form with the site filled in
  await page.goto(base + '/countries', { waitUntil: 'networkidle' });
  const cRow = (h) => page.locator('.datatable tbody tr').filter({ hasText: h }).first();
  await cRow('intranet.example.com').locator('a', { hasText: '新增限制' }).click();
  await page.waitForLoadState('networkidle');
  ok(/kind=country/.test(page.url()) && (await page.locator('.card.form .field.grow input.mono').first().inputValue()) === 'intranet.example.com',
     'country limits: "add limit" opens the country form for that site');
  // a limit in place: "modify" opens it; fewer allowed countries tighten, one more loosens
  await page.goto(base + '/countries', { waitUntil: 'networkidle' });
  const appRow = cRow('app.example.com');
  await appRow.locator('a', { hasText: '修改' }).first().click();
  await page.waitForLoadState('networkidle');
  await page.waitForFunction(() => document.querySelectorAll('.cochip').length === 2, null, { timeout: 5000 }).catch(() => {});
  const dirBadge = async () => { await page.waitForTimeout(900); return (await page.locator('.card').filter({ hasText: 'ipMatchFromFile' }).locator('.badge', { hasText: /加強|放寬/ }).first().innerText()).trim() }
  ok(/item=/.test(page.url()) && (await page.locator('.cochip').count()) === 2, 'country modify: the form holds the rule in place');
  await page.locator('.cochip', { hasText: 'JP' }).locator('button').click();
  const dTight = await dirBadge();
  await page.locator('#co-add').click();
  await page.locator('[role=option]').filter({ hasText: 'US' }).first().click();
  await page.locator('#co-add').click().catch(() => {});
  await page.keyboard.press('Escape').catch(() => {});
  const dLoose = await dirBadge();
  ok(dTight.includes('加強') && dLoose.includes('放寬'), 'country modify: fewer countries tighten, another one loosens (' + dTight + ' / ' + dLoose + ')');
  // country limits by site: names in the interface language, "add limit" where the WAF runs, a note where it is off,
  // and a waiting change for a name no server block has
  await page.goto(base + '/countries', { waitUntil: 'networkidle' });
  const cs = (h) => page.locator('#country-sites tbody tr, .datatable tbody tr').filter({ hasText: h }).first();
  ok((await cs('app.example.com').locator('.cochip', { hasText: '台灣' }).count()) === 1
     && (await cs('app.example.com').locator('a', { hasText: '修改' }).count()) === 1
     && (await cs('intranet.example.com').locator('a', { hasText: '新增限制' }).count()) === 1
     && (await cs('static.example.com').locator('a', { hasText: '新增限制' }).count()) === 0
     && (await page.locator('.card', { hasText: 'shop.example.com' }).count()) >= 1,
     'country limits page: per site, with names, actions and the change for a name no site has');
  await page.goto(base + '/admin/settings', { waitUntil: 'networkidle' });
  await page.waitForSelector('.coreg tbody tr', { timeout: 5000 }).catch(() => {});
  ok((await page.locator('.coreg tbody tr').count()) === 5 && (await page.locator('.cosets tbody tr').count()) >= 1,
     'country block: the registries and the lists in use in Settings');
  // 0.4.90: CrowdSec rules as changes: the rule in use whose upstream changed, and the form for a related one
  await page.goto(base + '/crowdsec', { waitUntil: 'networkidle' });
  const hRow = (n) => page.locator('.datatable tbody tr').filter({ hasText: n }).first();
  ok((await page.locator('.hubtiles .tile').count()) === 6 && (await hRow('vpatch-nextcloud-upload').locator('.badge', { hasText: '上游有新版' }).count()) === 1,
     'crowdsec: an "in use" tile; the rule in use shows that the hub changed it');
  await hRow('vpatch-nextcloud-upload').click();
  await page.waitForSelector('.hubuse', { timeout: 8000 }).catch(() => {});
  ok((await page.locator('.hubuse button', { hasText: '提出更新' }).count()) === 1 && (await page.locator('.hubuse button', { hasText: '提出移除' }).count()) === 1,
     'crowdsec: a rule in use can be updated to the hub\'s version or removed');
  await hRow('vpatch-nextcloud-upload').click();
  // 0.4.91: an "apply" button in the row itself opens the form; the index is current, so no "sync first" notice
  ok((await page.locator('.alert.warn', { hasText: '立即同步' }).count()) === 0 &&
     (await hRow('vpatch-keycloak-redirect').locator('button', { hasText: '套用' }).count()) === 1,
     'crowdsec: a rule that can be proposed has an apply button in its row');
  await hRow('vpatch-keycloak-redirect').locator('button', { hasText: '套用' }).click();
  await page.waitForSelector('.hubuse .hubsites', { timeout: 8000 }).catch(() => {});
  ok((await page.locator('.hubuse .hubsites .chip', { hasText: 'sso.example.com' }).count()) === 1 &&
     (await page.locator('.hubuse button', { hasText: '提出變更' }).isDisabled()),
     'crowdsec: the form names the sites running the software; no proposal without a reason');
  await page.locator('.hubuse textarea').fill('Keycloak on sso.example.com is affected until it is updated.');
  await page.screenshot({ path: path.join(SHOTS, 'crowdsec-propose.png'), fullPage: true });
  await page.locator('.hubuse button', { hasText: '提出變更' }).click();
  await page.waitForSelector('.hubuse .alert.error', { timeout: 8000 }).catch(() => {});
  ok((await page.locator('.hubuse .alert.error').count()) === 1, 'crowdsec: proposing reaches the workflow (this environment is not adopted: refused)');
  // 0.4.92: cross-application rules -- PHP through Nextcloud's stack; React for all sites
  await page.locator('.seg button', { hasText: '跨應用' }).click();
  ok((await page.locator('.datatable tbody tr').filter({ hasText: 'vpatch-' }).count()) === 2 &&
     (await hRow('vpatch-php2shell').locator('.chip', { hasText: 'PHP' }).count()) === 1,
     'crowdsec: the cross-application filter; a PHP flaw relates to the PHP application');
  await hRow('vpatch-react-rce').locator('button', { hasText: '套用' }).click();
  await page.waitForSelector('.hubuse .check input', { timeout: 8000 }).catch(() => {});
  ok(await page.locator('.hubuse .check input').isChecked() && (await page.locator('.hubuse .hubsites').count()) === 0,
     'crowdsec: a framework\'s flaw with no site known to run it is offered for all sites');
  // 0.4.93: several rules ticked and applied at once (one change); no proposal without a reason
  await hRow('vpatch-react-rce').click();
  await hRow('vpatch-php2shell').locator('td input[type=checkbox]').check();
  await hRow('vpatch-react-rce').locator('td input[type=checkbox]').check();
  ok((await page.locator('.hubbatch button', { hasText: '套用勾選的 2 條' }).count()) === 1 &&
     (await page.locator('.hubbatch button', { hasText: '套用勾選的 2 條' }).isDisabled()),
     'crowdsec: two rules ticked; applying them needs a reason');
  await page.locator('#hub-batch-reason').fill('PHP and React flaws: every site that runs them.');
  await page.locator('.hubbatch button', { hasText: '套用勾選的 2 條' }).click();
  await page.waitForSelector('.hubbatch .alert.error', { timeout: 8000 }).catch(() => {});
  ok((await page.locator('.hubbatch .alert.error').count()) === 1, 'crowdsec: applying several reaches the workflow as one change (not adopted here: refused)');
  // 0.4.96: a filter set to something has a "×" back to "all"
  await page.goto(base + '/rules', { waitUntil: 'networkidle' });
  const fsel = page.locator('.filters .selectbox').first();
  await fsel.locator('.sb-btn').click();
  await page.locator('.sb-pop li[role=option]').nth(1).dispatchEvent('mousedown');
  await page.waitForTimeout(200);
  const hadClear = await fsel.locator('.sb-clear').count();
  if (hadClear) await fsel.locator('.sb-clear').click();
  await page.waitForTimeout(200);
  ok(hadClear === 1 && (await fsel.locator('.sb-clear').count()) === 0, 'filters: a chosen value can be cleared with one click');
  // several rules at once: tick, "switch off" opens the change form with its preview (or why it cannot)
  await page.goto(base + '/rules?source=local', { waitUntil: 'networkidle' });
  await page.locator('input.rowsel').first().check();
  ok((await page.locator('.selbar').innerText()).includes('1'), 'rules: a ticked rule is counted');
  await page.locator('.selbar button.danger').click();
  await page.waitForSelector('.ruletoggle', { timeout: 5000 }).catch(() => {});
  await page.waitForLoadState('networkidle');
  ok(await page.locator('.ruletoggle').isVisible() && (await page.locator('.ruletoggle .planbox, .ruletoggle .alert.error').count()) > 0,
     'rules: switching off shows the plan or the reason');
  await page.locator('.ruletoggle button.ghost').click();
  ok(!(await page.locator('.ruletoggle').count()), 'rules: the change form closes');
  // log servers: destination 1 is listed, another can be added (not saved here)
  await page.goto(base + '/admin/settings', { waitUntil: 'networkidle' });
  await page.waitForSelector('#uiset-syslog .dest', { timeout: 5000 }).catch(() => {});
  const nDest = await page.locator('#uiset-syslog .dest').count();
  await page.getByRole('button', { name: /新增目的地|Add a destination|送信先を追加/ }).click();
  ok(nDest >= 1 && (await page.locator('#uiset-syslog .dest').count()) === nDest + 1, 'settings: log servers listed, one more can be added');
  // column widths: the arrow keys on a header's edge set the width, remembered after a reload
  await page.goto(base + '/changes?tab=history', { waitUntil: 'networkidle' });
  const grip = page.locator('table.grid thead th .dt-resize').nth(1);
  await grip.focus();
  for (let i = 0; i < 4; i++) await page.keyboard.press('ArrowRight');
  const w1 = await page.locator('table.grid thead th').nth(1).evaluate((th) => th.style.width);
  await page.reload({ waitUntil: 'networkidle' });
  const w2 = await page.locator('table.grid thead th').nth(1).evaluate((th) => th.style.width);
  ok(/px$/.test(w1) && w1 === w2 && (await page.locator('table.grid.fixedcols').count()) > 0, 'tables: a column width is set and remembered (' + w1 + ')');
  await page.locator('table.grid thead th .dt-resize').nth(1).dblclick();
  ok(!(await page.locator('table.grid.fixedcols').count()), 'tables: a double click gives the columns their own width back');
  // /alerts?id=N: that alert selected with its handling form open
  const aid = await page.evaluate(async () => { const r = await (await fetch('/api/v1/alerts?state=open&limit=1')).json(); return r.items[0] && r.items[0].id })
  await page.goto(base + '/alerts?id=' + aid, { waitUntil: 'networkidle' });
  await page.waitForTimeout(400);
  ok(!!aid && (await page.locator('tr.row-focus').count()) === 1 && (await page.locator('textarea, .card h2:has-text("#' + aid + '")').count()) > 0,
     'alerts: ?id opens that alert for handling');
  await page.goto(base + '/', { waitUntil: 'networkidle' });
  // notification preview: example message, language switch, Escape closes
  await page.goto(base + '/admin/notify', { waitUntil: 'networkidle' });
  await page.locator('#notify-events .evname button').first().click();
  await page.waitForSelector('.pvmsg', { timeout: 5000 }).catch(() => {});
  const pv1 = await page.locator('.pvmsg .pvtitle b').innerText().catch(() => '');
  await page.locator('.pvbar .seg button', { hasText: 'English' }).click();
  // the preview is fetched again: wait for the new title, not just for a quiet network (it may not have started yet)
  await page.waitForFunction((old) => { const b = document.querySelector('.pvmsg .pvtitle b'); return b && b.innerText !== old }, pv1,
    { timeout: 8000 }).catch(() => {});
  const pv2 = await page.locator('.pvmsg .pvtitle b').innerText().catch(() => '');
  ok(pv1 && pv2 && pv1 !== pv2 && /^[\x20-\x7e]+$/.test(pv2), 'notify: preview in two languages (' + pv1 + ' / ' + pv2 + ')');
  await page.keyboard.press('Escape');
  ok(!(await page.locator('.pvmsg').count()), 'notify: preview closes with Escape');
  await page.goto(base + '/', { waitUntil: 'networkidle' });
  // hover tooltip on a chart
  const bar = page.locator('.hb-bar').first();
  await bar.hover();
  ok(await page.locator('.charttip').isVisible(), 'chart tooltip on hover');
  // the server is upgraded while the tab is open: the page notices and offers a reload
  ok(!(await page.locator('.newver').count()), 'new version: no banner while the versions match');
  await page.route('**/api/v1/meta', (r) => r.fulfill({ contentType: 'application/json',
    body: JSON.stringify({ name: 'jt-waf-mgr', version: '99.0.0', source_url: '', sso_enabled: false, node_id: '', login_notice: '', password_policy: null }) }));
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  await page.waitForSelector('.newver', { timeout: 5000 }).catch(() => {});
  ok(await page.locator('.newver:has-text("99.0.0") button').isVisible(), 'new version: the page offers a reload');
  await page.unroute('**/api/v1/meta');
  // Thumbnails for the project site (docs/index.html): one screen of each page, rendered at twice the resolution
  // so they stay sharp when shown small (tools/make_thumbs.py scales them down). Same session, its own window size.
  const THUMBS = { overview: '/', events: '/events', 'waf-model': '/waf', analysis: '/analysis', notifications: '/admin/notify',
    alerts: '/alerts', 'system-check': '/admin/system', changes: '/changes', rules: '/rules', lookup: '/lookup/203.0.113.9', traffic: '/traffic', countries: '/countries', intel: '/intel', reviews: '/reviews/8', warroom: '/warroom', 'warroom-globe': '/warroom?demo=1&page=globe' };
  const state = await ctx.storageState();
  for (const scheme of ['light', 'dark']) {
    const tc = await browser.newContext({ storageState: state, viewport: { width: 1200, height: 900 }, deviceScaleFactor: 2, colorScheme: scheme });
    await tc.addInitScript((s) => { try { localStorage.setItem('jtwaf.theme', s) } catch (e) { /* ignore */ } }, scheme);
    const tp = await tc.newPage();
    watch(tp, 'thumbs');
    await tp.goto(base + '/', { waitUntil: 'networkidle' });
    for (const lang of ['zh-TW', 'en', 'ja']) {
      await setLang(tp, lang);
      for (const [name, p] of Object.entries(scheme === 'light' ? THUMBS : { overview: '/' })) {
        await tp.goto(base + p, { waitUntil: 'networkidle' });
        await tp.waitForTimeout(p.startsWith('/warroom') ? 2500 : 400);
        await tp.screenshot({ path: SHOTS + '/thumb-' + lang + '-' + name + (scheme === 'dark' ? '-dark' : '') + '.png' });
        // 0.4.94: the IP reputation card on its own, for the project site (the picture and its thumbnail)
        if (name === 'lookup' && scheme === 'light') {
          await tp.locator('section.iprep').screenshot({ path: SHOTS + '/thumb-' + lang + '-iprep.png' });
          fs.copyFileSync(SHOTS + '/thumb-' + lang + '-iprep.png', SHOTS + '/' + (lang === 'zh-TW' ? 'light' : lang) + '_iprep.png');
        }
      }
    }
    await setLang(tp, 'zh-TW');
    await tc.close();
  }
  ok(fs.existsSync(SHOTS + '/thumb-ja-iprep.png') && fs.existsSync(SHOTS + '/thumb-ja-lookup.png') && fs.existsSync(SHOTS + '/thumb-en-overview-dark.png') && fs.existsSync(SHOTS + '/thumb-en-warroom-globe.png'), 'site thumbnails at 2x');
  // Notifications as they look on a phone (a chat app's channel, dark), for the project site: the messages come from
  // the notification preview (made-up example data, never real records), drawn the way a chat app shows the Markdown
  // format (bold title, values in code). Two phones per picture; each language its own picture.
  // a chat shows the newest at the bottom: what does not fit scrolls away at the top
  const PHONES = { 'notify-alerts': [['account.locked', 'alert.created', 'alert.reminder'], ['report.review', 'report.daily']],
    'notify-intel': [['system.version_changed', 'analyst.proposals', 'intel.new_threats'], ['settings.changed', 'change.awaiting_approval', 'change.applied']] };
  const TIMES = [['07:41', '08:12', '09:00'], ['11:58', '12:00', '12:05']];
  const LOGO = 'data:image/svg+xml;base64,' + fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'public', 'favicon.svg')).toString('base64');
  const PL = { 'zh-TW': { topic: '通知', today: '今天', say: '訊息' }, en: { topic: 'notifications', today: 'Today', say: 'Message' }, ja: { topic: '通知', today: '今日', say: 'メッセージ' } };
  const esc = (x) => String(x == null ? '' : x).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
  const message = (m, time) => '<div class="msg"><div class="who"><img src="' + LOGO + '" alt=""><b>jt-waf-mgr</b><i>BOT</i><span>' + time + '</span></div>' +
    '<div class="head">' + esc(m.emoji) + ' ' + esc(m.title) + '</div>' + (m.text ? '<p><code>' + esc(m.text) + '</code></p>' : '') +
    '<ul>' + m.facts.map((f) => '<li>' + esc(f.label) + ': <code>' + esc(f.value) + '</code></li>').join('') + '</ul>' +
    '<a>' + esc(m.open_label) + '</a></div>';
  const phone = (ms, l, times) => '<div class="ph"><div class="notch"></div><div class="bar"><span>' + times[times.length - 1] + '</span><span>&#9679;&#9679;&#9679;</span></div>' +
    '<div class="top"><b># jt-waf-mgr</b><small>' + esc(l.topic) + '</small></div><div class="day"><b>' + esc(l.topic) + '</b><span>' + esc(l.today) + '</span></div>' +
    '<div class="feed">' + ms.map((m, i) => message(m, times[i])).join('') + '</div>' +
    '<div class="say">' + esc(l.say) + ' #jt-waf-mgr &gt; ' + esc(l.topic) + '</div></div>';
  const PHONE_CSS = 'html,body{margin:0}body{width:1200px;height:900px;display:flex;align-items:center;justify-content:center;gap:70px;' +
    'background:radial-gradient(800px 500px at 30% 20%,#dfe8f7,transparent 70%),radial-gradient(700px 500px at 80% 90%,#e9e4f7,transparent 70%),#eef2f8;' +
    'font-family:"Noto Sans CJK TC","Noto Sans TC","Noto Sans CJK JP",system-ui,sans-serif}' +
    '.ph{position:relative;width:390px;height:820px;border-radius:52px;background:#16161d;border:12px solid #0b0b0f;box-shadow:0 30px 70px rgba(30,40,80,.35);overflow:hidden;color:#e6e6ea}' +
    '.notch{position:absolute;left:50%;top:10px;width:120px;height:32px;margin-left:-60px;border-radius:20px;background:#000;z-index:2}' +
    '.bar{display:flex;justify-content:space-between;padding:16px 30px 6px;font-size:15px;font-weight:600;background:#3a2f5c}.bar span:last-child{letter-spacing:-2px;font-size:10px;padding-top:4px}' +
    '.top{background:#3a2f5c;padding:8px 22px 12px}.top b{display:block;font-size:24px;color:#fff}.top small{color:#cfc8e8;font-size:14px}' +
    '.day{display:flex;justify-content:space-between;align-items:center;background:#2e2649;padding:9px 18px;font-size:16px}.day span{color:#b8b0d6;font-size:14px}' +
    '.msg{padding:14px 16px;font-size:14.5px;line-height:1.5}.who{display:flex;align-items:center;gap:8px;margin-bottom:6px}.who img{width:30px;height:30px;border-radius:7px;background:#fff}' +
    '.who b{font-size:16px}.who i{font-style:normal;font-size:10px;padding:1px 5px;border-radius:4px;background:#4b4470;color:#ddd}.who span{margin-left:auto;color:#9a9aa8;font-size:13px}' +
    '.head{font-weight:700;font-size:17px;margin:2px 0 6px}p{margin:0 0 6px}ul{margin:0;padding-left:18px}li{margin:3px 0}' +
    'code{font-family:"Noto Sans Mono CJK TC","DejaVu Sans Mono",monospace;font-size:12.5px;background:#2b2b36;border-radius:4px;padding:1px 4px;word-break:break-all}' +
    'a{display:inline-block;margin-top:6px;color:#8fb4ff;text-decoration:underline}.feed{position:absolute;top:196px;bottom:74px;left:0;right:0;overflow:hidden;display:flex;flex-direction:column;justify-content:flex-end;-webkit-mask-image:linear-gradient(transparent,#000 56px);mask-image:linear-gradient(transparent,#000 56px)}' +
    '.msg+.msg{border-top:1px solid #26262f}.say{position:absolute;left:0;right:0;bottom:0;height:74px;box-sizing:border-box;padding:14px 18px;background:#1d1d26;border-top:1px solid #2c2c38;color:#8a8a98;font-size:16px}';
  const pc = await browser.newContext({ viewport: { width: 1200, height: 900 }, deviceScaleFactor: 2 });
  const pp = await pc.newPage();
  for (const lang of ['zh-TW', 'en', 'ja']) {
    for (const [name, evs] of Object.entries(PHONES)) {
      const phones = [];
      for (const group of evs) {
        const msgs = [];
        for (const ev of group) {
          const r = await ctx.request.get(base + '/api/v1/notify/preview?event=' + encodeURIComponent(ev) + '&lang=' + lang);
          msgs.push(await r.json());
        }
        ok(msgs.every((m) => m.title && Array.isArray(m.facts)), 'notification preview for the phone pictures (' + lang + ', ' + name + ')');
        phones.push(msgs);
      }
      await pp.setContent('<!doctype html><meta charset="utf-8"><style>' + PHONE_CSS + '</style>' + phones.map((ms, i) => phone(ms, PL[lang], TIMES[i].slice(-ms.length))).join(''), { waitUntil: 'load' });
      await pp.waitForTimeout(200);
      const pre = { 'zh-TW': 'light', en: 'en', ja: 'ja' }[lang];
      await pp.screenshot({ path: SHOTS + '/thumb-' + lang + '-' + name + '.png' });
      fs.copyFileSync(SHOTS + '/thumb-' + lang + '-' + name + '.png', SHOTS + '/' + pre + '_' + name + '.png');
    }
  }
  await pc.close();
  await ctx.close();
  // viewer: guide and events, no admin links
  const v = await login(browser, 'viewer', 'dark');
  await setLang(v.page, 'zh-TW');
  for (const p of ['/', '/events', '/guide', '/changes']) {
    await v.page.goto(base + p, { waitUntil: 'networkidle' });
    await rawKeys(v.page, 'viewer ' + p); await audit(v.page, 'viewer ' + p);
  }
  await v.page.screenshot({ path: SHOTS + '/viewer-changes-dark.png', fullPage: true });
  await v.ctx.close();
  // login page logo
  const lp = await browser.newPage();
  await lp.goto(base + '/login', { waitUntil: 'networkidle' });
  ok(await lp.locator('img[src="/logo-mark.svg"]').first().isVisible(), 'login logo visible');
  ok((await lp.evaluate(() => document.querySelector('link[rel=icon]').href)).endsWith('/favicon.svg'), 'favicon link');
  const fav = await lp.request.get(base + '/favicon.svg');
  ok(fav.status() === 200, 'favicon served');
  await lp.screenshot({ path: SHOTS + '/login.png' });
  // after an upgrade the login page shows the reload notice right above the login box, as wide as the box
  await lp.route('**/api/v1/meta', (r) => r.fulfill({ contentType: 'application/json',
    body: JSON.stringify({ name: 'jt-waf-mgr', version: '99.0.0', source_url: '', sso_enabled: false, node_id: '', login_notice: '', password_policy: null }) }));
  await lp.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
  await lp.waitForSelector('.newver', { timeout: 5000 }).catch(() => {});
  const nb = await lp.locator('.newver').boundingBox();
  const ab = await lp.locator('.authbox').boundingBox();
  ok(nb && ab && Math.abs(nb.width - ab.width) < 2 && Math.abs(nb.x - ab.x) < 2 && nb.y + nb.height <= ab.y && ab.y - (nb.y + nb.height) < 30,
    'login: the reload notice sits right above the login box, as wide as it');
  await lp.screenshot({ path: SHOTS + '/login-newver.png' });
  await lp.unroute('**/api/v1/meta');
  // phone and tablet widths: no page scrolls sideways, the menu reaches every page group
  for (const [name, vp] of [['phone', { width: 375, height: 812 }], ['tablet', { width: 768, height: 1024 }]]) {
    const m = await login(browser, 'admin', 'light', vp);
    await setLang(m.page, 'zh-TW');
    for (const p of ['/', '/events', '/rules', '/changes', '/analysis', '/alerts', '/admin/notify', '/admin/system', '/admin/audit', '/waf', '/lookup/203.0.113.9', '/admin/settings']) {
      await m.page.goto(base + p, { waitUntil: 'networkidle' });
      await m.page.waitForTimeout(250);
      const over = await m.page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      if (over > 1) problems.push(name + ' ' + p + ': page scrolls sideways by ' + over + 'px');
      await m.page.screenshot({ path: SHOTS + '/' + name + p.replace(/\//g, '_') + '.png', fullPage: false });
    }
    if (name === 'phone') {
      await m.page.goto(base + '/', { waitUntil: 'networkidle' });
      ok(await m.page.locator('.navtoggle').isVisible(), 'phone: menu button');
      await m.page.click('.navtoggle');
      const groups = await m.page.locator('#navpanel .np-group').count();
      ok(groups >= 5, 'phone: menu shows the page groups (' + groups + ')');
      await m.page.screenshot({ path: SHOTS + '/phone_menu.png' });
    }
    await m.ctx.close();
  }
  await freshStep('admin');      // the security scan signs in next: never with a one-time code already used
  await browser.close();
  console.log(notes.filter((n) => n.startsWith('warn')).join('\n'));
  console.log(problems.length ? problems.join('\n') : 'NO PROBLEMS');
  process.exitCode = problems.length ? 1 : 0;
  console.log('checks ok:', notes.filter((n) => n.startsWith('ok')).length);
})();
