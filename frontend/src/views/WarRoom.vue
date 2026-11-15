<!-- The war room (/warroom, opened in a tab of its own from the Overview menu): a dark board for a wall screen.
     A snapshot of the last 30 minutes, then the new events every 5 seconds (the snapshot again every minute).
     Read only: nothing here asks for an analysis or writes anything. No address, path or query reaches this page
     (the API leaves them out); a site served only to internal networks has an alias. -->
<template>
  <div class="wr" :class="{ reduced }" @keydown="onKey">
    <header class="wr-top">
      <div class="wr-brand"><img src="/logo-mark.svg" alt="" width="26" height="26"><b>jt-waf-mgr</b><span class="wr-sep" aria-hidden="true"></span><span>{{ t('war.title') }}</span></div>
      <div class="wr-ctl">
        <span class="wr-state" :class="'st-' + state" role="status" :title="stateHint"><span class="wr-dot" aria-hidden="true"></span>{{ t('war.state.' + state) }}</span>
        <span class="wr-clock mono">{{ clock }}</span><span class="wr-tz mono">{{ tz }}</span>
        <button type="button" class="wr-btn" :class="{ on: rotating }" :aria-pressed="rotating ? 'true' : 'false'" @click="rotating = !rotating"><Icon name="refresh" />{{ t('war.rotate') }}</button>
        <button type="button" class="wr-btn" :class="{ on: paused }" :aria-pressed="paused ? 'true' : 'false'" @click="paused = !paused"><Icon :name="paused ? 'run' : 'timer'" />{{ t(paused ? 'war.resume' : 'war.pause') }}</button>
        <button type="button" class="wr-btn" :class="{ on: frozen }" :aria-pressed="frozen ? 'true' : 'false'" @click="toggleFreeze"><Icon :name="frozen ? 'unlock' : 'lock'" />{{ t(frozen ? 'war.unfreeze' : 'war.freeze') }}</button>
        <button type="button" class="wr-btn" @click="fullscreen"><Icon name="expand" />{{ t('war.fullscreen') }}</button>
      </div>
    </header>
    <nav class="wr-tabs" role="tablist" :aria-label="t('war.title')">
      <button v-for="(p, i) in PAGES" :key="p" type="button" class="wr-tab" role="tab" :aria-selected="page === i ? 'true' : 'false'" :class="{ on: page === i }" @click="go(i)">{{ t('war.page.' + p) }}</button>
    </nav>

    <div v-if="expired" class="wr-msg" role="alert">
      <p>{{ t('war.expired') }}</p>
      <a class="wr-btn" href="/login?next=/warroom"><Icon name="login" />{{ t('war.signin') }}</a>
    </div>
    <template v-else>
      <section class="wr-head">
        <div>
          <div class="wr-eyebrow">{{ PAGES[page] === 'atlas' ? 'GLOBAL EVENT ATLAS' : 'ORBITAL DEFENSE' }}</div>
          <h1>{{ t('war.page.' + PAGES[page]) }}</h1>
          <div v-if="frozen || state === 'offline'" class="wr-asof">{{ t('war.as_of', { time: asOf }) }}</div>
        </div>
        <div class="wr-kpis">
          <div><span>{{ t('war.k.events') }}</span><b>{{ fmtNum(totals.events) }}</b></div>
          <div class="k-blocked"><span>{{ t('war.k.blocked') }}</span><b>{{ fmtNum(totals.blocked) }}</b></div>
          <div class="k-logged"><span>{{ t('war.k.logged') }}</span><b>{{ fmtNum(totals.logged) }}</b></div>
          <div><span>{{ t('war.k.countries') }}</span><b>{{ fmtNum(countries.length) }}</b></div>
        </div>
      </section>

      <div class="wr-grid">
        <section class="wr-card wr-map">
          <div class="wr-card-h"><h2><Icon name="globe" />{{ t(PAGES[page] === 'atlas' ? 'war.map_title' : 'war.globe_title') }}</h2>
            <span class="wr-sub">{{ dest ? t('war.to_dest', { dest: dest.label }) : t('war.no_dest') }}</span></div>
          <div class="wr-mapbox">
            <WarAtlas v-if="PAGES[page] === 'atlas'" :sources="countries" :batches="batches" :destination="dest" :paused="paused || frozen || state === 'offline'"
                      :reduced="reduced" :focus="picked" :label="t('war.map_title')" :describe="describe" @pick="pick" />
            <WarGlobe v-else :sources="countries" :batches="batches" :destination="dest" :paused="paused || frozen || state === 'offline'"
                      :reduced="reduced" :focus="picked" :spin="spin" :label="t('war.globe_title')" :describe="describe" @pick="pick" />
          </div>
          <div class="wr-card-f">
            <span class="wr-legend"><i class="lg-b"></i>{{ t('war.k.blocked') }}<i class="lg-l"></i>{{ t('war.k.logged') }}</span>
            <span v-if="PAGES[page] === 'globe'" class="wr-globectl">
              <button type="button" class="wr-btn small" @click="spin = !spin"><Icon :name="spin ? 'timer' : 'refresh'" />{{ t(spin ? 'war.stop_spin' : 'war.start_spin') }}</button>
            </span>
            <span class="wr-sub">{{ t('war.geo_note') }}</span>
          </div>
        </section>

        <section class="wr-card wr-rank">
          <div class="wr-card-h"><h2><Icon name="chart" />{{ t('war.rank') }}</h2><span class="wr-sub">{{ t('war.window') }}</span></div>
          <ol v-if="countries.length" class="wr-ranklist">
            <li v-for="c in countries.slice(0, 8)" :key="c.cc">
              <button type="button" class="wr-rankrow" :class="{ on: picked === c.cc }" @click="pick(c.cc)">
                <span class="wr-cc mono">{{ c.cc }}</span>
                <span class="wr-cn">{{ countryName(c.cc) || c.cc }}<small>{{ t('war.sources_n', { n: fmtNum(c.sources) }) }}</small></span>
                <span class="wr-n mono">{{ fmtNum(c.events) }}</span>
                <span class="wr-bar" aria-hidden="true"><i class="b" :style="{ width: pct(c.blocked) }"></i><i class="l" :style="{ width: pct(c.logged) }"></i></span>
              </button>
            </li>
          </ol>
          <p v-else class="wr-empty">{{ t('war.no_outside') }}</p>
          <p class="wr-foot">{{ t('war.internal_n', { n: fmtNum(totals.internal) }) }} · {{ t('war.unlocated_n', { n: fmtNum(totals.unlocated) }) }}</p>
        </section>

        <section class="wr-card wr-pulse">
          <div class="wr-card-h"><h2><Icon name="timer" />{{ t('war.intensity') }}</h2><span class="wr-sub">{{ t('war.per_minute', { n: fmtNum(peak) }) }}</span></div>
          <div class="wr-bars" role="img" :aria-label="t('war.intensity')">
            <div v-for="m in minutes" :key="m.t" class="wr-col" :title="fmtTimeShort(m.t) + ' · ' + fmtNum(m.blocked + m.logged)">
              <i class="l" :style="{ height: h(m.logged) }"></i><i class="b" :style="{ height: h(m.blocked) }"></i>
            </div>
          </div>
          <div class="wr-axis mono"><span>{{ minutes.length ? fmtTimeShort(minutes[0].t) : '' }}</span><span>{{ minutes.length ? fmtTimeShort(minutes[minutes.length - 1].t) : '' }}</span></div>
        </section>

        <section class="wr-card wr-latest">
          <div class="wr-card-h"><h2><Icon name="list" />{{ t('war.latest') }}</h2><span class="wr-sub">{{ t('war.click_event') }}</span></div>
          <ul v-if="latest.length" class="wr-events">
            <li v-for="e in latest.slice(0, 7)" :key="e.id">
              <a :href="'/events/' + e.id" target="_blank" rel="noopener">
                <span class="mono">{{ fmtClock(e.ts) }}</span><span class="mono wr-cc2">{{ e.cc === 'LAN' ? t('war.lan') : e.cc }}</span>
                <span class="mono wr-host">{{ e.host }}</span>
                <span class="wr-oc" :class="e.outcome === 'blocked' ? 'b' : 'l'">{{ e.outcome === 'blocked' ? (DECIDED[e.decided_by] ? t(DECIDED[e.decided_by]) : t('war.k.blocked')) : t('war.k.logged') }}</span>
              </a>
            </li>
          </ul>
          <p v-else class="wr-empty">{{ t('war.quiet') }}</p>
        </section>
      </div>

      <footer class="wr-bottom">
        <span><span class="wr-dot" :class="'st-' + state" aria-hidden="true"></span>{{ t('war.footer', { s: POLL / 1000 }) }}</span>
        <span class="mono">jt-waf-mgr · {{ nodeId }}</span>
      </footer>

      <!-- a country picked on the map or in the ranking: its numbers in the window and where to read the events -->
      <aside v-if="picked && pickedRow" class="wr-drawer" role="dialog" :aria-label="countryName(picked) || picked">
        <div class="wr-card-h"><h2><Icon name="globe" /><span class="wr-cc mono">{{ picked }}</span> {{ countryName(picked) || picked }}</h2>
          <button type="button" class="wr-btn small" @click="picked = null"><Icon name="close" />{{ t('war.close') }}</button></div>
        <dl class="wr-dl">
          <div><dt>{{ t('war.k.events') }}</dt><dd>{{ fmtNum(pickedRow.events) }}</dd></div>
          <div><dt>{{ t('war.k.blocked') }}</dt><dd class="b">{{ fmtNum(pickedRow.blocked) }}</dd></div>
          <div><dt>{{ t('war.k.logged') }}</dt><dd class="l">{{ fmtNum(pickedRow.logged) }}</dd></div>
          <div><dt>{{ t('war.k.sources') }}</dt><dd>{{ fmtNum(pickedRow.sources) }}</dd></div>
        </dl>
        <h3>{{ t('war.recent_from') }}</h3>
        <ul class="wr-events">
          <li v-for="e in latestOf(picked)" :key="e.id"><a :href="'/events/' + e.id" target="_blank" rel="noopener">
            <span class="mono">{{ fmtClock(e.ts) }}</span><span class="mono wr-host">{{ e.host }}</span>
            <span class="wr-oc" :class="e.outcome === 'blocked' ? 'b' : 'l'">{{ e.outcome === 'blocked' ? t('war.k.blocked') : t('war.k.logged') }}</span></a></li>
        </ul>
        <a class="wr-btn" :href="eventsLink(picked)" target="_blank" rel="noopener"><Icon name="list" />{{ t('war.open_events') }}</a>
        <p class="wr-note">{{ t('war.geo_disclaimer') }}</p>
      </aside>
    </template>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { api } from '../api.js'
import { t, lang } from '../i18n.js'
import { countryName as cn, fmtNum } from '../util.js'
import Icon from '../components/Icon.vue'
import WarAtlas from '../components/warroom/WarAtlas.vue'
import WarGlobe from '../components/warroom/WarGlobe.vue'

const PAGES = ['atlas', 'globe']
const POLL = 5000
const RESYNC = 60000
const DECIDED = { confident: 'war.d.confident', crs_score: 'war.d.crs', country: 'war.d.country' }

const page = ref(0)
const rotating = ref(false)
const paused = ref(false)
const frozen = ref(false)
const spin = ref(true)
const picked = ref(null)
const expired = ref(false)
const offline = ref(false)
const syncing = ref(false)
const snap = ref(null)
const extra = ref([])          // events since the snapshot (newest first)
const batches = ref([])
const nowMs = ref(Date.now())
const asOfMs = ref(Date.now())
const reduced = ref(window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)').matches : false)
let hw = 0
let timer = null, resyncTimer = null, clockTimer = null, rotateTimer = null

const countryName = (cc) => (cc && cc.length === 2 ? cn(cc, lang.value) : '')
const dest = computed(() => (snap.value && snap.value.destination) || null)
const nodeId = computed(() => (snap.value && snap.value.node_id) || '')

// the snapshot's numbers plus the events that arrived since (the next snapshot replaces both)
const countries = computed(() => {
  const by = {}
  for (const c of (snap.value && snap.value.countries) || []) by[c.cc] = { ...c }
  for (const e of extra.value) {
    if (e.cc === 'LAN' || e.cc === '?') continue
    const c = by[e.cc] || (by[e.cc] = { cc: e.cc, events: 0, blocked: 0, logged: 0, sources: 1 })
    c.events++
    c[e.outcome === 'blocked' ? 'blocked' : 'logged']++
  }
  return Object.values(by).sort((a, b) => b.events - a.events || a.cc.localeCompare(b.cc))
})
const totals = computed(() => {
  const s = { events: 0, blocked: 0, logged: 0, internal: 0, unlocated: 0, ...((snap.value && snap.value.totals) || {}) }
  for (const e of extra.value) {
    s.events++
    s[e.outcome === 'blocked' ? 'blocked' : 'logged']++
    if (e.cc === 'LAN') s.internal++
    else if (e.cc === '?') s.unlocated++
  }
  return s
})
const minutes = computed(() => {
  const ms = ((snap.value && snap.value.minutes) || []).map((m) => ({ ...m }))
  if (!ms.length) return ms
  const t0 = Date.parse(ms[0].t)
  for (const e of extra.value) {
    const i = Math.floor((Date.parse(e.ts) - t0) / 60000)
    if (i >= 0 && i < ms.length) ms[i][e.outcome === 'blocked' ? 'blocked' : 'logged']++
  }
  return ms
})
const peak = computed(() => Math.max(0, ...minutes.value.map((m) => m.blocked + m.logged)))
const latest = computed(() => extra.value.concat((snap.value && snap.value.latest) || [])
  .slice().sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts) || b.id - a.id).slice(0, 30))
const pickedRow = computed(() => countries.value.find((c) => c.cc === picked.value) || null)
function latestOf(cc) { return latest.value.filter((e) => e.cc === cc).slice(0, 6) }
function pct(n) { const m = countries.value.length ? countries.value[0].events : 1; return (100 * n / Math.max(1, m)).toFixed(1) + '%' }
function h(n) { return (100 * n / Math.max(1, peak.value)).toFixed(1) + '%' }

// the four states the wall must tell apart, plus "live"
const state = computed(() => {
  if (offline.value) return 'offline'
  if (syncing.value) return 'syncing'
  const c = snap.value && snap.value.collector
  if (c && c.stopped) return 'stopped'
  const last = latest.value.length ? Date.parse(latest.value[0].ts) : 0
  return !last || nowMs.value - last > 5 * 60000 ? 'quiet' : 'live'
})
const stateHint = computed(() => t('war.state_hint.' + state.value))
const clock = computed(() => new Date(nowMs.value).toLocaleTimeString(lang.value, { hour12: false }))
const tz = computed(() => { const o = -new Date().getTimezoneOffset() / 60; return 'UTC' + (o >= 0 ? '+' : '') + o })
const asOf = computed(() => new Date(asOfMs.value).toLocaleTimeString(lang.value, { hour12: false }))
function fmtClock(iso) { return new Date(iso).toLocaleTimeString(lang.value, { hour12: false }) }
function fmtTimeShort(iso) { return new Date(iso).toLocaleTimeString(lang.value, { hour: '2-digit', minute: '2-digit', hour12: false }) }
function describe(s) { return (countryName(s.cc) || s.cc) + ': ' + t('war.describe', { n: fmtNum(s.events), b: fmtNum(s.blocked), l: fmtNum(s.logged), s: fmtNum(s.sources) }) }
function eventsLink(cc) {
  const since = snap.value ? snap.value.window_start : ''
  return '/events?country=' + encodeURIComponent(cc) + (since ? '&since=' + encodeURIComponent(since) : '')
}

async function get(path, params) {
  try {
    const r = await api('GET', path, { params, quiet401: true })
    offline.value = false
    return r
  } catch (e) {
    if (e && e.status === 401) { expired.value = true; snap.value = null; extra.value = []; stopAll(); return null }
    offline.value = true
    return null
  }
}
async function loadSnapshot() {
  syncing.value = !!snap.value || offline.value
  const s = await get('/warroom/snapshot')
  syncing.value = false
  if (!s) return
  snap.value = s
  extra.value = extra.value.filter((e) => e.id > s.high_water_id)
  hw = Math.max(hw, s.high_water_id)
  asOfMs.value = Date.now()
}
async function poll() {
  if (frozen.value || expired.value || document.hidden) return
  const r = await get('/warroom/events', { after: hw })
  if (!r) return
  asOfMs.value = Date.now()
  if (r.collector && snap.value) snap.value = { ...snap.value, collector: r.collector }
  if (!r.events.length) return
  hw = r.high_water_id
  extra.value = r.events.slice().reverse().concat(extra.value).slice(0, 2000)
  // one tracer per country and outcome of this poll (×n when more), only for outside sources with a country
  const groups = {}
  for (const e of r.events) {
    if (e.cc === 'LAN' || e.cc === '?') continue
    const k = e.cc + '|' + e.outcome
    groups[k] = groups[k] || { id: hw + ':' + k, cc: e.cc, outcome: e.outcome === 'blocked' ? 'blocked' : 'logged', count: 0, t: e.ts }
    groups[k].count++
  }
  batches.value = Object.values(groups)
  if (r.more) { syncing.value = true; await loadSnapshot() }   // too far behind: the snapshot catches up
}
function stopAll() { clearInterval(timer); clearInterval(resyncTimer); clearInterval(rotateTimer) }
function startAll() {
  stopAll()
  timer = setInterval(poll, POLL)
  resyncTimer = setInterval(loadSnapshot, RESYNC)
  setRotation()
}
function setRotation() {
  clearInterval(rotateTimer)
  if (rotating.value) rotateTimer = setInterval(() => go((page.value + 1) % PAGES.length), ((snap.value && snap.value.rotate_seconds) || 25) * 1000)
}
watch(rotating, setRotation)
async function toggleFreeze() {
  frozen.value = !frozen.value
  if (!frozen.value) {
    // the events that piled up meanwhile go into the numbers, never into a burst of tracers
    await loadSnapshot()
    extra.value = []
    batches.value = []
  }
}
function go(i) { page.value = i; batches.value = [] }
function pick(cc) { picked.value = picked.value === cc ? null : cc }
function fullscreen() {
  const el = document.documentElement
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {})
  else if (el.requestFullscreen) el.requestFullscreen().catch(() => {})
}
function onKey(e) {
  if (e.target && /^(INPUT|SELECT|TEXTAREA)$/.test(e.target.tagName)) return
  if (e.key === 'ArrowRight') go((page.value + 1) % PAGES.length)
  else if (e.key === 'ArrowLeft') go((page.value + PAGES.length - 1) % PAGES.length)
  else if (e.key === 'Escape') picked.value = null
  else if (e.key === ' ' && !(e.target && e.target.tagName === 'BUTTON')) { e.preventDefault(); paused.value = !paused.value }
}
function onVisible() { if (!document.hidden) loadSnapshot() }

onMounted(async () => {
  document.title = t('war.title') + ' · jt-waf-mgr'
  document.documentElement.classList.add('wr-page')
  window.addEventListener('keydown', onKey)
  document.addEventListener('visibilitychange', onVisible)
  clockTimer = setInterval(() => { nowMs.value = Date.now() }, 1000)
  await loadSnapshot()
  startAll()
})
onBeforeUnmount(() => {
  stopAll()
  clearInterval(clockTimer)
  window.removeEventListener('keydown', onKey)
  document.removeEventListener('visibilitychange', onVisible)
  document.documentElement.classList.remove('wr-page')
})
</script>

<style scoped>
.wr { position: fixed; inset: 0; overflow: auto; z-index: 50; display: flex; flex-direction: column; gap: 14px; padding: 18px 28px 14px;
  background: radial-gradient(1200px 700px at 30% 20%, #10302f, #071216 70%); color: #e8f1ec; font-size: 15px;
  --b: #ff9974; --l: #77ebd0; --line: #24474a; --card: rgba(9, 29, 33, .78); --muted: #93b1aa; }
.mono { font-family: var(--mono, ui-monospace, monospace); }
.wr-top { display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; padding-bottom: 12px; border-bottom: 1px solid var(--line); }
.wr-brand { display: flex; align-items: center; gap: 10px; font-size: 15px; color: var(--muted); }
.wr-brand b { color: #f4f8f4; font-family: var(--mono, monospace); font-size: 17px; }
.wr-sep { width: 1px; height: 18px; background: var(--line); }
.wr-ctl { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.wr-clock { font-size: 18px; color: #f4f8f4; }
.wr-tz { font-size: 11px; color: var(--muted); }
.wr-btn { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; border: 1px solid #3a6463; border-radius: 6px; background: rgba(12, 40, 42, .8);
  color: #e8f1ec; font: inherit; font-size: 14px; cursor: pointer; text-decoration: none; }
.wr-btn:hover { border-color: var(--l); }
.wr-btn.on { border-color: var(--l); color: var(--l); }
.wr-btn.small { padding: 3px 9px; font-size: 13px; }
.wr-btn .icon { width: 16px; height: 16px; }
.wr-card-h h2 .icon { width: 18px; height: 18px; color: var(--l); }
.wr-btn:focus-visible, .wr-tabs button:focus-visible, .wr-ranklist button:focus-visible { outline: 2px solid #f3c778; outline-offset: 2px; }
.wr-state { display: inline-flex; align-items: center; gap: 6px; padding: 3px 10px; border-radius: 6px; font-size: 13px; border: 1px solid #3a6463; }
.wr-dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; background: var(--l); margin-right: 6px; vertical-align: 0; }
.st-live .wr-dot, .wr-dot.st-live { background: var(--l); box-shadow: 0 0 8px var(--l); }
.st-quiet .wr-dot, .wr-dot.st-quiet { background: #6f9b92; }
.st-stopped, .st-offline { border-color: #c98a4a; color: #ffd39a; }
.st-stopped .wr-dot, .st-offline .wr-dot, .wr-dot.st-stopped, .wr-dot.st-offline { background: #ff9d4d; }
.st-syncing .wr-dot, .wr-dot.st-syncing { background: #f3c778; }
.wr-tabs { display: flex; gap: 22px; border-bottom: 1px solid var(--line); flex-wrap: wrap; }
.wr-tabs button { background: none; border: none; color: #b9cfc9; font: inherit; font-size: 16px; font-weight: 600; padding: 4px 0 10px; cursor: pointer; border-bottom: 2px solid transparent; }
.wr-tabs button.on { color: var(--l); border-bottom-color: var(--l); }
.wr-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 20px; flex-wrap: wrap; }
.wr-eyebrow { font-size: 11px; letter-spacing: .22em; color: var(--l); font-weight: 700; }
.wr-head h1 { margin: 4px 0 0; font-size: clamp(30px, 4vw, 52px); line-height: 1.1; color: #f6f1e6; }
.wr-asof { color: #ffd39a; font-size: 13px; margin-top: 4px; }
.wr-kpis { display: flex; gap: clamp(18px, 4vw, 60px); }
.wr-kpis div { display: flex; flex-direction: column; }
.wr-kpis span { color: var(--muted); font-size: 13px; }
.wr-kpis b { font-family: var(--mono, monospace); font-weight: 500; font-size: clamp(28px, 3.4vw, 44px); line-height: 1.1; color: #f6f1e6; }
.wr-kpis .k-blocked b { color: var(--b); }
.wr-kpis .k-logged b { color: var(--l); }
.wr-grid { display: grid; grid-template-columns: minmax(0, 2.4fr) minmax(280px, 1fr); grid-template-rows: minmax(340px, 1fr) auto; gap: 14px; flex: 1 0 auto; }
.wr-pulse { grid-column: 1; }
.wr-latest { grid-column: 2; }
@media (max-width: 1100px) { .wr-grid { grid-template-columns: minmax(0, 1fr); } .wr-pulse, .wr-latest { grid-column: 1; } }
.wr-card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 14px 18px; display: flex; flex-direction: column; gap: 10px; min-width: 0; }
.wr-card-h { display: flex; align-items: baseline; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
.wr-card-h h2 { margin: 0; font-size: 18px; color: #f6f1e6; display: flex; align-items: center; gap: 8px; }
.wr-sub { color: var(--muted); font-size: 13px; }
.wr-mapbox { position: relative; flex: 1; min-height: 340px; }
.wr-mapbox > * { position: absolute; inset: 0; width: 100%; height: 100%; }
.wr-card-f { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
.wr-legend { display: inline-flex; align-items: center; gap: 6px; color: #d6e4df; font-size: 13px; }
.wr-legend i { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-left: 6px; }
.wr-legend .lg-b { background: var(--b); margin-left: 0; }
.wr-legend .lg-l { background: var(--l); }
.wr-ranklist { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }
.wr-ranklist button { width: 100%; display: grid; grid-template-columns: 36px minmax(0, 1fr) auto; grid-template-rows: auto 5px; gap: 2px 10px; align-items: center;
  background: none; border: 1px solid transparent; border-radius: 6px; padding: 4px 6px; color: inherit; font: inherit; text-align: left; cursor: pointer; }
.wr-ranklist button:hover, .wr-ranklist button.on { border-color: #3a6463; background: rgba(20, 60, 60, .35); }
.wr-cc { display: inline-flex; justify-content: center; min-width: 30px; padding: 1px 4px; border: 1px solid #3a6463; border-radius: 4px; font-size: 12px; color: var(--l); }
.wr-ranklist .wr-cc { grid-row: 1 / span 2; }
.wr-cn { font-size: 15px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.wr-cn small { color: var(--muted); font-size: 12px; margin-left: 8px; }
.wr-n { font-size: 17px; text-align: right; }
.wr-bar { grid-column: 2 / span 2; display: flex; height: 4px; border-radius: 2px; background: #1a3a3b; overflow: hidden; }
.wr-bar i { display: block; height: 100%; }
.wr-bar .b, .wr-col .b { background: var(--b); }
.wr-bar .l, .wr-col .l { background: var(--l); }
.wr-foot { margin: 6px 0 0; padding-top: 8px; border-top: 1px solid var(--line); color: var(--muted); font-size: 13px; }
.wr-empty { color: var(--muted); margin: 8px 0; }
.wr-bars { display: flex; align-items: flex-end; gap: 3px; height: 92px; border-bottom: 1px solid var(--line); }
.wr-col { flex: 1; display: flex; flex-direction: column-reverse; height: 100%; min-width: 2px; }
.wr-col i { display: block; width: 100%; }
.wr-col .b { border-radius: 2px 2px 0 0; }
.wr-axis { display: flex; justify-content: space-between; color: var(--muted); font-size: 11px; }
.wr-events { list-style: none; margin: 0; padding: 0; }
.wr-events li + li { border-top: 1px solid #1d3d3f; }
.wr-events a { display: grid; grid-template-columns: auto 38px minmax(0, 1fr) auto; gap: 12px; align-items: center; padding: 6px 2px; color: #e8f1ec; text-decoration: none; font-size: 14px; }
.wr-drawer .wr-events a { grid-template-columns: auto minmax(0, 1fr) auto; }
.wr-events a:hover .wr-host { text-decoration: underline; }
.wr-cc2 { color: #b9cfc9; }
.wr-host { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.wr-oc { font-size: 13px; white-space: nowrap; }
.wr-oc.b { color: var(--b); }
.wr-oc.l { color: var(--l); }
.wr-bottom { display: flex; justify-content: space-between; gap: 12px; color: var(--muted); font-size: 12.5px; flex-wrap: wrap; }
.wr-drawer { position: fixed; top: 0; right: 0; bottom: 0; width: min(420px, 100vw); z-index: 60; background: #0a1d21; border-left: 1px solid #3a6463;
  padding: 18px; display: flex; flex-direction: column; gap: 12px; overflow: auto; box-shadow: -12px 0 30px rgba(0, 0, 0, .4); }
.wr-drawer h3 { margin: 6px 0 0; font-size: 14px; color: var(--muted); }
.wr-dl { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin: 0; }
.wr-dl div { border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; }
.wr-dl dt { color: var(--muted); font-size: 12.5px; }
.wr-dl dd { margin: 0; font-family: var(--mono, monospace); font-size: 24px; }
.wr-dl dd.b { color: var(--b); }
.wr-dl dd.l { color: var(--l); }
.wr-note { color: var(--muted); font-size: 12.5px; margin: 0; }
.wr-msg { margin: 15vh auto; text-align: center; display: flex; flex-direction: column; gap: 14px; align-items: center; font-size: 18px; }
</style>
