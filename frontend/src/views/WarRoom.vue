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
          <div class="wr-eyebrow">{{ EYEBROW[PAGES[page]] }}</div>
          <h1>{{ t('war.page.' + PAGES[page]) }}</h1>
          <div v-if="frozen || state === 'offline'" class="wr-asof">{{ t('war.as_of', { time: asOf }) }}</div>
        </div>
        <div class="wr-kpis">
          <div v-for="k in kpis" :key="k.key" :class="k.cls"><span>{{ k.label }}</span><b>{{ k.value }}</b></div>
        </div>
      </section>

      <div v-if="PAGES[page] === 'intel'" class="wr-two">
        <section class="wr-card">
          <div class="wr-card-h"><h2><Icon name="timer" />{{ t('war.analysis_title') }}</h2><span class="wr-sub">{{ t('war.analysis_l1') }}</span></div>
          <template v-if="ops && ops.analysis.latest">
            <div class="wr-eyebrow">RUN #{{ ops.analysis.latest.id }} · {{ fmtTimeShort(ops.analysis.latest.started_at) }}</div>
            <div class="wr-big">{{ fmtNum(ops.analysis.latest.events_scanned ?? ops.analysis.latest.candidates) }}<small>{{ ops.analysis.latest.events_scanned != null ? t('war.events_unit') : t('war.candidates_unit') }}</small></div>
            <p class="wr-sub">{{ t('war.analysis_d', { n: fmtNum(ops.analysis.latest.candidates) }) }}</p>
            <div class="wr-vbar" aria-hidden="true"><i v-for="v in verdictParts" :key="v.key" :class="'v-' + v.key" :style="{ flex: v.n }"></i></div>
            <p class="wr-vlegend"><span v-for="v in verdictParts" :key="v.key">{{ tOr('analysis.verdict.' + v.key, v.key) }} {{ v.n }}</span></p>
            <a class="wr-clue" href="/analysis" target="_blank" rel="noopener"><span class="wr-tag l">{{ t('war.run_facts', { s: Math.round(ops.analysis.latest.seconds || 0), p: ops.analysis.latest.proposals }) }}</span><b>{{ t('war.run_log') }}</b><Icon name="external" /></a>
          </template>
          <p v-else class="wr-empty">{{ ops && !ops.analysis.enabled ? t('war.analysis_off') : t('war.analysis_none') }}</p>
          <p class="wr-foot">{{ t('war.analysis_day', { n: ops ? ops.analysis.runs_24h : 0, e: ops ? ops.analysis.errors_24h : 0 }) }}</p>
        </section>
        <section class="wr-card">
          <div class="wr-card-h"><h2><Icon name="ai" />{{ t('war.intel_title') }}</h2><span class="wr-sub">{{ t('war.intel_l2') }}</span></div>
          <template v-if="ops && ops.intel.enabled">
            <div class="wr-note-card" :class="{ warn: ops.intel.exploited }"><b>{{ ops.intel.exploited ? t('war.intel_exploited', { n: ops.intel.exploited }) : t('war.intel_open', { n: ops.intel.open }) }}</b>
              <p>{{ t('war.intel_counts', { a: ops.intel.affected, u: ops.intel.unknown, p: ops.intel.patched_by_rule }) }}</p></div>
            <ul class="wr-revlist">
              <li v-for="x in ops.intel.top" :key="x.id + x.product"><a href="/intel" target="_blank" rel="noopener">
                <span class="wr-tag" :class="{ b: x.exploited }">{{ x.exploited ? t('war.exploited') : tOr('intel.affected.' + x.affected, x.affected) }}</span>
                <span class="mono">{{ x.id }}</span><span>{{ x.product }}</span><Icon name="external" /></a></li>
            </ul>
            <a class="wr-clue" href="/intel" target="_blank" rel="noopener"><span class="wr-tag l">{{ t('war.sw_pending', { n: ops.intel.software_unconfirmed }) }}</span><b>{{ t('war.check_software') }}</b><Icon name="external" /></a>
            <p class="wr-foot">{{ ops.intel.last_run_at ? t('war.intel_last', { time: fmtTimeShort(ops.intel.last_run_at) }) : t('war.analysis_none') }}</p>
          </template>
          <p v-else class="wr-empty">{{ t('war.intel_off') }}</p>
        </section>
      </div>

      <div v-else-if="PAGES[page] === 'ops'" class="wr-ops">
        <section v-for="col in opsCols" :key="col.key" class="wr-card wr-opcol" :class="'oc-' + col.key">
          <div class="wr-card-h"><h2><Icon :name="col.icon" />{{ col.label }}</h2><span class="wr-sub mono">{{ col.items.length }}</span></div>
          <i class="wr-opbar" aria-hidden="true"></i>
          <a v-for="it in col.items.slice(0, 6)" :key="it.key" class="wr-opcard" :href="it.href" target="_blank" rel="noopener">
            <span class="mono">{{ it.title }}</span><b>{{ it.what }}</b><small>{{ it.when }}</small></a>
          <p v-if="col.items.length > 6" class="wr-sub">{{ t('war.more_n', { n: col.items.length - 6 }) }}</p>
          <p v-if="!col.items.length" class="wr-empty">{{ t('war.none') }}</p>
        </section>
        <section class="wr-card wr-opsnote">
          <div class="wr-card-h"><h2><Icon name="lock" />{{ t('war.ops_rights') }}</h2><span class="wr-sub">{{ t('war.read_only') }}</span></div>
          <p class="wr-sub">{{ t('war.ops_rights_d') }}</p>
        </section>
      </div>

      <div v-else class="wr-grid">
        <section v-if="PAGES[page] === 'flow'" class="wr-card wr-map">
          <div class="wr-card-h"><h2><Icon name="change" />{{ t('war.flow_title') }}</h2><span class="wr-sub">{{ t('war.flow_unit') }}</span></div>
          <div class="wr-mapbox"><WarFlow :flow="flow" :labels="flowLabels" :columns="[t('war.col.source'), t('war.col.decision'), t('war.col.outcome')]"
                                          :label="t('war.flow_title')" @pick="pickFlow" /></div>
        </section>
        <section v-else-if="PAGES[page] === 'sites'" class="wr-card wr-map">
          <div class="wr-card-h"><h2><Icon name="server" />{{ t('war.sites_title') }}</h2><span class="wr-sub">{{ t('war.sites_unit') }}</span></div>
          <div class="wr-sitehead"><span>{{ t('war.col.site') }}</span><span>{{ t('war.col.density') }}</span><span>{{ t('war.k.events') }}</span><span>{{ t('war.k.blocked') }}</span><span>{{ t('war.k.logged') }}</span></div>
          <ul class="wr-sites">
            <li v-for="st in siteRows" :key="st.host"><a :href="siteLink(st.host)" target="_blank" rel="noopener">
              <span class="mono wr-host">{{ st.host }}</span>
              <span class="wr-cells" aria-hidden="true"><i v-for="(n, i) in st.buckets" :key="i" :style="{ opacity: cell(n) }"></i></span>
              <span class="mono">{{ fmtNum(st.events) }}</span><span class="mono b">{{ fmtNum(st.blocked) }}</span><span class="mono l">{{ fmtNum(st.logged) }}</span></a></li>
          </ul>
          <p v-if="!siteRows.length" class="wr-empty">{{ t('war.quiet') }}</p>
        </section>
        <section v-else-if="PAGES[page] === 'review'" class="wr-card wr-map">
          <div class="wr-card-h"><h2><Icon name="block" />{{ t('war.review_title') }}</h2><span class="wr-sub">{{ t('war.by_site') }}</span></div>
          <p class="wr-sub">{{ t('war.review_unit') }}</p>
          <div class="wr-big score">{{ fmtNum(scoreOnlyTotal) }}</div>
          <ul class="wr-revlist">
            <li v-for="g in scoreOnly.slice(0, 6)" :key="g.host"><a :href="scoreLink(g.host)" target="_blank" rel="noopener">
              <span class="wr-tag">{{ t('war.d.crs') }} · {{ fmtNum(g.events) }}</span><span class="mono wr-host">{{ g.host }}</span><Icon name="external" /></a></li>
          </ul>
          <p v-if="!scoreOnly.length" class="wr-empty">{{ t('war.no_score_only') }}</p>
        </section>
        <section v-else class="wr-card wr-map">
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

        <section v-if="PAGES[page] === 'flow'" class="wr-card wr-rank">
          <div class="wr-card-h"><h2><Icon name="list" />{{ t('war.basis') }}</h2><span class="wr-sub">{{ t('war.click_event') }}</span></div>
          <ul class="wr-basis">
            <li v-for="d in decisionRows" :key="d.key"><a :href="decisionLink(d.key)" target="_blank" rel="noopener">
              <span :class="'d-' + d.key">{{ flowLabels[d.key] }}</span><span class="mono">{{ fmtNum(d.n) }}</span></a></li>
          </ul>
        </section>
        <section v-else-if="PAGES[page] === 'sites'" class="wr-card wr-rank">
          <div class="wr-card-h"><h2><Icon name="info" />{{ t('war.site_notes') }}</h2></div>
          <div class="wr-note-card"><b>{{ t('war.note.concentrated') }}</b><p>{{ topSite ? t('war.note.concentrated_d', { site: topSite.host, p: topShare }) : t('war.quiet') }}</p></div>
          <div class="wr-note-card warn"><b>{{ t('war.note.no_events') }}</b><p>{{ watchedQuiet.length ? t('war.note.no_events_d', { sites: watchedQuiet.join(', ') }) : t('war.note.all_have') }}</p></div>
          <p class="wr-foot">{{ t('war.note.requests') }}</p>
        </section>
        <section v-else-if="PAGES[page] === 'review'" class="wr-card wr-rank">
          <div class="wr-card-h"><h2><Icon name="search" />{{ t('war.clues') }}</h2><span class="wr-sub">{{ t('war.click_event') }}</span></div>
          <div class="wr-note-card"><b>{{ t('war.clue.internal') }}</b><p>{{ t('war.clue.internal_d') }}</p></div>
          <a class="wr-clue" :href="eventsQuery({ origin: 'internal', outcome: 'logged' })" target="_blank" rel="noopener">
            <span class="wr-tag l">{{ t('war.lan') }} · {{ fmtNum(flow.internal ? flow.internal.logged || 0 : 0) }}</span><b>{{ t('war.clue.see_internal') }}</b><Icon name="external" /></a>
          <a class="wr-clue" :href="eventsQuery({ origin: 'external', outcome: 'logged' })" target="_blank" rel="noopener">
            <span class="wr-tag l">{{ t('war.outside') }} · {{ fmtNum(flow.external ? flow.external.logged || 0 : 0) }}</span><b>{{ t('war.clue.see_external') }}</b><Icon name="external" /></a>
          <p class="wr-foot">{{ t('war.clue.note') }}</p>
        </section>
        <section v-else class="wr-card wr-rank">
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
import { t, tOr, lang } from '../i18n.js'
import { countryName as cn, fmtNum } from '../util.js'
import Icon from '../components/Icon.vue'
import WarAtlas from '../components/warroom/WarAtlas.vue'
import WarGlobe from '../components/warroom/WarGlobe.vue'
import WarFlow from '../components/warroom/WarFlow.vue'

const PAGES = ['atlas', 'globe', 'flow', 'sites', 'review', 'intel', 'ops']
const EYEBROW = { atlas: 'GLOBAL EVENT ATLAS', globe: 'ORBITAL DEFENSE', flow: 'DECISION FLOW', sites: 'SITE ACTIVITY', review: 'REVIEW DESK',
  intel: 'INTELLIGENCE BRIEF', ops: 'OPERATIONS QUEUE' }
const POLL = 5000
const RESYNC = 60000
const DECIDED = { confident: 'war.d.confident', fallback: 'war.d.fallback', score: 'war.d.crs' }

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
// --- decision flow, sites, review: the snapshot's numbers plus the events since ---------------------------------
function decisionOf(e) {
  if (e.outcome !== 'blocked') return 'logged'
  return ['confident', 'fallback', 'score'].includes(e.decided_by) ? e.decided_by : 'other'
}
const flow = computed(() => {
  const f = JSON.parse(JSON.stringify((snap.value && snap.value.flow) || {}))
  for (const e of extra.value) {
    const o = e.origin === 'internal' ? 'internal' : 'external'
    const d = decisionOf(e)
    f[o] = f[o] || {}
    f[o][d] = (f[o][d] || 0) + 1
  }
  return f
})
const flowLabels = computed(() => ({ external: t('war.outside'), internal: t('war.lan'), confident: t('war.d.confident'), score: t('war.d.crs'),
  fallback: t('war.d.fallback'), other: t('war.d.other'), logged: t('war.k.logged'), blocked: t('war.k.blocked') }))
const decisionRows = computed(() => ['confident', 'fallback', 'score', 'other', 'logged']
  .map((k) => ({ key: k, n: (flow.value.external?.[k] || 0) + (flow.value.internal?.[k] || 0) })).filter((d) => d.n > 0))
const siteRows = computed(() => {
  const by = {}
  for (const x of (snap.value && snap.value.sites) || []) by[x.host] = { ...x, buckets: x.buckets.slice() }
  const since = snap.value ? Date.parse(snap.value.window_start) : 0
  for (const e of extra.value) {
    const x = by[e.host] || (by[e.host] = { host: e.host, events: 0, blocked: 0, logged: 0, buckets: new Array(15).fill(0) })
    x.events++
    x[e.outcome === 'blocked' ? 'blocked' : 'logged']++
    const i = Math.min(14, Math.max(0, Math.floor((Date.parse(e.ts) - since) / 120000)))
    x.buckets[i]++
  }
  const rows = Object.values(by).sort((a, b) => b.events - a.events || a.host.localeCompare(b.host)).slice(0, 12)
  for (const h of (snap.value && snap.value.watched) || []) if (!by[h]) rows.push({ host: h, events: 0, blocked: 0, logged: 0, buckets: new Array(15).fill(0) })
  return rows
})
const cellMax = computed(() => Math.max(1, ...siteRows.value.flatMap((r) => r.buckets)))
function cell(n) { return n ? (0.25 + 0.75 * n / cellMax.value).toFixed(2) : '0.08' }
const topSite = computed(() => siteRows.value.find((r) => r.events > 0) || null)
const topShare = computed(() => (topSite.value && totals.value.events ? Math.round(100 * topSite.value.events / totals.value.events) : 0) + '%')
const watchedQuiet = computed(() => siteRows.value.filter((r) => !r.events).map((r) => r.host))
const scoreOnly = computed(() => {
  const by = {}
  for (const g of (snap.value && snap.value.score_only) || []) by[g.host] = g.events
  for (const e of extra.value) if (decisionOf(e) === 'score') by[e.host] = (by[e.host] || 0) + 1
  return Object.entries(by).map(([host, events]) => ({ host, events })).sort((a, b) => b.events - a.events)
})
const scoreOnlyTotal = computed(() => scoreOnly.value.reduce((a, g) => a + g.events, 0))
const kpis = computed(() => {
  const p = PAGES[page.value]
  const T = totals.value
  if (p === 'flow') return [{ key: 'e', label: t('war.k.audit_events'), value: fmtNum(T.events) },
    { key: 'p', cls: 'k-blocked', label: t('war.k.blocked_share'), value: (T.events ? Math.round(100 * T.blocked / T.events) : 0) + '%' }]
  if (p === 'sites') return [{ key: 'a', label: t('war.k.sites_active'), value: fmtNum(siteRows.value.filter((r) => r.events).length) },
    { key: 'o', label: t('war.k.sites_watched'), value: fmtNum(siteRows.value.length) },
    { key: 'z', cls: 'k-logged', label: t('war.k.sites_quiet'), value: fmtNum(watchedQuiet.value.length) }]
  if (p === 'intel') {
    const r = ops.value && ops.value.analysis.latest
    return [{ key: 'c', label: t('war.k.candidates'), value: r ? fmtNum(r.candidates) : '—' },
      { key: 'i', cls: 'k-score', label: t('war.k.no_answer'), value: r ? fmtNum((r.verdicts || {}).invalid || 0) : '—' },
      { key: 'p', cls: 'k-logged', label: t('war.k.proposals'), value: r ? fmtNum(r.proposals) : '—' }]
  }
  if (p === 'ops') {
    const o = ops.value
    return [{ key: 'a', cls: 'k-score', label: t('war.k.alerts_open'), value: o ? fmtNum(o.alerts.length) : '—' },
      { key: 'c', label: t('war.k.changes_moving'), value: o ? fmtNum(o.changes.checking.length + o.changes.pending.length) : '—' },
      { key: 'd', cls: 'k-logged', label: t('war.k.applied_24h'), value: o ? fmtNum(o.changes.applied.length) : '—' }]
  }
  if (p === 'review') return [{ key: 's', cls: 'k-score', label: t('war.k.score_only'), value: fmtNum(scoreOnlyTotal.value) },
    { key: 'i', cls: 'k-logged', label: t('war.k.internal_logged'), value: fmtNum(flow.value.internal?.logged || 0) }]
  return [{ key: 'e', label: t('war.k.events'), value: fmtNum(T.events) }, { key: 'b', cls: 'k-blocked', label: t('war.k.blocked'), value: fmtNum(T.blocked) },
    { key: 'l', cls: 'k-logged', label: t('war.k.logged'), value: fmtNum(T.logged) }, { key: 'c', label: t('war.k.countries'), value: fmtNum(countries.value.length) }]
})
// the work around the WAF (intel / ops pages): every 30 seconds, never more often
const ops = ref(null)
let opsTimer = null
async function loadOps() { if (!frozen.value && !document.hidden) { const r = await get('/warroom/ops'); if (r) ops.value = r } }
const verdictParts = computed(() => Object.entries((ops.value && ops.value.analysis.latest && ops.value.analysis.latest.verdicts) || {})
  .map(([key, n]) => ({ key, n })).filter((v) => v.n > 0))
function ago(iso) { const m = Math.round((nowMs.value - Date.parse(iso)) / 60000); return m < 60 ? t('war.min_ago', { n: Math.max(0, m) }) : t('war.h_ago', { n: Math.round(m / 60) }) }
function chgCard(c) {
  return { key: 'c' + c.id, title: t('war.change_n', { id: c.id }), href: '/changes/' + c.id,
           what: t('op.' + c.op) + (c.kind ? ' · ' + tOr('kind.' + c.kind, c.kind) : '') + ' · ' + tOr('direction.' + c.direction, c.direction), when: ago(c.updated_at) }
}
const opsCols = computed(() => {
  const o = ops.value || { alerts: [], changes: { checking: [], pending: [], applied: [] } }
  return [
    { key: 'alerts', icon: 'bell', label: t('war.col.alerts'), items: o.alerts.map((a) => ({ key: 'a' + a.id, title: t('war.alert_n', { id: a.id }), href: '/alerts',
      what: tOr('alerts.kind.' + a.kind, a.kind), when: ago(a.created_at) })) },
    { key: 'checking', icon: 'test', label: t('war.col.checking'), items: o.changes.checking.map(chgCard) },
    { key: 'pending', icon: 'approve', label: t('war.col.pending'), items: o.changes.pending.map(chgCard) },
    { key: 'applied', icon: 'check', label: t('war.col.applied'), items: o.changes.applied.map(chgCard) },
  ]
})
// drill-down: the event list with the same window, in a new tab (internal-only sites have an alias here: no host filter)
function eventsQuery(q) {
  const since = snap.value ? snap.value.window_start : ''
  const p = new URLSearchParams(Object.assign({}, q, since ? { since } : {}))
  return '/events?' + p.toString()
}
function siteLink(h) { return /^internal-\d+$/.test(h) || h === 'site' ? eventsQuery({ origin: 'internal' }) : eventsQuery({ host: h }) }
function scoreLink(h) { return /^internal-\d+$/.test(h) || h === 'site' ? eventsQuery({ decided_by: 'score' }) : eventsQuery({ host: h, decided_by: 'score' }) }
function decisionLink(d) { return d === 'logged' ? eventsQuery({ outcome: 'logged' }) : eventsQuery(d === 'other' ? { outcome: 'blocked' } : { decided_by: d }) }
function pickFlow(p) {
  const q = {}
  if (p.origin) q.origin = p.origin
  if (p.decision) Object.assign(q, p.decision === 'logged' ? { outcome: 'logged' } : p.decision === 'other' ? { outcome: 'blocked' } : { decided_by: p.decision })
  if (p.outcome) q.outcome = p.outcome
  window.open(eventsQuery(q), '_blank', 'noopener')
}
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
function stopAll() { clearInterval(timer); clearInterval(resyncTimer); clearInterval(rotateTimer); clearInterval(opsTimer) }
function startAll() {
  stopAll()
  timer = setInterval(poll, POLL)
  resyncTimer = setInterval(loadSnapshot, RESYNC)
  opsTimer = setInterval(loadOps, 30000)
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
  loadOps()
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
.wr-kpis .k-score b { color: #f3c778; }
.wr-sitehead, .wr-sites a { display: grid; grid-template-columns: minmax(120px, 1.4fr) minmax(160px, 2fr) 70px 70px 70px; gap: 12px; align-items: center; }
.wr-sitehead { color: var(--muted); font-size: 13px; padding: 0 2px 6px; border-bottom: 1px solid var(--line); }
.wr-sites { list-style: none; margin: 0; padding: 0; }
.wr-sites li + li { border-top: 1px solid #1d3d3f; }
.wr-sites a { padding: 8px 2px; color: #e8f1ec; text-decoration: none; }
.wr-sites a:hover .wr-host { text-decoration: underline; }
.wr-sites .b { color: var(--b); }
.wr-sites .l { color: var(--l); }
.wr-cells { display: grid; grid-template-columns: repeat(15, 1fr); gap: 2px; height: 18px; }
.wr-cells i { display: block; background: var(--l); border-radius: 2px; }
.wr-big { font-family: var(--mono, monospace); font-size: clamp(40px, 5vw, 64px); line-height: 1; }
.wr-big.score { color: #f3c778; }
.wr-revlist { list-style: none; margin: 8px 0 0; padding: 0; }
.wr-revlist li { border-top: 1px solid var(--line); }
.wr-revlist a, .wr-clue { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 12px; padding: 12px 2px; color: #f6efe1; text-decoration: none; font-size: 17px; }
.wr-revlist a .icon, .wr-clue .icon { width: 16px; height: 16px; color: var(--l); }
.wr-tag { display: inline-block; border: 1px solid #f3c778; color: #f3c778; border-radius: 4px; padding: 0 6px; font-size: 12px; font-family: var(--mono, monospace); }
.wr-tag.l { border-color: var(--l); color: var(--l); }
.wr-clue { border-top: 1px solid var(--line); }
.wr-basis { list-style: none; margin: 0; padding: 0; }
.wr-basis li { border-top: 1px solid var(--line); }
.wr-basis a { display: flex; justify-content: space-between; padding: 14px 2px; color: #e8f1ec; text-decoration: none; font-size: 17px; font-weight: 600; }
.d-confident, .d-fallback { color: var(--b); }
.d-score { color: #f3c778; }
.d-other { color: #c99bd8; }
.d-logged { color: var(--l); }
.wr-note-card { border-left: 3px solid var(--l); background: rgba(20, 60, 60, .35); border-radius: 0 6px 6px 0; padding: 10px 14px; }
.wr-note-card.warn { border-left-color: #f3c778; }
.wr-note-card b { display: block; margin-bottom: 4px; color: #f6efe1; }
.wr-note-card p { margin: 0; color: #d6e4df; }
.wr-two { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
@media (max-width: 1000px) { .wr-two { grid-template-columns: minmax(0, 1fr); } }
.wr-big small { font-size: 15px; color: var(--muted); margin-left: 12px; font-family: inherit; }
.wr-vbar { display: flex; gap: 3px; height: 8px; border-radius: 4px; overflow: hidden; }
.wr-vbar i { display: block; background: #8aa29d; }
.wr-vbar .v-attack, .wr-vbar .v-attack_probe { background: var(--b); }
.wr-vbar .v-unsure { background: #f3c778; }
.wr-vbar .v-false_positive, .wr-vbar .v-legitimate { background: var(--l); }
.wr-vlegend { display: flex; flex-wrap: wrap; gap: 4px 14px; color: var(--muted); font-size: 13px; margin: 0; }
.wr-tag.b { border-color: var(--b); color: var(--b); }
.wr-ops { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
@media (max-width: 1100px) { .wr-ops { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 640px) { .wr-ops { grid-template-columns: minmax(0, 1fr); } }
.wr-opsnote { grid-column: 1 / -1; }
.wr-opbar { display: block; height: 6px; border-radius: 3px; background: #f3c778; }
.oc-checking .wr-opbar { background: #8fb3ff; }
.oc-pending .wr-opbar { background: var(--b); }
.oc-applied .wr-opbar { background: var(--l); }
.wr-opcard { display: flex; flex-direction: column; gap: 4px; padding: 12px; border: 1px solid var(--line); border-left: 3px solid #f3c778;
  border-radius: 0 6px 6px 0; background: rgba(20, 60, 60, .3); color: #e8f1ec; text-decoration: none; }
.oc-checking .wr-opcard { border-left-color: #8fb3ff; }
.oc-pending .wr-opcard { border-left-color: var(--b); }
.oc-applied .wr-opcard { border-left-color: var(--l); }
.wr-opcard small { color: var(--muted); }
.wr-opcard:hover b { text-decoration: underline; }
.wr-msg { margin: 15vh auto; text-align: center; display: flex; flex-direction: column; gap: 14px; align-items: center; font-size: 18px; }
</style>
