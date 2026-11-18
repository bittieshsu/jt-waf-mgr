<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('lookup.title') }}</h1>
      <button type="button" class="btn small ghost" :class="{ on: showGuide }" :aria-pressed="showGuide ? 'true' : 'false'" @click="toggleGuide"><Icon name="help" />{{ t('guide.how') }}</button>
    </div>
    <FlowSteps v-if="showGuide" :title="t('guide.ip.title')" :steps="flow" :note="t('guide.ip.note')" />
    <form class="filters inline" @submit.prevent="go">
      <label class="field grow"><span>{{ t('lookup.ip') }}</span><input v-model.trim="input" maxlength="64" placeholder="203.0.113.7" required></label>
      <div class="actions"><button class="btn primary" type="submit"><Icon name="search" />{{ t('lookup.submit') }}</button></div>
    </form>
    <ErrorBox :error="error" />
    <Loading v-if="loading" />
    <template v-if="data">
      <section class="card">
        <h2 class="mono"><Icon name="globe" /> {{ safeText(data.ip, 45) }} <OriginBadge :origin="data.origin" /> <GeoTag :geo="data.geo" full />
          <span v-if="data.blocked_now" class="badge b-blocked">{{ t('lookup.blocked_now') }}</span></h2>
        <p v-if="data.ptr" class="ptrline small"><span class="muted">{{ t('ipcard.ptr') }}</span>
          <span v-if="data.ptr.pending" class="muted gapl">{{ t('ipcard.ptr_pending') }}</span>
          <template v-else-if="data.ptr.name"><span class="mono gapl">{{ safeText(data.ptr.name, 255) }}</span>
            <span class="gapl" :class="data.ptr.confirmed ? 'ok' : 'warn'">{{ data.ptr.confirmed ? t('ipcard.ptr_confirmed') : t('ipcard.ptr_unconfirmed') }}</span></template>
          <span v-else class="muted gapl">{{ data.ptr.error ? t('ipcard.ptr_error') : t('ipcard.ptr_none') }}</span></p>
        <div class="tiles">
          <div class="tile stat t-events"><div class="tl"><Icon name="list" />{{ t('lookup.d7_events') }}</div><div class="tv">{{ fmtNum(data.d7.events) }}</div>
            <div class="ts">{{ t('outcome.blocked') }} {{ fmtNum(data.d7.blocked) }}</div>
            <Sparkline class="stat-spark" :values="spark(7, 'events')" tone="s1" :label="t('lookup.d7_events')" /></div>
          <div class="tile stat t-blocked"><div class="tl"><Icon name="block" />{{ t('lookup.d30_events') }}</div><div class="tv">{{ fmtNum(data.d30.events) }}</div>
            <div class="ts">{{ t('outcome.blocked') }} {{ fmtNum(data.d30.blocked) }}</div>
            <Sparkline class="stat-spark" :values="spark(30, 'blocked')" tone="blocked" :label="t('lookup.d30_events')" /></div>
          <div class="tile stat"><div class="tl"><Icon name="history" />{{ t('lookup.first_seen') }}</div><div class="tv small">{{ data.first_seen ? fmtTime(data.first_seen) : '—' }}</div>
            <div v-if="data.first_seen" class="ts">{{ ago(data.first_seen) }}</div></div>
          <div class="tile stat"><div class="tl"><Icon name="timer" />{{ t('lookup.last_seen') }}</div><div class="tv small">{{ data.last_seen ? fmtTime(data.last_seen) : '—' }}</div>
            <div v-if="data.last_seen" class="ts">{{ ago(data.last_seen) }}</div></div>
        </div>
        <div class="chartgrid">
          <div><h3 class="charthead">{{ t('chart.ip_split', { period: t('lookup.d7_events') }) }}</h3><SegBar :parts="split(data.d7)" :label="t('lookup.d7_events')" /></div>
          <div><h3 class="charthead">{{ t('chart.ip_split', { period: t('lookup.d30_events') }) }}</h3><SegBar :parts="split(data.d30)" :label="t('lookup.d30_events')" /></div>
          <div v-if="mapItems.length"><h3 class="charthead">{{ t('lookup.location') }}</h3>
            <WorldMap :items="mapItems" :series="outcomeSeries" :label="t('lookup.location')" marker /></div>
        </div>
        <EventTimeline v-if="data.d30.events" :query="{ src_ip: data.ip, since: since30 }" :title="t('lookup.timeline')"
                       @select="(r) => router.push({ path: '/events', query: { src_ip: data.ip, since: r.since, until: r.until } })" />
        <div class="actions"><RouterLink class="btn small" :to="{ path: '/events', query: { src_ip: data.ip } }"><Icon name="list" />{{ t('lookup.view_events') }}</RouterLink></div>
      </section>
      <!-- 0.4.94: IP reputation -- the site's own evidence, public lists, InternetDB, the organisation's MISP -->
      <section v-if="rep" class="card iprep" :class="{ attention: rep.verdict === 'malicious' }">
        <h2><Icon name="shield" /> {{ t('iprep.title') }}
          <span class="badge gapl" :class="VERDICT_CLS[rep.verdict]">{{ t('iprep.verdict.' + rep.verdict) }}</span>
          <span v-if="rep.pending" class="muted small gapl" role="status"><Icon name="timer" /> {{ t('iprep.pending') }}</span></h2>
        <p v-if="rep.enabled === false" class="muted small">{{ t('iprep.off') }}
          <RouterLink v-if="isAdmin" class="gapl" to="/admin/settings#uiset-iprep">{{ t('iprep.where_on') }}</RouterLink></p>
        <ul v-if="rep.reasons.length" class="plainlist reasons">
          <li v-for="(r, i) in rep.reasons" :key="i"><span class="badge" :class="LEVEL_CLS[r.level]">{{ t('iprep.level.' + r.level) }}</span>
            <span class="gapl">{{ reasonText(r) }}</span></li>
        </ul>
        <p v-else class="muted small">{{ t('iprep.nothing') }}</p>
        <p class="muted small">{{ t('iprep.note') }}</p>
        <div v-if="rep.online" class="kvgroups">
          <div v-if="rep.online.internetdb" class="kvpanel">
            <h3><Icon name="globe" />Shodan InternetDB</h3>
            <p v-if="rep.online.internetdb.error" class="small warn">{{ safeText(rep.online.internetdb.error, 160) }}</p>
            <p v-else-if="rep.online.internetdb.none" class="muted small">{{ t('iprep.idb_none') }}</p>
            <dl v-else class="kv">
              <dt>{{ t('iprep.ports') }}</dt><dd class="mono">{{ (rep.online.internetdb.ports || []).join(', ') || '—' }}</dd>
              <dt>{{ t('iprep.tags') }}</dt><dd><span v-for="x in rep.online.internetdb.tags" :key="x" class="chip tag">{{ safeText(x, 40) }}</span><span v-if="!(rep.online.internetdb.tags || []).length" class="muted">—</span></dd>
              <dt>{{ t('iprep.vulns') }}</dt><dd class="mono small">{{ rep.online.internetdb.vulns_total ? fmtNum(rep.online.internetdb.vulns_total) + ' · ' + rep.online.internetdb.vulns.slice(0, 8).join(', ') : '—' }}</dd>
              <dt>{{ t('iprep.hostnames') }}</dt><dd class="mono small">{{ (rep.online.internetdb.hostnames || []).map((h) => safeText(h, 120)).join(', ') || '—' }}</dd>
            </dl>
          </div>
          <div v-if="rep.online.misp" class="kvpanel">
            <h3><Icon name="database" />MISP</h3>
            <p v-if="rep.online.misp.error" class="small warn">{{ safeText(rep.online.misp.error, 160) }}</p>
            <p v-else-if="!rep.online.misp.count" class="muted small">{{ t('iprep.misp_none') }}</p>
            <template v-else>
              <p class="small">{{ t('iprep.misp_count', { n: rep.online.misp.count, events: rep.online.misp.events.length }) }}</p>
              <ul class="plainlist small">
                <li v-for="e in rep.online.misp.events" :key="e.id"><span class="badge" :class="LEVEL_CLS[e.weight]">{{ t('iprep.level.' + e.weight) }}</span>
                  <span class="gapl">#{{ safeText(e.id, 20) }} {{ safeText(e.info, 160) }}</span></li>
              </ul>
            </template>
          </div>
        </div>
        <p v-if="rep.online_at" class="muted small">{{ t('iprep.online_at', { at: fmtTime(rep.online_at) }) }}</p>
      </section>
      <div class="cols2">
        <section class="card">
          <h2><Icon name="server" /> {{ t('lookup.hosts') }} <span class="count">{{ data.hosts.length }}</span></h2>
          <HBars :items="hostBars" :series="countSeries" />
        </section>
        <section class="card">
          <h2><Icon name="shield" /> {{ t('lookup.rules') }} <span class="count">{{ data.rules.length }}</span></h2>
          <HBars :items="ruleBars" :series="countSeries" mono />
        </section>
      </div>
    </template>
  </div>
</template>

<script setup>
import GeoTag from '../components/GeoTag.vue'
import { ref, computed, watch, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { get } from '../api.js'
import EventTimeline from '../components/EventTimeline.vue'
const since30 = new Date(Date.now() - 30 * 86400e3).toISOString()
import { lang, t, tOr } from '../i18n.js'
import { hasRole } from '../store.js'
import { countryName, safeText, fmtNum, fmtTime, fmtAgo } from '../util.js'
import Sparkline from '../components/charts/Sparkline.vue'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import OriginBadge from '../components/OriginBadge.vue'
import Icon from '../components/Icon.vue'
import FlowSteps from '../components/FlowSteps.vue'
import SegBar from '../components/charts/SegBar.vue'
import HBars from '../components/charts/HBars.vue'
import WorldMap from '../components/charts/WorldMap.vue'

const props = defineProps({ ip: { type: String, default: '' } })
const router = useRouter()
const input = ref(props.ip || '')
const data = ref(null)
const error = ref(null)
const loading = ref(false)

const GUIDE_KEY = 'jtwaf.guide.lookup'
function readFlag(k, d) { try { const v = window.localStorage.getItem(k); return v === null ? d : v === '1' } catch { return d } }
const showGuide = ref(readFlag(GUIDE_KEY, true))
function toggleGuide() {
  showGuide.value = !showGuide.value
  try { window.localStorage.setItem(GUIDE_KEY, showGuide.value ? '1' : '0') } catch { /* storage unavailable */ }
}
// the investigation, with where this address stands once it has been looked up
const flow = computed(() => {
  const d = data.value
  const seen = !!(d && d.d30.events)
  const ip = d ? d.ip : ''
  const canPropose = hasRole('operator')
  return [
    { key: 'look', label: t('guide.ip.look'), desc: t('guide.ip.look_d'), icon: 'search', state: d ? 'done' : 'current' },
    { key: 'events', label: t('guide.ip.events'), desc: t('guide.ip.events_d'), icon: 'list', state: seen ? 'current' : 'todo',
      to: ip ? { path: '/events', query: { src_ip: ip } } : '/events' },
    { key: 'rules', label: t('guide.ip.rules'), desc: t('guide.ip.rules_d'), icon: 'shield', to: '/rules' },
    { key: 'fp', label: t('guide.ip.fp'), desc: t('guide.ip.fp_d'), icon: 'add',
      to: canPropose ? { path: '/changes/new', query: { kind: 'exclusion' } } : null },
    { key: 'attack', label: t('guide.ip.attack'), desc: t('guide.ip.attack_d'), icon: 'block',
      to: canPropose ? { path: '/changes/new', query: { kind: 'confident_block' } } : null },
  ]
})

const outcomeSeries = computed(() => [
  { key: 'blocked', label: t('outcome.blocked'), tone: 'blocked' },
  { key: 'logged', label: t('outcome.logged'), tone: 'logged' },
])
// where this address is (GeoIP), with its last 30 days
const mapItems = computed(() => {
  const g = data.value && data.value.geo
  if (!g || g.scope !== 'external' || !g.cc) return []
  const d = data.value.d30 || {}
  return [{ key: g.cc, label: countryName(g.cc, lang.value) + ' (' + g.cc + ')',
            values: { blocked: d.blocked || 0, logged: Math.max((d.events || 0) - (d.blocked || 0), 0) } }]
})
const countSeries = computed(() => [{ key: 'events', label: t('chart.hits'), tone: 's1' }])
function split(p) {
  return [
    { key: 'blocked', label: t('outcome.blocked'), value: p.blocked || 0, tone: 'blocked' },
    { key: 'logged', label: t('outcome.logged'), value: Math.max(0, (p.events || 0) - (p.blocked || 0)), tone: 'logged' },
  ]
}
const hostBars = computed(() => (data.value ? data.value.hosts : []).map((h) => ({
  key: String(h.key), label: String(h.key), values: { events: h.events || 0 },
  to: { path: '/events', query: { src_ip: data.value.ip, host: h.key } },
})))
const ruleBars = computed(() => (data.value ? data.value.rules : []).map((r) => ({
  key: String(r.key), label: safeText(r.key, 12) + (r.family ? ' · ' + tOr('family.' + r.family, r.family) : ''),
  sub: r.msg ? safeText(r.msg, 120) : null, values: { events: r.events || 0 }, to: '/rules/' + encodeURIComponent(r.key),
})))

// --- IP reputation --------------------------------------------------------------------------------------------------
const isAdmin = computed(() => hasRole('admin'))
const rep = computed(() => data.value && data.value.reputation)
const VERDICT_CLS = { malicious: 'b-blocked', suspicious: 'b-warn', no_record: 'b-logged' }
const LEVEL_CLS = { high: 'b-blocked', medium: 'b-warn', info: 'b-logged' }
function reasonText(r) {
  if (r.source === 'site') return t('iprep.site.' + r.what, { n: fmtNum(r.n || 0) })
  if (r.source === 'list') return t('iprep.on_list', { name: r.name, category: tOr('iprep.cat.' + r.category, r.category), entry: r.entry })
  if (r.source === 'internetdb') return t('iprep.idb_tag', { tag: r.tag })
  if (r.source === 'misp') return t('iprep.misp_event', { id: r.id, name: r.name })
  return ''
}
// the online sources answer through their own job: look again a few times while they are pending
let polls = 0
let pollTimer = null
watch(() => rep.value && rep.value.pending, (p) => {
  clearTimeout(pollTimer)
  if (p && polls < 8) {
    pollTimer = setTimeout(async () => {
      polls += 1
      try { data.value = await get('/lookups/ip/' + encodeURIComponent(props.ip)) } catch { /* the page keeps what it has */ }
    }, 4000)
  }
})
onUnmounted(() => clearTimeout(pollTimer))

function go() {
  if (input.value) router.push('/lookup/' + encodeURIComponent(input.value))
}
async function load() {
  polls = 0
  data.value = null
  error.value = null
  if (!props.ip) return
  input.value = props.ip
  loading.value = true
  try { data.value = await get('/lookups/ip/' + encodeURIComponent(props.ip)) } catch (e) { error.value = e } finally { loading.value = false }
}
watch(() => props.ip, load, { immediate: true })
// the trend on a tile: the last `days` days of the 30-day series (events or blocked)
function spark(days, key) { return ((data.value && data.value.daily) || []).slice(-days).map((d) => ({ t: d.t, v: d[key] || 0 })) }
function ago(iso) { return fmtAgo(iso, lang.value) }
</script>

<style scoped>
.iprep .reasons li { margin: 4px 0; }
.iprep .kvgroups { margin-top: 10px; }
</style>
