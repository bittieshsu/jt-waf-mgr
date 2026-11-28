<!-- Alerts to follow up: what the event analysis or the system found that a person must look at (an attack the
     site may have answered, users hit by a false positive, an outside configuration change...). They stay open
     until an approver marks them handled with a note; open alerts are reminded through the notifications. -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('alerts.title') }}</h1>
      <div class="actions">
        <RouterLink v-if="isAdmin" to="/admin/notify" class="btn small"><Icon name="notify" />{{ t('alerts.to_notify') }}</RouterLink>
        <button type="button" class="btn small ghost" :disabled="loading" @click="reload"><Icon name="refresh" />{{ t('common.refresh') }}</button>
      </div>
    </div>
    <p class="muted">{{ t('alerts.intro') }}</p>
    <ErrorBox :error="error" />
    <div class="seg" role="tablist" :aria-label="t('alerts.filter')">
      <button v-for="f in FILTERS" :key="f" type="button" role="tab" :class="{ on: filter === f }"
              :aria-selected="filter === f ? 'true' : 'false'" @click="setFilter(f)">
        <Icon :name="f === 'open' ? 'bell' : f === 'handled' ? 'check' : 'list'" />{{ t('alerts.f.' + f) }}
        <span v-if="f === 'open' && counts.open" class="badge tiny b-warn">{{ counts.open }}</span></button>
    </div>

    <section v-if="sel || batchOpen" ref="handleEl" class="card handlecard">
      <template v-if="sel">
        <h2><Icon name="check" /> {{ t('alerts.handle_title', { id: sel.id }) }}</h2>
        <p><b>{{ kindText(sel) }}</b> <span class="mono small">{{ safeText(sel.summary, 160) }}</span></p>
        <p v-if="reasonText(sel)" class="reason">{{ safeText(reasonText(sel), 400) }}</p>
        <p v-if="sel.details.msg === 'intel_check' && sel.details.conditions" class="reason small">{{ t('alerts.conditions_line', { text: safeText(sel.details.conditions, 300) }) }}</p>
      </template>
      <template v-else>
        <h2><Icon name="check" /> {{ t('alerts.batch.title', { n: picked.size }) }}</h2>
        <ul class="batchlist small">
          <li v-for="r in pickedRows.slice(0, 20)" :key="r.id"><span class="mono">#{{ r.id }}</span> <b>{{ kindText(r) }}</b> <span class="mono">{{ safeText(r.summary, 100) }}</span></li>
          <li v-if="pickedRows.length > 20" class="muted">{{ t('alerts.batch.more', { n: pickedRows.length - 20 }) }}</li>
        </ul>
      </template>
      <label class="field"><span>{{ t('alerts.note') }}</span>
        <textarea v-model="note" rows="3" maxlength="1000" class="w-lg" :placeholder="t('alerts.note_ph')"></textarea></label>
      <ErrorBox :error="handleError" />
      <p v-if="batchResult" class="small" role="status">{{ batchResult }}</p>
      <div class="actions formacts">
        <button type="button" class="btn primary" :disabled="busy || (!sel && !picked.size)" @click="sel ? handle() : handleBatch()">
          <Spinner v-if="busy" /><Icon v-else name="check" />{{ sel ? t('alerts.mark_handled') : t('alerts.batch.mark', { n: picked.size }) }}</button>
        <button type="button" class="btn ghost" :disabled="busy" @click="closeForm"><Icon name="cancel" />{{ t('common.cancel') }}</button>
      </div>
    </section>

    <div v-if="canHandle && selectable.length" class="card batchbar" role="group" :aria-label="t('alerts.batch.group')">
      <label class="check"><input type="checkbox" :checked="allPicked" :indeterminate.prop="picked.size > 0 && !allPicked" @change="pickAll" /> {{ t('alerts.batch.all', { n: selectable.length }) }}</label>
      <button type="button" class="btn small primary" :disabled="!picked.size || busy" @click="openBatch"><Icon name="check" />{{ t('alerts.batch.mark', { n: picked.size }) }}</button>
    </div>

    <section class="card">
      <h2><Icon name="bell" /> {{ t('alerts.f.' + filter) }} <span class="count">{{ items.length }}</span></h2>
      <RowTimeline v-model:window="win" :title="t('timeline.alerts')" :rows="items" ts-key="created_at" :series="tlSeries" />
      <DataTable id="alerts" :columns="cols" :rows="shownItems" row-key="id" :has-more="!!cursor" :loading-more="loading"
                 :default-sort="{ key: 'id', dir: -1 }" :empty="filter === 'open' ? t('alerts.none_open') : t('common.no_data')"
                 :row-class="(r) => (r.id === focusId ? 'row-focus' : r.state === 'open' && r.severity === 'critical' ? 'row-crit' : null)" @more="more">
        <template #cell-sel="{ row }"><input v-if="row.state === 'open'" type="checkbox" :checked="picked.has(row.id)" :aria-label="t('alerts.batch.pick', { id: row.id })" @click.stop @change="togglePick(row.id)" /><span v-else aria-hidden="true"></span></template>
        <template #cell-created_at="{ row }"><span class="nowrap">{{ fmtShortTime(row.created_at) }}</span>
          <div v-if="row.count > 1" class="sub">{{ t('alerts.seen', { n: row.count, at: fmtShortTime(row.last_seen) }) }}</div></template>
        <template #cell-severity="{ row }"><span class="badge" :class="row.severity === 'critical' ? 'b-blocked' : 'b-warn'">{{ t('alerts.sev.' + row.severity) }}</span></template>
        <template #cell-kind="{ row }"><b>{{ kindText(row) }}</b><div class="sub">{{ tOr('alerts.src.' + row.source, row.source) }}</div></template>
        <template #cell-summary="{ row }"><span class="mono small breakall">{{ safeText(row.summary, 160) }}</span>
          <div v-if="reasonText(row)" class="sub reason">{{ safeText(reasonText(row), 240) }}</div></template>
        <template #cell-state="{ row }"><span class="badge" :class="row.state === 'open' ? 'b-warn' : 'b-ok'">{{ t('alerts.state.' + row.state) }}</span>
          <div v-if="row.handled_by" class="sub">{{ t('alerts.handled_by', { by: safeText(row.handled_by, 40), at: fmtShortTime(row.handled_at) }) }}</div>
          <div v-if="row.note" class="sub">{{ safeText(row.note, 200) }}</div></template>
        <template #cell-actions="{ row }">
          <div class="rowacts">
            <RouterLink v-if="safeLink(row.link)" :to="safeLink(row.link)" class="btn tiny"><Icon name="go" />{{ t('alerts.open') }}</RouterLink>
            <button v-if="row.state === 'open' && canPropose && DRAFT[row.kind] && row.details.path" type="button" class="btn tiny"
                    :disabled="drafting === row.id" @click="draft(row)"><Icon :name="DRAFT[row.kind] === 'exclusion' ? 'unlock' : 'block'" />{{ t('alerts.draft_' + DRAFT[row.kind]) }}</button>
            <button v-if="row.state === 'open' && canHandle" type="button" class="btn tiny" @click="pick(row)"><Icon name="check" />{{ t('alerts.mark_handled') }}</button>
          </div>
        </template>
      </DataTable>
    </section>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, ref } from 'vue'
import { get, post } from '../api.js'
import RowTimeline from '../components/RowTimeline.vue'
import { inWindow } from '../timeWindow.js'
import { t, tOr } from '../i18n.js'
import { fmtShortTime, safeText } from '../util.js'
import { hasRole, refreshAlerts } from '../store.js'
import { useRoute, useRouter } from 'vue-router'
import Icon from '../components/Icon.vue'
import ErrorBox from '../components/ErrorBox.vue'
import DataTable from '../components/DataTable.vue'
import Spinner from '../components/Spinner.vue'

const FILTERS = ['open', 'handled', 'all']
const filter = ref('open')
const items = ref([])
const win = ref(null)
const shownItems = computed(() => inWindow(items.value, 'created_at', win.value))
const tlSeries = computed(() => [{ key: 'critical', label: t('alerts.sev.critical'), tone: 'critical', test: (r) => r.severity === 'critical' }, { key: 'warning', label: t('alerts.sev.warning'), tone: 'warning', test: () => true }])
const counts = ref({ open: 0, critical: 0 })
const cursor = ref(null)
const loading = ref(false)
const error = ref(null)
const sel = ref(null)
const note = ref('')
const busy = ref(false)
const handleError = ref(null)
const handleEl = ref(null)
const isAdmin = computed(() => hasRole('admin'))
const canHandle = computed(() => hasRole('approver'))

// 0.5.48: several open alerts handled at once, with one note (each audited on its own)
const picked = ref(new Set())
const batchOpen = ref(false)
const batchResult = ref('')
const selectable = computed(() => shownItems.value.filter((r) => r.state === 'open'))
const pickedRows = computed(() => items.value.filter((r) => picked.value.has(r.id)))
const allPicked = computed(() => selectable.value.length > 0 && selectable.value.every((r) => picked.value.has(r.id)))
function togglePick(id) { const s = new Set(picked.value); s.has(id) ? s.delete(id) : s.add(id); picked.value = s }
function pickAll() { picked.value = allPicked.value ? new Set() : new Set(selectable.value.map((r) => r.id)) }
async function openBatch() {
  sel.value = null
  batchOpen.value = true
  note.value = ''
  handleError.value = null
  batchResult.value = ''
  await nextTick()
  if (handleEl.value) handleEl.value.scrollIntoView({ behavior: 'smooth', block: 'start' })
}
function closeForm() { sel.value = null; batchOpen.value = false }
async function handleBatch() {
  busy.value = true
  handleError.value = null
  batchResult.value = ''
  try {
    const r = await post('/alerts/handle-batch', { ids: [...picked.value], note: note.value })
    const bad = r.failed || []
    picked.value = new Set(bad.map((x) => x.id))
    if (!bad.length) batchOpen.value = false
    else batchResult.value = t('alerts.batch.done', { n: r.handled }) + ' ' + t('alerts.batch.failed', { list: bad.map((x) => '#' + x.id + ' ' + tOr('error.' + x.error, x.error)).join(', ') })
    reload()
  } catch (e) { handleError.value = e } finally { busy.value = false }
}

const cols = computed(() => [
  ...(canHandle.value && selectable.value.length ? [{ key: 'sel', label: '', sortable: false, filterable: false, required: true, nowrap: true, text: () => '' }] : []),
  { key: 'id', label: t('alerts.col.id'), align: 'num', hidden: true },
  { key: 'created_at', label: t('alerts.col.time'), required: true, text: (r) => fmtShortTime(r.created_at) },
  { key: 'severity', label: t('alerts.col.severity'), value: (r) => (r.severity === 'critical' ? 0 : 1), text: (r) => t('alerts.sev.' + r.severity) },
  { key: 'kind', label: t('alerts.col.kind'), class: 'c-kind', value: (r) => kindText(r) },
  { key: 'summary', label: t('alerts.col.what'), class: 'c-fill', value: (r) => r.summary + ' ' + reasonText(r) },
  { key: 'state', label: t('alerts.col.state'), value: (r) => t('alerts.state.' + r.state) },
  { key: 'actions', label: t('alerts.col.actions'), sortable: false, filterable: false },
])
function kindText(r) { return tOr('alerts.kind.' + r.kind, r.kind) }
// threat intelligence alerts carry a message key and its values: worded in the interface language (the stored
// reason is the English one, kept for the audit trail)
const MSGS = ['intel_urgent', 'intel_check', 'intel_patch', 'intel_remove', 'intel_elsewhere', 'intel_built_on', 'intel_tech_hit', 'intel_distro', 'intel_release', 'intel_search_empty']
// system alerts (0.5.43) carry a message key too; older ones are worded from their values by kind
const SYS_MSGS = ['crs_update', 'blocks_full', 'blocks_apply_failed', 'countries_apply_failed', 'traffic_spike', 'traffic_errors']
const SYS_KINDS = { crs_update: ['crs_update', 'version'], traffic_spike: ['traffic_spike', 'requests'], traffic_errors: ['traffic_errors', 'requests'] }
function sysMsg(r) {
  const d = r.details || {}
  const k = SYS_KINDS[r.kind]
  const m = d.msg || (k && d[k[1]] != null ? k[0] : '')
  return SYS_MSGS.includes(m) ? m : ''
}
function sysText(m, d) {
  const hm = String(d.hour || '').slice(11, 16)
  if (m === 'crs_update') return t('alerts.crs_update', { v: String(d.version || ''), installed: String(d.installed || '-') })
  if (m === 'blocks_full') return t('alerts.blocks_full', { max: String(d.max ?? '') })
  if (m === 'blocks_apply_failed' || m === 'countries_apply_failed') return t('alerts.' + m, { summary: String(d.summary || '') })
  if (m === 'traffic_spike') {
    return t('alerts.traffic_spike', { at: hm, n: String(d.requests ?? ''), usual: String(Math.round(Number(d.usual) || 0)), factor: String(d.factor ?? '') })
  }
  return t('alerts.traffic_errors', { at: hm, n: String(d.requests ?? ''), s5xx: String(d.s5xx ?? ''), percent: String(d.percent ?? '') })
}
function reasonText(r) {
  const d = r.details || {}
  if (r.kind === 'nginx_module') {
    return t('nginxmod.alert.' + (d.reason || 'ok'), { installed: String(d.installed || d.nginx_version || ''), candidate: String(d.candidate || ''),
      package: String(d.package || 'nginx') })
  }
  if (r.kind === 'nginx_security') {
    return t('alerts.nginx_security', { v: String(d.installed || ''), n: (d.issues || []).length, cves: (d.cves || []).join(', '),
      ready: d.ready && d.candidate ? t('alerts.nginx_security_ready', { v: String(d.candidate) }) : '' })
  }
  if (r.kind === 'backend_security') {
    return t('alerts.backend_security', { v: String(d.installed || ''), sites: (d.sites || []).slice(0, 5).join(', '),
      n: (d.issues || []).length, cves: (d.cves || []).join(', ') })
  }
  const sys = sysMsg(r)
  if (sys) return sysText(sys, d)
  if (!MSGS.includes(d.msg)) return d.reason || ''
  if (d.msg === 'intel_search_empty') {
    return t('alerts.intel_search_empty', { n: String(d.n ?? ''), of: String(d.of ?? ''), service: String(d.service || '') })
  }
  if (d.msg === 'intel_release') {
    // an announced security release (0.5.8): words from the vendor's page, shown as text
    const ids = (d.ids || []).map(String).slice(0, 10)
    return t('alerts.intel_release', { product: String(d.product || ''), at: d.release_at ? fmtShortTime(d.release_at) : '-',
      ids: ids.length ? ' (' + ids.join(', ') + ')' : '', title: String(d.title || d.summary || ''), products: String(d.products || ''),
      mit: d.mitigation ? t('alerts.intel_release_mit', { m: String(d.mitigation) }) : '' })
  }
  const ver = String(d.sw_version || '').trim()
  const product = String(d.product || '')
  return t('alerts.' + d.msg, {
    cve: String(d.cve || ''), product, sw: ver ? product + ' ' + ver : product,
    vu: ver || d.msg === 'intel_remove' ? '' : t('alerts.ver_unknown'),
    affects: t(d.affected === 'yes' ? 'alerts.aff_yes' : 'alerts.aff_maybe'),
    now: ver, was: String(d.sw_was || ''), rule_id: String(d.rule_id || ''), products: String(d.products || ''),
    tech: String(d.tech || ''), versions: (d.tech_hit || []).slice(0, 5).map(String).join(', '), patch: d.patch_rule ? t('alerts.intel_patched', { rule: String(d.patch_rule) }) : '',
  })
}
// an alert becomes a change: find a recent event of that site and path (paths in alerts are decoded and lower case,
// as a rule sees them) and open the change form filled from it
const DRAFT = { false_positive: 'exclusion', attack_passed: 'block', attack_in_progress: 'block' }
const canPropose = computed(() => hasRole('operator'))
const drafting = ref(null)
const router = useRouter()
function viewOf(p) { try { return decodeURIComponent(p).toLowerCase() } catch { return String(p).toLowerCase() } }
async function draft(r) {
  drafting.value = r.id
  const mode = DRAFT[r.kind]
  const host = String(r.details.host || '').split(',')[0].trim()
  const path = String(r.details.path || '').split(',')[0].trim()
  try {
    const q = { limit: 200 }
    if (host) q.host = host
    if (mode === 'exclusion') q.outcome = 'blocked'
    const res = await get('/events', q)
    const ev = (res.items || []).find((e) => viewOf(e.path || '/') === path)
    router.push(ev ? { path: '/changes/new', query: { from_event: ev.id, mode } }
      : { path: '/changes/new', query: { kind: mode === 'exclusion' ? 'exclusion' : 'confident_block' } })
  } catch (e) { error.value = e } finally { drafting.value = null }
}
// links come from the server and are paths inside this application only
function safeLink(l) { return typeof l === 'string' && /^\/[A-Za-z0-9/_-]*$/.test(l) ? l : '' }
async function load(append) {
  loading.value = true
  error.value = null
  try {
    const r = await get('/alerts', { state: filter.value === 'all' ? undefined : filter.value, limit: 100,
      cursor: append ? cursor.value : undefined })
    items.value = append ? items.value.concat(r.items) : r.items
    cursor.value = r.next_cursor
    counts.value = r.counts
  } catch (e) { error.value = e } finally { loading.value = false }
}
function more() { if (cursor.value) load(true) }
function reload() { load(false); refreshAlerts(true) }
function setFilter(f) { filter.value = f; sel.value = null; batchOpen.value = false; picked.value = new Set(); load(false) }
async function pick(r) {
  batchOpen.value = false
  sel.value = r
  note.value = ''
  handleError.value = null
  await nextTick()
  if (handleEl.value) handleEl.value.scrollIntoView({ behavior: 'smooth', block: 'start' })
}
async function handle() {
  busy.value = true
  handleError.value = null
  try {
    await post('/alerts/' + sel.value.id + '/handle', { note: note.value })
    sel.value = null
    reload()
  } catch (e) { handleError.value = e } finally { busy.value = false }
}
// /alerts?id=N (from the analysis page, a notification...): that alert, selected, its handling form open
const route = useRoute()
const focusId = ref(null)
async function focusAlert() {
  const id = Number(route.query.id)
  if (!Number.isInteger(id) || id <= 0) return
  focusId.value = id
  let r = items.value.find((x) => x.id === id)
  if (!r) {                    // handled already, or further down: look at every alert
    filter.value = 'all'
    await load(false)
    r = items.value.find((x) => x.id === id)
  }
  if (r && r.state === 'open' && canHandle.value) pick(r)
  else if (r) {
    await nextTick()
    const el = document.querySelector('.row-focus')
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }
}
onMounted(async () => { await load(false); focusAlert() })
</script>

<style scoped>
.seg { margin: 8px 0 14px; }
.sub { color: var(--muted); font-size: .85em; margin-top: 2px; }
.reason { white-space: pre-wrap; overflow-wrap: anywhere; }
.rowacts { display: flex; flex-wrap: wrap; gap: 6px; }
:deep(tr.row-focus) td { background: color-mix(in srgb, var(--accent) 12%, var(--panel)); }
:deep(tr.row-crit) td:first-child { box-shadow: inset 3px 0 0 var(--blocked); }
.w-lg { width: 100%; max-width: 560px; }
/* 0.5.48: the buttons sat right under the note box, touching it */
.handlecard .formacts { margin-top: 14px; display: flex; flex-wrap: wrap; gap: 10px; }
.batchbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 16px; padding-top: 12px; padding-bottom: 12px; }
.batchbar label.check { margin: 0; }
.batchlist { margin: 4px 0 10px; padding-left: 18px; }
.batchlist li { margin: 2px 0; overflow-wrap: anywhere; }
</style>
