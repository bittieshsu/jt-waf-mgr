<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('vhosts.title') }}</h1>
      <span class="badge b-int"><Icon name="lock" />{{ t('rules.readonly') }}</span>
    </div>
    <ErrorBox :error="error" />
    <Loading v-if="loading" />
    <div v-if="warnings.length" class="alert warn">
      <div v-for="(w, i) in warnings" :key="i">{{ safeText(w, 500) }}</div>
    </div>
    <section v-if="items.length" class="card">
      <p class="muted small">{{ t('vhosts.summary2', { total: items.length, on: count('on'), block: count('block'), off: count('off'), redirect: count('redirect') }) }}</p>
      <div class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.waf_modes') }}</h3><SegBar :parts="modeParts" :label="t('chart.waf_modes')" /></div>
      </div>
      <div class="cols2">
        <div>
          <h3 class="charthead">{{ t('chart.site_events') }}</h3>
          <HBars :items="siteBars" :series="outcomeSeries" mono />
        </div>
        <div>
          <h3 class="charthead">{{ t('chart.bypass_per_block') }}</h3>
          <HBars :items="bypassBars" mono />
        </div>
      </div>
    </section>
    <!-- the page blocked visitors see: every site at once here, one site at a time in the table -->
    <section v-if="items.length" id="blocked-page" class="card">
      <h2><Icon name="page" /> {{ t('blockpage.title') }}</h2>
      <p class="muted small">{{ t('blockpage.hint') }}</p>
      <p class="small">{{ t('blockpage.status', { ours: pageCount('ours'), can: pagePlan, own: pageCount('own') }) }}</p>
      <p v-if="pageInfo && pageInfo.refresh && pageCount('ours') > 0" class="alert info">{{ t('blockpage.refresh_hint') }}</p>
      <p v-if="pageInfo && !pageInfo.ok && pageInfo.error !== 'nothing_to_do'" class="alert warn">{{ t('blockpage.plan_error', { error: pageInfo.error }) }}</p>
      <div class="actions">
        <a class="btn small" href="/api/v1/vhosts/blocked-page/preview" target="_blank" rel="noopener noreferrer" data-preview="blocked-page"
           :title="t('blockpage.preview_hint')"><Icon name="show" />{{ t('blockpage.preview') }}</a>
        <RouterLink v-if="isApprover && pageChanges['*']" :to="'/changes/' + pageChanges['*']">{{ t('sitewaf.pending', { id: pageChanges['*'] }) }}</RouterLink>
        <template v-else-if="isApprover">
          <button v-if="pagePlan > 0" type="button" class="btn small primary" @click="startSite(null, 'enable', 'page')"><Icon name="page" />{{ t('blockpage.apply_all') }}</button>
          <button v-else-if="pageInfo && pageInfo.refresh" type="button" class="btn small primary" @click="startSite(null, 'enable', 'page')"><Icon name="refresh" />{{ t('blockpage.refresh') }}</button>
          <button v-if="pageCount('ours') > 0" type="button" class="btn small danger" @click="startSite(null, 'disable', 'page')"><Icon name="cancel" />{{ t('blockpage.remove_all') }}</button>
        </template>
      </div>
    </section>
    <section v-if="site.host" ref="siteForm" class="card">
      <h2><Icon :name="formIcon" /> {{ formTitle }}</h2>
      <p class="muted small">{{ formHint }}</p>
      <label class="field"><span>{{ t('sitewaf.reason') }}</span>
        <textarea v-model="site.reason" rows="2" maxlength="2000" class="w-lg"></textarea></label>
      <ErrorBox :error="site.error" />
      <div class="actions">
        <button type="button" class="btn small" :class="site.mode === 'enable' ? 'primary' : 'danger'" :disabled="site.busy || site.reason.trim().length < 5" @click="submitSite">
          <Icon name="send" />{{ t('sitewaf.propose') }}</button>
        <button type="button" class="btn small ghost" @click="site.host = ''"><Icon name="cancel" />{{ t('common.cancel') }}</button>
      </div>
    </section>
    <DataTable id="vhosts" :columns="cols" :rows="items" :row-key="(v) => v.file + ':' + v.line" :page-size="50">
      <template #cell-server_names="{ row }">
        <div v-for="n in row.server_names" :key="n" class="mono"><TruncText :text="n" :max="100" /></div>
        <div class="sub mono" :title="safeText(row.file, 500)">{{ shortFile(row.file) }}:{{ row.line }} · {{ (row.listen || []).map((l) => safeText(l, 40)).join(', ') }}</div>
      </template>
      <template #cell-waf="{ row }">
        <span v-if="row.waf === 'off' && row.redirect_only" class="badge b-logged" :title="t('waf.redirect_hint')">{{ t('waf.redirect') }}</span>
        <span v-else class="badge" :class="wafCls(row.waf)">{{ t('waf.' + (row.waf || 'unknown')) }}</span>
        <!-- switching ModSecurity on (or off again, only where it was switched on here): a change a person approves -->
        <div v-if="siteOf(row) && siteChanges[siteOf(row)]" class="sub"><RouterLink :to="'/changes/' + siteChanges[siteOf(row)]">{{ t('sitewaf.pending', { id: siteChanges[siteOf(row)] }) }}</RouterLink></div>
        <div v-else-if="isApprover && siteOf(row) && row.waf === 'off' && !row.redirect_only" class="sub">
          <button type="button" class="btn tiny" @click="startSite(row, 'enable')"><Icon name="shield" />{{ t('sitewaf.enable') }}</button></div>
        <div v-else-if="isApprover && siteOf(row) && row.waf_by_us" class="sub">
          <button type="button" class="btn tiny danger" @click="startSite(row, 'disable')"><Icon name="unlock" />{{ t('sitewaf.disable') }}</button></div>
        <div v-if="row.inline_rule_ids && row.inline_rule_ids.length" class="sub mono">
          {{ t('vhosts.inline_rules') }}: <RouterLink v-for="id in row.inline_rule_ids" :key="id" :to="'/rules/' + id" class="idlink">{{ id }}</RouterLink>
        </div>
      </template>
      <template #cell-page="{ row }">
        <span v-if="row.redirect_only && pageState(row) === 'none'" class="muted">—</span>
        <span v-else class="badge" :class="PAGE_CLS[pageState(row)]">{{ t('blockpage.state.' + pageState(row)) }}</span>
        <div v-if="pagePending(row)" class="sub"><RouterLink :to="'/changes/' + pagePending(row)">{{ t('sitewaf.pending', { id: pagePending(row) }) }}</RouterLink></div>
        <div v-else-if="isApprover && siteOf(row) && pageState(row) === 'none' && !row.redirect_only" class="sub">
          <button type="button" class="btn tiny" @click="startSite(row, 'enable', 'page')"><Icon name="page" />{{ t('blockpage.apply') }}</button></div>
        <div v-else-if="isApprover && siteOf(row) && pageState(row) === 'ours'" class="sub">
          <button type="button" class="btn tiny danger" @click="startSite(row, 'disable', 'page')"><Icon name="cancel" />{{ t('blockpage.remove') }}</button></div>
      </template>
      <!-- one line: what the country rules of this site allow or block; the details and the actions are on the
           country-limits page (this table is about the nginx configuration) -->
      <template #cell-countries="{ row }">
        <RouterLink v-if="(row.countries || []).length" class="cosum" :to="{ path: '/countries', query: { host: countryHost(row) } }"
                    :title="t('vhosts.country_open')">
          <span v-for="c in row.countries" :key="c.item_id" :class="{ off: !c.enabled }">
            <span class="badge" :class="!c.enabled ? 'b-logged' : c.mode === 'allow' ? 'b-ok' : 'b-blocked'">{{ t('vhosts.country_mode.' + (c.mode === 'deny' ? 'deny' : 'allow')) }}</span>
            <span class="mono">{{ c.countries.join(' ') }}</span>
          </span>
        </RouterLink>
        <span v-else class="muted">—</span>
      </template>
      <template #cell-dns="{ row }">
        <template v-if="row.dns">
          <span class="badge" :class="row.dns.class === 'internal_only' && row.reach === 'open' ? 'b-blocked' : DNS_CLS[row.dns.class] || 'b-logged'"
                :title="row.dns.class === 'internal_only' && row.reach === 'open' ? t('dns.risk') : null">{{ t('dns.class.' + row.dns.class) }}</span>
          <div v-if="row.dns.public_private" class="sub warn">{{ t('dns.public_private') }}</div>
        </template>
        <span v-else class="muted">—</span>
      </template>
      <template #cell-reach="{ row }">
        <span class="badge" :class="REACH_CLS[row.reach] || 'b-logged'" :title="row.reach_by ? safeText(row.reach_by, 300) : t('vhosts.reach_hint')">{{ t('vhosts.reach.' + (row.reach || 'open')) }}</span>
        <div v-if="row.outside_7d != null && !row.redirect_only" class="sub" :class="{ warn: row.reach === 'internal' && row.outside_7d > 0 }">{{ t('vhosts.outside_7d', { n: fmtNum(row.outside_7d) }) }}</div>
      </template>
      <template #cell-bypass="{ row }">
        <div v-for="b in row.bypass || []" :key="b.file + b.line" class="mono" :title="safeText(b.file, 500) + ':' + b.line"><TruncText :text="b.location" :max="120" mono /></div>
        <span v-if="!(row.bypass || []).length" class="muted">—</span>
      </template>
      <template #cell-body_limit="{ row }"><span class="mono">{{ row.body_limit ? safeText(row.body_limit, 20) : t('vhosts.default') }}</span></template>
      <template #cell-restrictions="{ row }">
        <div v-for="(r, i) in row.restrictions || []" :key="i" class="mono small"><TruncText :text="r" :max="160" mono /></div>
        <span v-if="!(row.restrictions || []).length" class="muted">—</span>
      </template>
      <template #cell-upstreams="{ row }"><div v-for="u in row.upstreams || []" :key="u" class="mono small"><TruncText :text="u" :max="100" mono /></div></template>
    </DataTable>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { get, post } from '../api.js'
import { hasRole } from '../store.js'
import { t } from '../i18n.js'
import { safeText, fmtNum } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import TruncText from '../components/TruncText.vue'
import Icon from '../components/Icon.vue'
import DataTable from '../components/DataTable.vue'
import SegBar from '../components/charts/SegBar.vue'
import HBars from '../components/charts/HBars.vue'

const router = useRouter()
const isApprover = computed(() => hasRole('approver'))
const siteChanges = ref({})
const pageChanges = ref({})
const pageInfo = ref(null)        // can the blocked page go on every site: {ok, plan: n} or {ok: false, error}
const site = reactive({ host: '', mode: 'enable', kind: 'waf', reason: '', busy: false, error: null })
const PAGE_CLS = { ours: 'b-ok', own: 'b-int', none: 'b-logged' }
const pagePlan = computed(() => (pageInfo.value && pageInfo.value.ok ? pageInfo.value.plan : 0))
function pageState(v) { return v.blocked_page || 'none' }
function pageCount(w) { return items.value.filter((v) => pageState(v) === w).length }
function pagePending(v) { return pageChanges.value[siteOf(v).toLowerCase()] || pageChanges.value['*'] || 0 }
const formIcon = computed(() => (site.kind === 'page' ? (site.mode === 'enable' ? 'page' : 'cancel') : site.mode === 'enable' ? 'shield' : 'unlock'))
const formTitle = computed(() => {
  if (site.kind !== 'page') return t(site.mode === 'enable' ? 'sitewaf.enable_title' : 'sitewaf.disable_title', { host: site.host })
  if (site.host === '*') return t(site.mode === 'enable' ? 'blockpage.enable_all_title' : 'blockpage.disable_all_title')
  return t(site.mode === 'enable' ? 'blockpage.enable_title' : 'blockpage.disable_title', { host: site.host })
})
const formHint = computed(() => t((site.kind === 'page' ? 'blockpage.' : 'sitewaf.') + (site.mode === 'enable' ? 'enable_hint' : 'disable_hint')))
const siteForm = ref(null)
// the site a switch is for: the first plain name of the server block
function siteOf(v) {
  return (v.server_names || []).find((n) => n && n !== '_' && !n.startsWith('~') && /^[a-z0-9.-]+$/i.test(n)) || ''
}
async function startSite(row, mode, kind = 'waf') {
  Object.assign(site, { host: row ? siteOf(row).toLowerCase() : '*', mode, kind, error: null,
    reason: kind === 'page' && mode === 'enable' ? t('blockpage.default_reason') : '' })
  await nextTick()
  if (siteForm.value) siteForm.value.scrollIntoView({ behavior: 'smooth', block: 'center' })
}
async function submitSite() {
  site.busy = true
  site.error = null
  try {
    const r = await post(site.kind === 'page' ? '/vhosts/blocked-page' : '/vhosts/waf', { host: site.host, mode: site.mode, reason: site.reason.trim() })
    router.push('/changes/' + r.change_id)
  } catch (e) { site.error = e } finally { site.busy = false }
}
const items = ref([])
const warnings = ref([])
const loading = ref(false)
const error = ref(null)
const byHost = ref([])        // /overview?range=7d by_host: the 15 busiest sites

const cols = computed(() => [
  { key: 'server_names', label: t('vhosts.server_names'), required: true, value: (v) => (v.server_names || [])[0] || '~',
    text: (v) => (v.server_names || []).join(' ') + ' ' + (v.file || '') + ' ' + (v.listen || []).join(' ') },
  { key: 'waf', label: t('vhosts.waf'), nowrap: true, value: (v) => (v.waf === 'off' && v.redirect_only ? t('waf.redirect') : t('waf.' + (v.waf || 'unknown'))),
    text: (v) => (v.waf === 'off' && v.redirect_only ? t('waf.redirect') : t('waf.' + (v.waf || 'unknown'))) + ' ' + (v.inline_rule_ids || []).join(' ') },
  { key: 'page', label: t('vhosts.page'), nowrap: true, value: (v) => t('blockpage.state.' + pageState(v)) },
  { key: 'dns', label: t('dns.col.dns'), nowrap: true, value: (v) => (v.dns ? t('dns.class.' + v.dns.class) : '') },
  { key: 'reach', label: t('vhosts.reach'), nowrap: true, value: (v) => t('vhosts.reach.' + (v.reach || 'open')),
    text: (v) => t('vhosts.reach.' + (v.reach || 'open')) + ' ' + (v.reach_by || '') },
  { key: 'countries', label: t('vhosts.countries'), value: (v) => (v.countries || []).length,
    text: (v) => (v.countries || []).concat(v.country_changes || []).map((c) => t('vhosts.country_mode.' + (c.mode === 'deny' ? 'deny' : 'allow')) + ' ' + (c.countries || []).join(' ')).join(' ') },
  { key: 'bypass', label: t('vhosts.bypass'), value: (v) => (v.bypass || []).length, text: (v) => (v.bypass || []).map((b) => b.location).join(' ') },
  { key: 'body_limit', label: t('vhosts.body_limit'), text: (v) => v.body_limit || t('vhosts.default') },
  { key: 'restrictions', label: t('vhosts.restrictions'), value: (v) => (v.restrictions || []).length, text: (v) => (v.restrictions || []).join(' ') },
  { key: 'realip', label: t('vhosts.realip'), value: (v) => (v.realip ? t('common.yes') : t('common.no')) },
  { key: 'upstreams', label: t('vhosts.upstreams'), value: (v) => (v.upstreams || []).join(' ') },
])

// the site a new country rule is for: the first plain name of the server block (not "_" or a regular expression)
function countryHost(v) {
  return (v.server_names || []).find((n) => n && n !== '_' && !n.startsWith('~') && /^(\*\.)?[a-z0-9.-]+$/i.test(n)) || ''
}
// internal only: green; limited to countries or addresses: blue; a check not understood: grey; open: amber
// what the DNS check found: internal DNS only (hidden, amber; red when nginx lets outside sources in), public, ...
const DNS_CLS = { internal_only: 'b-warn', public: 'b-int', wildcard: 'b-logged', not_found: 'b-logged', error: 'b-blocked' }
const REACH_CLS = { internal: 'b-ok', country: 'b-int', limited: 'b-int', restricted: 'b-logged', open: 'b-warn' }
// a block that only redirects (http to https) is not counted as unprotected: there is nothing in it to protect
function count(w) { return items.value.filter((v) => (w === 'redirect' ? v.waf === 'off' && v.redirect_only : v.waf === w && !(w === 'off' && v.redirect_only))).length }
function wafCls(w) { return w === 'block' ? 'b-blocked' : w === 'on' ? 'b-ok' : w === 'off' ? 'b-warn' : 'b-int' }
function shortFile(p) {
  const s = String(p || '')
  const i = s.lastIndexOf('/')
  return safeText(i >= 0 ? s.slice(i + 1) : s, 120)
}

const modeParts = computed(() => [
  { key: 'block', label: t('waf.block'), value: count('block'), tone: 's1' },
  { key: 'on', label: t('waf.on'), value: count('on'), tone: 's2' },
  { key: 'off', label: t('waf.off'), value: count('off'), tone: 'warning' },
  { key: 'redirect', label: t('waf.redirect'), value: count('redirect'), tone: 'muted' },
  { key: 'unknown', label: t('waf.unknown'), value: items.value.filter((v) => !['block', 'on', 'off'].includes(v.waf)).length, tone: 'muted' },
])
const outcomeSeries = computed(() => [
  { key: 'blocked', label: t('outcome.blocked'), tone: 'blocked' },
  { key: 'logged', label: t('outcome.logged'), tone: 'logged' },
])
const siteBars = computed(() => byHost.value.map((h) => ({
  key: String(h.key), label: String(h.key), values: { blocked: h.blocked || 0, logged: h.logged || 0 },
  to: { path: '/events', query: { host: h.key } },
})))
const bypassBars = computed(() => items.value.filter((v) => (v.bypass || []).length)
  .map((v) => ({ key: v.file + ':' + v.line, label: (v.server_names || [])[0] || shortFile(v.file), values: { value: v.bypass.length } }))
  .sort((a, b) => b.values.value - a.values.value).slice(0, 15))

onMounted(async () => {
  loading.value = true
  try {
    const data = await get('/vhosts')
    items.value = data.items || []
    warnings.value = data.warnings || []
    siteChanges.value = data.site_changes || {}
    pageChanges.value = data.page_changes || {}
    pageInfo.value = data.blocked_page || null
  } catch (e) { error.value = e } finally { loading.value = false }
  try { byHost.value = (await get('/overview', { range: '7d' })).by_host || [] } catch { byHost.value = [] }
})
</script>

<style scoped>
.cosum { display: inline-flex; flex-wrap: wrap; gap: 4px 10px; align-items: center; white-space: nowrap; text-decoration: none; color: inherit; }
.cosum > span { display: inline-flex; gap: 4px; align-items: center; }
.cosum .off { opacity: .6; }
.cosum:hover .mono { text-decoration: underline; }
.badge .icon { margin-right: 3px; vertical-align: -0.25em; }
</style>
