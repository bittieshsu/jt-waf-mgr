<!-- CrowdSec virtual patching rules: the CrowdSec Hub's appsec rules (MIT), read and converted into ModSecurity rules
     on this host: which rules exist, which convert (and why not), which name software of this site; a converted rule is
     proposed for chosen sites as an ordinary change (the sandbox replays the hub's own attack requests), updated when
     the hub changes it, removed when the software is fixed. -->
<template>
  <div class="page">
    <div class="pagehead"><h1>{{ t('hub.title') }}</h1></div>
    <p class="alert info small"><Icon name="info" /> {{ t('hub.intro') }}</p>
    <Loading v-if="!data && !error" />
    <ErrorBox :error="error" />
    <template v-if="data">
      <div v-if="data.commit" class="tiles hubtiles">
        <div v-for="st in tiles" :key="st.key" class="tile stat" :class="st.cls">
          <div class="tl"><Icon :name="st.icon" />{{ st.label }}</div>
          <div class="tv">{{ fmtNum(st.value) }}</div>
          <div class="ts"><span class="tsub">{{ st.sub }}</span></div>
        </div>
      </div>

      <section class="card">
        <h2><Icon name="refresh" /> {{ t('hub.source') }}</h2>
        <div class="kvgroups">
          <div class="kvpanel">
            <h3><Icon name="code" />{{ t('hub.g_source') }}</h3>
            <dl class="kv">
              <dt>{{ t('hub.sync') }}</dt><dd><span class="badge" :class="data.enabled ? 'b-ok' : 'b-logged'">{{ data.enabled ? t('hub.on') : t('hub.off') }}</span>
                <RouterLink v-if="isAdmin && !data.enabled" class="gapl" to="/admin/settings#uiset-hub">{{ t('hub.where_on') }}</RouterLink></dd>
              <dt>{{ t('hub.commit') }}</dt><dd><a v-if="data.commit" class="mono" :href="'https://github.com/crowdsecurity/hub/commit/' + data.commit" target="_blank" rel="noopener noreferrer">{{ data.commit.slice(0, 12) }}</a><span v-else class="muted">—</span>
                <span v-if="data.source" class="muted small gapl">{{ sourceText(data.source) }}</span></dd>
              <dt>{{ t('hub.synced_at') }}</dt><dd>{{ data.synced_at ? fmtMinute(data.synced_at) : '—' }}
                <span v-if="data.requested" class="badge b-warn gapl">{{ t('hub.requested') }}</span></dd>
              <dt>{{ t('hub.last_run') }}</dt><dd><template v-if="data.status && data.status.state">
                <span class="badge" :class="data.status.state === 'error' ? 'b-blocked' : data.status.state === 'ok' ? 'b-ok' : 'b-logged'">{{ tOr('hub.state.' + data.status.state, data.status.state) }}</span>
                <span class="muted small gapl">{{ fmtMinute(data.status.at) }}</span>
                <div v-if="data.status.error" class="small warn">{{ safeText(data.status.error, 300) }}</div></template><span v-else class="muted">—</span></dd>
            </dl>
          </div>
          <div class="kvpanel">
            <h3><Icon name="page" />{{ t('hub.g_license') }}</h3>
            <p class="small">{{ t('hub.license_note') }}</p>
            <button v-if="data.commit" type="button" class="btn small ghost" @click="toggleLicense"><Icon name="page" />{{ showLicense ? t('hub.hide_license') : t('hub.show_license') }}</button>
            <CodeBlock v-if="showLicense && license" small :code="license" />
          </div>
        </div>
        <div v-if="isAdmin" class="actions hubacts">
          <button type="button" class="btn primary" :disabled="busy || !data.enabled || data.requested" :title="data.enabled ? '' : t('hub.sync_off_hint')" @click="syncNow"><Icon name="refresh" />{{ t('hub.sync_now') }}</button>
          <label class="btn ghost filebtn"><Icon name="upload" />{{ t('hub.upload') }}
            <input type="file" accept=".zip,.tar.gz,.tgz,application/zip,application/gzip" :disabled="busy" @change="upload"></label>
        </div>
        <p v-if="isAdmin" class="muted small uphint">{{ t('hub.upload_hint') }}</p>
        <p v-if="progress" class="small" role="status"><Icon name="timer" /> {{ progress }}</p>
        <ErrorBox :error="actionError" />
      </section>

      <section v-if="data.rules.length" class="card">
        <div class="cardhead">
          <h2><Icon name="shield" /> {{ t('hub.rules') }} <span class="count">{{ shown.length }}</span></h2>
          <div class="seg" role="group" :aria-label="t('hub.show')">
            <button v-for="f in FILTERS" :key="f" type="button" :class="{ on: filter === f }" :aria-pressed="filter === f" @click="filter = f"><Icon :name="FILTER_ICON[f]" />{{ t('hub.f.' + f) }}</button>
          </div>
        </div>
        <p class="muted small">{{ t('hub.rules_hint') }}</p>
        <DataTable id="hub-rules" :columns="cols" :rows="shown" row-key="name" :page-size="50" :expanded="open" clickable
                   @row-click="(r) => openRule(r)">
          <template #cell-name="{ row }"><span class="mono small hubname">{{ safeText(row.name.replace(/^crowdsecurity\//, ''), 120) }}</span>
            <span v-if="row.change === 'new' || row.change === 'changed'" class="badge b-int gapl">{{ t('hub.change.' + row.change) }}</span></template>
          <template #cell-cves="{ row }"><span v-for="c in row.cves.slice(0, 3)" :key="c" class="chip tag mono">{{ safeText(c, 30) }}</span><span v-if="!row.cves.length" class="muted">—</span></template>
          <template #cell-label="{ row }">{{ safeText(row.label || row.description, 160) }}</template>
          <template #cell-related="{ row }"><template v-if="row.related.length"><span v-for="p in row.related" :key="p.name" class="chip ok">{{ safeText(p.name, 60) }}</span></template><span v-else class="muted">—</span></template>
          <template #cell-use="{ row }"><RouterLink v-if="row.open_change" class="badge b-int" :to="'/changes/' + row.open_change.change_id" @click.stop>{{ useText(row) }}</RouterLink>
            <span v-else-if="row.applied" class="badge" :class="row.applied.upstream === 'same' ? 'b-ok' : 'b-warn'">{{ useText(row) }}</span><span v-else class="muted">—</span></template>
          <template #cell-ok="{ row }"><span class="badge" :class="row.ok ? 'b-ok' : 'b-warn'" :title="row.ok ? '' : tOr('hub.why.' + row.reason, row.reason)">{{ row.ok ? t('hub.convertible') : t('hub.unsupported') }}</span></template>
          <template #expand="{ row }">
            <div class="hubdetail">
              <Loading v-if="!detail || detail.name !== row.name" />
              <template v-else>
                <p>{{ safeText(detail.description, 500) }}</p>
                <p class="small">
                  <a v-for="c in detail.cves" :key="c" class="gapr" :href="'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(c)" target="_blank" rel="noopener noreferrer">{{ c }}</a>
                  <a :href="'https://github.com/crowdsecurity/hub/blob/' + (detail.commit || 'master') + '/' + detail.path" target="_blank" rel="noopener noreferrer">{{ t('hub.on_github') }}</a></p>
                <p v-if="detail.related.length" class="small"><strong>{{ t('hub.related') }}：</strong>
                  <template v-for="p in detail.related" :key="p.name">{{ safeText(p.name, 60) }}<span v-if="p.sites.length" class="muted"> ({{ p.sites.map((s) => safeText(s, 80)).join(', ') }})</span> </template></p>
                <div class="hubcols">
                  <div><h3 class="charthead">{{ t('hub.upstream') }}</h3><CodeBlock small :code="detail.yaml || ''" /></div>
                  <div><h3 class="charthead">{{ t('hub.converted') }}</h3>
                    <CodeBlock v-if="detail.ok" small lang="modsec" :code="detail.text" />
                    <p v-else class="alert warn small">{{ tOr('hub.why.' + detail.reason, detail.reason) }}<span v-if="detail.details && Object.keys(detail.details).length" class="mono gapl">{{ safeText(JSON.stringify(detail.details), 200) }}</span></p>
                    <p v-if="detail.ok" class="muted small">{{ t('hub.preview_note', { n: detail.rule_count }) }}</p></div>
                </div>
                <div class="hubuse">
                  <h3 class="charthead"><Icon name="shield" />{{ t('hub.use_title') }}</h3>
                  <p v-if="detail.fp_warning" class="alert warn small"><Icon name="warning" /> {{ t('hub.fp_warning') }}</p>
                  <template v-if="detail.applied">
                    <p class="small">{{ t('hub.applied_on', { sites: detail.applied.hosts.join(', '), from: detail.applied.rule_id,
                                                              to: detail.applied.rule_id + detail.applied.rule_count - 1 }) }}
                      <RouterLink v-if="detail.applied.change_id" class="gapl" :to="'/changes/' + detail.applied.change_id">{{ t('hub.by_change', { id: detail.applied.change_id }) }}</RouterLink></p>
                    <p v-if="detail.applied.upstream !== 'same'" class="alert warn small">{{ t('hub.upstream_' + detail.applied.upstream) }}</p>
                  </template>
                  <p v-if="detail.open_change" class="small"><RouterLink :to="'/changes/' + detail.open_change.change_id">{{ t('hub.open_change', { id: detail.open_change.change_id }) }}</RouterLink></p>
                  <template v-else-if="canPropose">
                    <template v-if="!detail.applied">
                      <p v-if="!detail.ok" class="muted small">{{ t('hub.cannot_propose') }}</p>
                      <p v-else-if="!(detail.tests || []).length" class="muted small">{{ t('hub.no_tests', { why: tOr('hub.why.' + detail.tests_reason, detail.tests_reason || '') }) }}</p>
                      <template v-else>
                        <p class="muted small">{{ t('hub.tests_note', { n: detail.tests.length }) }}</p>
                        <div class="field"><label :for="'hub-site-' + row.name">{{ t('hub.sites') }}</label>
                          <div class="hubsites">
                            <span v-for="h in form.hosts" :key="h" class="chip">{{ safeText(h, 100) }}
                              <button type="button" class="chipx" :aria-label="t('hub.remove_site', { site: h })" @click.stop="form.hosts = form.hosts.filter((x) => x !== h)"><Icon name="close" /></button></span>
                            <SelectBox :id="'hub-site-' + row.name" small :model-value="null" :options="siteOpts" :placeholder="t('hub.add_site')"
                                       @update:model-value="(v) => { if (v && !form.hosts.includes(v)) form.hosts.push(v) }" />
                          </div>
                          <p class="muted small">{{ t('hub.sites_hint') }}</p></div>
                        <div class="field"><label :for="'hub-src-' + row.name">{{ t('hub.source_label') }}</label>
                          <SelectBox :id="'hub-src-' + row.name" v-model="form.source" small :options="[{ value: 'external', label: t('hub.src.external') }, { value: 'all', label: t('hub.src.all') }]" /></div>
                      </template>
                    </template>
                    <div v-if="detail.applied || (detail.ok && (detail.tests || []).length)" class="field">
                      <label :for="'hub-reason-' + row.name">{{ t('hub.reason') }}</label>
                      <textarea :id="'hub-reason-' + row.name" v-model="form.reason" rows="2" maxlength="2000" :placeholder="t('hub.reason_ph')" />
                    </div>
                    <div class="actions">
                      <button v-if="!detail.applied && detail.ok && (detail.tests || []).length" type="button" class="btn primary"
                              :disabled="busy || !form.hosts.length || !form.reason.trim()" @click.stop="propose('add')"><Icon name="add" />{{ t('hub.propose') }}</button>
                      <button v-if="detail.applied && detail.applied.upstream === 'changed' && detail.ok" type="button" class="btn primary"
                              :disabled="busy || !form.reason.trim()" @click.stop="propose('modify')"><Icon name="refresh" />{{ t('hub.update') }}</button>
                      <button v-if="detail.applied" type="button" class="btn danger" :disabled="busy || !form.reason.trim()" @click.stop="propose('delete')"><Icon name="delete" />{{ t('hub.remove') }}</button>
                    </div>
                  </template>
                  <ErrorBox :error="proposeError" />
                </div>
              </template>
            </div>
          </template>
        </DataTable>
      </section>
      <p v-else-if="!data.commit" class="alert info">{{ t('hub.empty') }}</p>
      <section v-if="(data.applied_removed || []).length" class="card attention">
        <h2><Icon name="warning" /> {{ t('hub.removed_title') }}</h2>
        <p class="small">{{ t('hub.removed_hint') }}</p>
        <ul class="small">
          <li v-for="a in data.applied_removed" :key="a.name"><span class="mono">{{ safeText(a.name, 120) }}</span> ({{ a.hosts.join(', ') }})
            <RouterLink v-if="a.open_change" class="gapl" :to="'/changes/' + a.open_change.change_id">{{ t('hub.open_change', { id: a.open_change.change_id }) }}</RouterLink>
            <button v-else-if="canPropose" type="button" class="btn small danger gapl" :disabled="busy" @click="removeGone(a)"><Icon name="delete" />{{ t('hub.remove') }}</button></li>
        </ul>
        <ErrorBox :error="proposeError" />
      </section>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { get, post } from '../api.js'
import { t, tOr } from '../i18n.js'
import { hasRole } from '../store.js'
import { fmtMinute, fmtNum, safeText } from '../util.js'
import { uploadInParts } from '../upload.js'
import Icon from '../components/Icon.vue'
import Loading from '../components/Loading.vue'
import ErrorBox from '../components/ErrorBox.vue'
import DataTable from '../components/DataTable.vue'
import CodeBlock from '../components/CodeBlock.vue'
import SelectBox from '../components/SelectBox.vue'

const router = useRouter()
const canPropose = computed(() => hasRole('operator'))
const form = reactive({ hosts: [], source: 'external', reason: '' })
const proposeError = ref(null)
const sites = ref([])
const siteOpts = computed(() => sites.value.filter((n) => !form.hosts.includes(n)))

const data = ref(null)
const error = ref(null)
const actionError = ref(null)
const busy = ref(false)
const progress = ref('')
const open = ref(null)
const detail = ref(null)
const showLicense = ref(false)
const license = ref('')
const filter = ref('related')
const FILTERS = ['related', 'applied', 'convertible', 'unsupported', 'all']
const FILTER_ICON = { related: 'server', applied: 'shield', convertible: 'check', unsupported: 'warning', all: 'list' }
const isAdmin = computed(() => hasRole('admin'))

const shown = computed(() => {
  const rs = (data.value && data.value.rules) || []
  if (filter.value === 'related') return rs.filter((r) => r.related.length)
  if (filter.value === 'applied') return rs.filter((r) => r.applied || r.open_change)
  if (filter.value === 'convertible') return rs.filter((r) => r.ok)
  if (filter.value === 'unsupported') return rs.filter((r) => !r.ok)
  return rs
})
const tiles = computed(() => {
  const d = data.value || {}
  const c = d.counts || {}
  const rs = d.rules || []
  return [
    { key: 'total', icon: 'list', label: t('hub.t_total'), value: c.total || 0, sub: t('hub.t_total_sub'), cls: 't-events' },
    { key: 'ok', icon: 'check', label: t('hub.t_ok'), value: c.convertible || 0, sub: t('hub.t_ok_sub'), cls: 't-ok' },
    { key: 'no', icon: 'warning', label: t('hub.t_no'), value: c.unsupported || 0, sub: t('hub.t_no_sub'), cls: 't-warn' },
    { key: 'rel', icon: 'server', label: t('hub.t_related'), value: d.related_count || 0, sub: t('hub.t_related_sub'), cls: 't-ext' },
    { key: 'new', icon: 'timer', label: t('hub.t_new'), value: rs.filter((r) => r.change === 'new' || r.change === 'changed').length,
      sub: t('hub.t_new_sub', { n: (d.removed || []).length }), cls: 't-int' },
    { key: 'applied', icon: 'shield', label: t('hub.t_applied'), value: d.applied_count || 0,
      sub: t('hub.t_applied_sub', { n: d.outdated_count || 0 }), cls: d.outdated_count ? 't-warn' : 't-ok' },
  ]
})
const cols = computed(() => [
  { key: 'name', label: t('hub.c_name'), class: 'c-name' },
  { key: 'cves', label: 'CVE', nowrap: true, text: (r) => r.cves.join(' ') },
  { key: 'label', label: t('hub.c_label'), class: 'c-fill', text: (r) => r.label || r.description || '' },
  { key: 'related', label: t('hub.c_related'), text: (r) => r.related.map((p) => p.name).join(' ') },
  { key: 'ok', label: t('hub.c_state'), nowrap: true, text: (r) => (r.ok ? t('hub.convertible') : t('hub.unsupported')) },
  { key: 'use', label: t('hub.c_use'), nowrap: true, text: (r) => useText(r) },
])
function useText(r) {
  if (r.open_change) return t('hub.use.open', { id: r.open_change.change_id })
  if (!r.applied) return ''
  return r.applied.upstream === 'same' ? t('hub.use.applied') : t('hub.use.' + r.applied.upstream)
}

function sourceText(s) { return s === 'github' ? t('hub.from_github') : t('hub.from_upload', { name: safeText(s.replace(/^upload:?/, ''), 100) }) }
async function load() {
  try { data.value = await get('/hub'); error.value = null } catch (e) { error.value = e }
}
async function openRule(r) {
  open.value = open.value === r.name ? null : r.name
  if (!open.value) return
  detail.value = null
  proposeError.value = null
  try {
    detail.value = await get('/hub/rule', { name: r.name })
    const d = detail.value
    form.hosts = d.applied ? [...d.applied.hosts] : [...new Set(d.related.flatMap((p) => p.sites || []))]
    form.source = (d.applied && d.applied.source) || 'external'
    form.reason = ''
    if (canPropose.value && !sites.value.length) loadSites()
  } catch (e) { actionError.value = e }
}
async function loadSites() {
  try {
    const v = await get('/vhosts')
    const names = new Set()
    for (const s of v.items || []) for (const n of s.server_names || []) if (n && n !== '_' && !n.startsWith('~')) names.add(n.toLowerCase())
    sites.value = [...names].sort()
  } catch (e) { /* the related sites are enough to propose */ }
}
async function propose(op) {
  const d = detail.value
  busy.value = true
  proposeError.value = null
  try {
    const body = op === 'add'
      ? { op, kind: 'crowdsec', spec: { name: d.name, hosts: form.hosts, source: form.source }, reason: form.reason.trim() }
      : { op, item_id: d.applied.item_id, spec: {}, reason: form.reason.trim() }
    const r = await post('/changes', body)
    router.push('/changes/' + r.change_id)
  } catch (e) { proposeError.value = e } finally { busy.value = false }
}
async function removeGone(a) {
  busy.value = true
  proposeError.value = null
  try {
    const r = await post('/changes', { op: 'delete', item_id: a.item_id, spec: {}, reason: t('hub.removed_reason', { name: a.name }) })
    router.push('/changes/' + r.change_id)
  } catch (e) { proposeError.value = e } finally { busy.value = false }
}
async function toggleLicense() {
  showLicense.value = !showLicense.value
  if (showLicense.value && !license.value) {
    try { license.value = (await get('/hub/license')).license || '' } catch (e) { actionError.value = e }
  }
}
async function syncNow() {
  busy.value = true
  actionError.value = null
  try { await post('/hub/sync') } catch (e) { actionError.value = e } finally { busy.value = false; load() }
}
async function upload(ev) {
  const f = ev.target.files && ev.target.files[0]
  ev.target.value = ''
  if (!f) return
  busy.value = true
  actionError.value = null
  try {
    await uploadInParts('hub', f, {}, (sent, total) => { progress.value = t('hub.uploading', { p: Math.round((sent / total) * 100) }) })
    progress.value = t('hub.uploaded')
  } catch (e) { actionError.value = e; progress.value = '' } finally { busy.value = false; load() }
}
let timer = null
onMounted(() => { load(); timer = setInterval(() => { if (data.value && data.value.requested) load() }, 5000) })
// "sync now" / an upload: keep looking until the job has answered
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.hubtiles { margin: 0 0 14px; }
.hubname { white-space: nowrap; }
:deep(td.c-name) { min-width: 17em; }
.hubacts { align-items: center; flex-wrap: wrap; margin-top: 14px; }
.uphint { margin: 8px 0 0; }
.filebtn { position: relative; overflow: hidden; }
.filebtn input { position: absolute; inset: 0; opacity: 0; cursor: pointer; }
.hubdetail { display: flex; flex-direction: column; gap: 8px; }
.hubcols { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.hubcols :deep(pre) { max-height: 420px; overflow: auto; }
.gapr { margin-right: 10px; }
.hubuse { border-top: 1px solid var(--border); padding-top: 10px; display: flex; flex-direction: column; gap: 8px; }
.hubuse .field { max-width: 720px; }
.hubsites { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.chipx { border: 0; background: none; padding: 0 0 0 4px; cursor: pointer; color: inherit; line-height: 1; }
@media (max-width: 900px) { .hubcols { grid-template-columns: minmax(0, 1fr); } }
</style>
