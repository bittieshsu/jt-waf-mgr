<!-- CrowdSec virtual patching rules: the CrowdSec Hub's appsec rules (MIT), read and converted into ModSecurity rules
     on this host. Read-only for now: which rules exist, which convert (and why not), which name software of this site. -->
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
              </template>
            </div>
          </template>
        </DataTable>
      </section>
      <p v-else-if="!data.commit" class="alert info">{{ t('hub.empty') }}</p>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
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
const FILTERS = ['related', 'convertible', 'unsupported', 'all']
const FILTER_ICON = { related: 'server', convertible: 'check', unsupported: 'warning', all: 'list' }
const isAdmin = computed(() => hasRole('admin'))

const shown = computed(() => {
  const rs = (data.value && data.value.rules) || []
  if (filter.value === 'related') return rs.filter((r) => r.related.length)
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
  ]
})
const cols = computed(() => [
  { key: 'name', label: t('hub.c_name'), class: 'c-name' },
  { key: 'cves', label: 'CVE', nowrap: true, text: (r) => r.cves.join(' ') },
  { key: 'label', label: t('hub.c_label'), class: 'c-fill', text: (r) => r.label || r.description || '' },
  { key: 'related', label: t('hub.c_related'), text: (r) => r.related.map((p) => p.name).join(' ') },
  { key: 'ok', label: t('hub.c_state'), nowrap: true, text: (r) => (r.ok ? t('hub.convertible') : t('hub.unsupported')) },
])

function sourceText(s) { return s === 'github' ? t('hub.from_github') : t('hub.from_upload', { name: safeText(s.replace(/^upload:?/, ''), 100) }) }
async function load() {
  try { data.value = await get('/hub'); error.value = null } catch (e) { error.value = e }
}
async function openRule(r) {
  open.value = open.value === r.name ? null : r.name
  if (!open.value) return
  detail.value = null
  try { detail.value = await get('/hub/rule', { name: r.name }) } catch (e) { actionError.value = e }
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
@media (max-width: 900px) { .hubcols { grid-template-columns: minmax(0, 1fr); } }
</style>
