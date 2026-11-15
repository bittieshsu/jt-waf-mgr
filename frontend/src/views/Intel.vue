<!-- Threat intelligence: the second-tier LLM searches the web for new vulnerabilities in the software list a person
     confirmed. Only product names and versions leave the host. What the model and web pages say is shown as text. -->
<template>
  <div class="page">
    <div class="pagehead">
      <h1>{{ t('intel.title') }}</h1>
      <RouterLink v-if="isAdmin" class="btn small ghost" to="/admin/settings#uiset-intel"><Icon name="settings" />{{ t('intel.settings') }}</RouterLink>
      <button v-if="isApprover" class="btn small primary" type="button" :disabled="busy || !st || !st.ready || st.requested" @click="runNow"><Icon name="search" />{{ t('intel.run_now') }}</button>
      <button class="btn small ghost" type="button" :disabled="busy" @click="load"><Icon name="refresh" />{{ t('common.refresh') }}</button>
    </div>
    <p class="muted">{{ t('intel.intro') }}</p>
    <ErrorBox :error="error" />
    <Loading v-if="!data && !error" />

    <template v-if="data">
      <!-- how it is set up, what it costs -->
      <section class="card">
        <h2><Icon name="ai" /> {{ t('intel.status') }}</h2>
        <p v-if="!st.ready" class="alert info">{{ tOr('intel.not_ready.' + st.not_ready_reason, st.not_ready_reason) }}</p>
        <p v-else-if="st.over_budget" class="alert warn">{{ t('intel.over_budget') }}</p>
        <p v-if="!st.confirmed_software" class="alert warn">{{ t('intel.no_software') }}</p>
        <dl class="kv two">
          <dt>{{ t('intel.provider') }}</dt><dd>{{ t('intel.provider_v.' + st.provider) }}<span v-if="st.model" class="mono small gapl">{{ st.model }}</span>
            <div v-if="st.uses_first_tier" class="muted small">{{ t('intel.first_tier') }}</div></dd>
          <dt>{{ t('intel.search') }}</dt><dd>{{ t('intel.search_v.' + st.search) }}</dd>
          <dt>{{ t('intel.schedule') }}</dt><dd>{{ t('intel.schedule_v', { h: st.interval_hours, d: st.days }) }}
            <span v-if="st.requested" class="badge b-warn gapl">{{ t('countries.queued') }}</span></dd>
          <dt>{{ t('intel.tokens') }}</dt><dd>{{ t('intel.tokens_v', { d: fmtNum(st.tokens.day), dl: st.daily_tokens ? fmtNum(st.daily_tokens) : '∞', m: fmtNum(st.tokens.month), ml: st.monthly_tokens ? fmtNum(st.monthly_tokens) : '∞' }) }}</dd>
          <dt>{{ t('intel.last_run') }}</dt><dd><template v-if="st.last_run">{{ fmtMinute(st.last_run.started_at) }}
            <span class="badge gapl" :class="st.last_run.error ? 'b-blocked' : 'b-ok'">{{ st.last_run.error ? t('result.failed') : t('intel.found', { n: st.last_run.threats }) }}</span>
            <div v-if="st.last_run.error" class="small warn">{{ safeText(st.last_run.error, 300) }}</div></template><span v-else class="muted">—</span></dd>
        </dl>
      </section>

      <!-- what was found -->
      <section class="card">
        <div class="cardhead">
          <h2><Icon name="alert" /> {{ t('intel.threats') }}</h2>
          <span class="muted small">{{ t('intel.threats_open', { n: openCount }) }}</span>
        </div>
        <p class="muted small">{{ t('intel.threats_hint') }}</p>
        <DataTable id="intel-threats" :columns="threatCols" :rows="data.threats" row-key="threat_id" :page-size="25" :empty="t('intel.no_threats')"
                   :expanded="openThreat" clickable @row-click="(r) => openThreat = openThreat === r.threat_id ? null : r.threat_id">
          <template #cell-id="{ row }"><span class="mono">{{ row.id }}</span></template>
          <template #cell-product="{ row }">{{ row.product }} <span class="mono small muted">{{ row.our_version }}</span></template>
          <template #cell-flags="{ row }">
            <span v-if="row.exploited" class="badge b-blocked">{{ t('intel.exploited') }}</span>
            <span v-else-if="row.exploited_claimed" class="badge b-warn" :title="t('intel.claimed_hint')">{{ t('intel.claimed') }}</span>
            <span class="badge" :class="AFF[row.affected]">{{ t('intel.affected.' + row.affected) }}</span></template>
          <template #cell-severity="{ row }"><span class="badge" :class="SEV[row.severity] || 'b-logged'">{{ tOr('intel.sev.' + row.severity, row.severity) }}</span></template>
          <template #cell-first_seen="{ row }">{{ fmtMinute(row.first_seen) }}</template>
          <template #cell-status="{ row }"><span class="badge" :class="row.status === 'open' ? 'b-warn' : 'b-logged'">{{ t('intel.st.' + row.status) }}</span></template>
          <template #expand="{ row }">
            <div class="thdetail">
              <p>{{ row.summary }}</p>
              <dl class="kv two">
                <dt>{{ t('intel.affected_versions') }}</dt><dd class="mono">{{ row.affected_versions || '—' }}</dd>
                <dt>{{ t('intel.fixed_version') }}</dt><dd class="mono">{{ row.fixed_version || '—' }}</dd>
                <dt>{{ t('intel.vector') }}</dt><dd>{{ tOr('intel.vec.' + row.attack_vector, row.attack_vector) }}</dd>
                <dt>{{ t('intel.pattern') }}</dt><dd>{{ row.request_pattern || '—' }}</dd>
                <dt v-if="row.exploited">{{ t('intel.evidence') }}</dt><dd v-if="row.exploited">{{ row.exploited_evidence || '—' }}</dd>
                <dt>{{ t('intel.patch') }}</dt><dd>
                  <RouterLink v-if="row.patch_change_id" :to="'/changes/' + row.patch_change_id">{{ t('intel.patch_change', { id: row.patch_change_id }) }}</RouterLink>
                  <span v-else-if="row.patch_note" class="muted">{{ tOr('intel.patch_note.' + row.patch_note, row.patch_note) }}</span>
                  <span v-else class="muted">{{ ['url', 'header'].includes(row.attack_vector) ? t('intel.patch_pending') : t('intel.patch_none') }}</span></dd>
                <dt>{{ t('intel.seen') }}</dt><dd>{{ fmtMinute(row.first_seen) }} – {{ fmtMinute(row.last_seen) }}</dd>
              </dl>
              <!-- links the model gave: the site is shown first, so a look-alike domain stands out -->
              <ul class="refs"><li v-for="u in row.references" :key="u"><b class="small">{{ hostOf(u) }}</b>
                <a :href="u" target="_blank" rel="noopener noreferrer nofollow" class="mono small breakall gapl"><Icon name="external" />{{ u }}</a></li></ul>
              <div v-if="isApprover" class="actions">
                <button v-if="row.status !== 'handled'" type="button" class="btn small" :disabled="busy" @click.stop="setStatus(row, 'handled')"><Icon name="check" />{{ t('intel.mark_handled') }}</button>
                <button v-if="row.status !== 'ignored'" type="button" class="btn small ghost" :disabled="busy" @click.stop="setStatus(row, 'ignored')"><Icon name="hide" />{{ t('intel.mark_ignored') }}</button>
                <button v-if="row.status !== 'open'" type="button" class="btn small ghost" :disabled="busy" @click.stop="setStatus(row, 'open')"><Icon name="rollback" />{{ t('intel.reopen') }}</button>
              </div>
            </div>
          </template>
        </DataTable>
      </section>

      <!-- the software list: the program guesses, a person confirms -->
      <section class="card">
        <div class="cardhead">
          <h2><Icon name="server" /> {{ t('intel.software') }}</h2>
          <span v-if="isApprover" class="rowbtns">
            <button v-if="waiting > 0" class="btn small primary" type="button" :disabled="busy" @click="confirmAll"><Icon name="check" />{{ t('intel.confirm_all', { n: waiting }) }}</button>
            <button class="btn small" type="button" :disabled="busy" @click="guess"><Icon name="refresh" />{{ t('intel.guess') }}</button>
          </span>
        </div>
        <p class="muted small">{{ t('intel.software_hint') }}</p>
        <p v-if="guessMsg" class="muted small" role="status">{{ guessMsg }}</p>
        <DataTable id="intel-software" :columns="swCols" :rows="data.software" row-key="id" :page-size="50" :empty="t('intel.no_software_rows')">
          <template #cell-name="{ row }"><b>{{ row.name }}</b><div v-if="row.evidence" class="sub muted"><TruncText :text="row.evidence" :max="120" /></div></template>
          <template #cell-version="{ row }"><span class="mono">{{ row.version || '—' }}</span></template>
          <template #cell-hosts="{ row }"><span class="small">{{ row.kind === 'host' ? t('intel.this_host') : (row.hosts.join(', ') || '—') }}</span></template>
          <template #cell-confirmed="{ row }"><span class="badge" :class="row.confirmed ? 'b-ok' : 'b-warn'">{{ row.confirmed ? t('intel.confirmed') : t('intel.unconfirmed') }}</span>
            <span class="muted small gapl">{{ t('intel.source.' + row.source) }}</span></template>
          <template #cell-act="{ row }">
            <span v-if="isApprover" class="rowbtns">
              <button v-if="!row.confirmed" type="button" class="btn tiny" :disabled="busy" @click="confirm(row)"><Icon name="check" />{{ t('intel.confirm') }}</button>
              <button type="button" class="btn tiny ghost" :disabled="busy" @click="startEdit(row)"><Icon name="edit" />{{ t('common.edit') }}</button>
              <button type="button" class="btn tiny danger" :disabled="busy" @click="remove(row)"><Icon name="delete" />{{ t('common.delete') }}</button>
            </span></template>
        </DataTable>
        <form v-if="isApprover" class="swform" @submit.prevent="saveSw">
          <h3><Icon :name="edit.id ? 'edit' : 'add'" /> {{ edit.id ? t('intel.edit_title', { name: edit.orig }) : t('intel.add_title') }}</h3>
          <div class="filters">
            <label class="field"><span>{{ t('intel.name') }}</span><input v-model.trim="edit.name" maxlength="120" placeholder="Keycloak"></label>
            <label class="field"><span>{{ t('intel.version_optional') }}</span><input v-model.trim="edit.version" class="mono" maxlength="60" placeholder="26.0.5"></label>
            <label class="field grow"><span>{{ t('intel.hosts') }}</span><input v-model.trim="edit.hosts" class="mono" maxlength="2000" placeholder="sso.example.com"></label>
          </div>
          <div class="actions">
            <button type="submit" class="btn primary small" :disabled="busy || !edit.name"><Icon name="save" />{{ edit.id ? t('common.save') : t('intel.add') }}</button>
            <button v-if="edit.id" type="button" class="btn ghost small" @click="resetEdit"><Icon name="cancel" />{{ t('common.cancel') }}</button>
          </div>
        </form>
      </section>

      <!-- each search: what was asked and read -->
      <section class="card">
        <h2><Icon name="history" /> {{ t('intel.runs') }}</h2>
        <DataTable id="intel-runs" :columns="runCols" :rows="data.runs" row-key="id" :page-size="10" :empty="t('intel.no_runs')"
                   :expanded="openRun" clickable @row-click="(r) => openRun = openRun === r.id ? null : r.id">
          <template #cell-started_at="{ row }">{{ fmtMinute(row.started_at) }}</template>
          <template #cell-result="{ row }"><span class="badge" :class="row.error ? 'b-blocked' : 'b-ok'">{{ row.error ? t('result.failed') : t('intel.found', { n: row.threats }) }}</span>
            <span v-if="row.note" class="muted small gapl">{{ safeText(row.note, 80) }}</span></template>
          <template #expand="{ row }">
            <div class="thdetail">
              <p v-if="row.error" class="small warn">{{ safeText(row.error, 300) }}</p>
              <h4>{{ t('intel.searched', { n: row.searches.length }) }}</h4>
              <ul class="refs"><li v-for="(q, i) in row.searches" :key="'q' + i" class="small">{{ q }}</li></ul>
              <h4>{{ t('intel.read', { n: row.fetched.length }) }}</h4>
              <ul class="refs"><li v-for="(u, i) in row.fetched" :key="'u' + i" class="mono small breakall">{{ u }}</li></ul>
            </div>
          </template>
        </DataTable>
      </section>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { del, get, patch, post } from '../api.js'
import { t, tOr } from '../i18n.js'
import { hasRole } from '../store.js'
import { fmtMinute, fmtNum, safeText } from '../util.js'
import Icon from '../components/Icon.vue'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import DataTable from '../components/DataTable.vue'
import TruncText from '../components/TruncText.vue'

const data = ref(null)
const error = ref(null)
const busy = ref(false)
const guessMsg = ref('')
const openThreat = ref(null)
const openRun = ref(null)
const isApprover = computed(() => hasRole('approver'))
const isAdmin = computed(() => hasRole('admin'))
const st = computed(() => data.value && data.value.status)
const openCount = computed(() => (data.value ? data.value.threats.filter((x) => x.status === 'open').length : 0))
function hostOf(u) { try { return new URL(u).hostname } catch { return '' } }
const SEV = { critical: 'b-blocked', high: 'b-blocked', medium: 'b-warn', low: 'b-logged', unknown: 'b-logged' }
const AFF = { yes: 'b-blocked', no: 'b-ok', unknown: 'b-logged' }
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 }

const threatCols = computed(() => [
  { key: 'id', label: t('intel.col.id') },
  { key: 'product', label: t('intel.col.product'), text: (r) => r.product + ' ' + (r.our_version || '') },
  { key: 'flags', label: t('intel.col.flags'), value: (r) => (r.exploited ? 0 : 2) + (r.affected === 'yes' ? 0 : 1), text: (r) => (r.exploited ? t('intel.exploited') + ' ' : '') + t('intel.affected.' + r.affected) },
  { key: 'severity', label: t('intel.col.severity'), value: (r) => SEV_ORDER[r.severity] ?? 9, text: (r) => tOr('intel.sev.' + r.severity, r.severity) },
  { key: 'first_seen', label: t('intel.col.first_seen'), value: (r) => r.first_seen, text: (r) => fmtMinute(r.first_seen) },
  { key: 'status', label: t('intel.col.status'), value: (r) => r.status, text: (r) => t('intel.st.' + r.status) },
])
const swCols = computed(() => [
  { key: 'name', label: t('intel.name'), required: true },
  { key: 'version', label: t('intel.version') },
  { key: 'hosts', label: t('intel.hosts'), value: (r) => (r.kind === 'host' ? '' : r.hosts.join(' ')) },
  { key: 'confirmed', label: t('intel.col.confirmed'), value: (r) => (r.confirmed ? 1 : 0) },
  { key: 'act', label: '', sortable: false, filterable: false },
])
const runCols = computed(() => [
  { key: 'id', label: '#', align: 'num' },
  { key: 'started_at', label: t('intel.col.time'), value: (r) => r.started_at },
  { key: 'trigger', label: t('intel.col.trigger'), value: (r) => tOr('review.trigger.' + r.trigger, r.trigger) },
  { key: 'model', label: t('intel.col.model') },
  { key: 'tokens', label: t('intel.col.tokens'), align: 'num', value: (r) => r.tokens_in + r.tokens_out },
  { key: 'result', label: t('intel.col.result'), value: (r) => (r.error ? -1 : r.threats) },
])

const edit = reactive({ id: null, orig: '', name: '', version: '', hosts: '' })
function resetEdit() { Object.assign(edit, { id: null, orig: '', name: '', version: '', hosts: '' }) }
function startEdit(r) { Object.assign(edit, { id: r.id, orig: r.name, name: r.name, version: r.version, hosts: r.hosts.join(', ') }) }
const hostList = () => edit.hosts.split(/[\s,]+/).filter(Boolean)

async function load() {
  error.value = null
  try { data.value = await get('/intel') } catch (e) { error.value = e }
}
async function act(fn) {
  busy.value = true
  error.value = null
  try { await fn() } catch (e) { error.value = e } finally { busy.value = false }
}
const runNow = () => act(async () => { data.value.status = await post('/intel/run', {}) })
const guess = () => act(async () => {
  const r = await post('/intel/software/guess', {})
  data.value.software = r.software
  guessMsg.value = t('intel.guessed', { added: r.added, updated: r.updated, removed: r.removed || 0 })
})
const confirm = (r) => act(async () => { data.value.software = (await patch('/intel/software/' + r.id, { confirmed: true })).software })
const waiting = computed(() => ((data.value && data.value.software) || []).filter((r) => !r.confirmed).length)
const confirmAll = () => act(async () => {
  if (!window.confirm(t('intel.confirm_all_ask', { n: waiting.value }))) return
  const r = await post('/intel/software/confirm-all', {})
  data.value.software = r.software
  guessMsg.value = t('intel.confirmed_n', { n: r.confirmed })
})
const remove = (r) => act(async () => {
  if (!window.confirm(t('intel.delete_confirm', { name: r.name }))) return
  data.value.software = (await del('/intel/software/' + r.id)).software
})
const saveSw = () => act(async () => {
  const body = { name: edit.name, version: edit.version, hosts: hostList(), confirmed: true }
  const r = edit.id ? await patch('/intel/software/' + edit.id, body) : await post('/intel/software', body)
  data.value.software = r.software
  resetEdit()
})
const setStatus = (row, status) => act(async () => { data.value.threats = (await post('/intel/threats/' + row.threat_id, { status })).threats })
onMounted(load)
</script>

<style scoped>
.thdetail { display: flex; flex-direction: column; gap: 8px; }
.thdetail p { margin: 0; }
.thdetail h4 { margin: 6px 0 0; font-size: 13.5px; }
.refs { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 3px; }
.refs a { display: inline-flex; gap: 4px; align-items: center; }
.rowbtns { display: inline-flex; gap: 6px; flex-wrap: wrap; }
.swform { margin-top: 14px; border-top: 1px solid var(--border); padding-top: 12px; }
.swform h3 { margin: 0 0 8px; font-size: 15px; }
</style>
