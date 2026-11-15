<!-- Settings > Export and import: every setting of this page as one JSON file, and back. Export leaves the keys and
     passwords out unless asked for with a fresh one-time code. Import shows the file next to the current values
     first; only the settings ticked are written (all or none, a fresh one-time code, each audited). -->
<template>
  <section class="card" id="settings-transfer">
    <h2><Icon name="backup" /> {{ t('setio.title') }}</h2>
    <p class="muted small">{{ t('setio.intro') }}</p>
    <div class="setio-row">
      <label class="check"><input v-model="withSecrets" type="checkbox" /> {{ t('setio.with_secrets') }}</label>
      <div v-if="withSecrets" class="field"><label for="setio-otp-ex">{{ t('setio.otp') }}</label>
        <input id="setio-otp-ex" v-model="otpEx" class="mono otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" /></div>
      <button type="button" class="btn small" :disabled="busy || (withSecrets && otpEx.length !== 6)" @click="doExport"><Icon name="download" />{{ t('setio.export') }}</button>
      <span class="setio-sep" aria-hidden="true"></span>
      <label class="btn small filepick"><Icon name="upload" />{{ fileName || t('setio.choose') }}
        <input type="file" accept=".json,application/json" class="sr-only" @change="pick" /></label>
    </div>
    <ErrorBox :error="error" />
    <p v-if="done" class="alert success small" role="status"><Icon name="check" /> {{ done }}</p>
    <template v-if="pv">
      <p class="small">{{ t('setio.file_facts', { version: pv.file.version || '—', node: pv.file.node_id || '—', at: pv.file.exported_at ? fmtMinute(pv.file.exported_at) : '—' }) }}
        <span v-if="pv.file.with_secrets" class="badge b-warn gapl">{{ t('setio.has_secrets') }}</span></p>
      <div class="setio-row">
        <span class="small">{{ t('setio.picked', { n: picked.size, of: pickable.length }) }}</span>
        <button type="button" class="btn small ghost" @click="pickDifferent"><Icon name="check" />{{ t('setio.pick_different') }}</button>
        <button type="button" class="btn small ghost" @click="pickAll"><Icon name="check" />{{ t('setio.pick_all') }}</button>
        <button type="button" class="btn small ghost" @click="picked = new Set()"><Icon name="clear" />{{ t('setio.pick_none') }}</button>
        <label class="check small"><input v-model="onlyDiff" type="checkbox" /> {{ t('setio.only_different') }}</label>
        <SelectBox v-model="groupPick" :options="groupOpts" small :aria-label="t('setio.pick_group')" @update:model-value="pickGroup" />
      </div>
      <DataTable id="settings-import" :columns="cols" :rows="shownRows" :row-key="(r) => r.area + ':' + r.key" :page-size="50"
                 :row-class="(r) => (r.same || !r.valid ? 'setio-dim' : null)">
        <template #cell-sel="{ row }"><input type="checkbox" :disabled="!row.valid" :checked="picked.has(id(row))"
                 :aria-label="t('setio.pick_one', { key: row.key })" @change="toggle(row)" /></template>
        <template #cell-key="{ row }"><span>{{ label(row) }}</span><div class="mono muted small">{{ row.area === 'workflow' ? 'workflow.' : '' }}{{ row.key }}</div></template>
        <template #cell-current="{ row }"><span class="mono small setio-val">{{ show(row.current) }}</span></template>
        <template #cell-incoming="{ row }"><span class="mono small setio-val">{{ show(row.incoming) }}</span></template>
        <template #cell-state="{ row }">
          <span v-if="!row.known" class="badge b-logged">{{ t('setio.unknown') }}</span>
          <span v-else-if="!row.valid" class="badge b-blocked">{{ t('setio.invalid') }}</span>
          <span v-else-if="row.same" class="badge b-logged">{{ t('setio.same') }}</span>
          <span v-else class="badge b-warn">{{ t('setio.differs') }}</span>
          <div v-if="row.needs && picked.has(id(row))" class="sub warn">{{ t('setio.needs_key') }}</div>
        </template>
      </DataTable>
      <div class="setio-row">
        <div class="field"><label for="setio-otp-im">{{ t('setio.otp') }}</label>
          <input id="setio-otp-im" v-model="otpIm" class="mono otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" /></div>
        <button type="button" class="btn small primary" :disabled="busy || !picked.size || otpIm.length !== 6" @click="doImport"><Icon name="save" />{{ t('setio.apply', { n: picked.size }) }}</button>
      </div>
    </template>
  </section>
</template>

<script setup>
import { computed, ref } from 'vue'
import { api } from '../api.js'
import { t, tOr } from '../i18n.js'
import { downloadText, fmtMinute, stamp } from '../util.js'
import Icon from './Icon.vue'
import ErrorBox from './ErrorBox.vue'
import DataTable from './DataTable.vue'
import SelectBox from './SelectBox.vue'

const emit = defineEmits(['saved'])
const withSecrets = ref(false)
const otpEx = ref('')
const otpIm = ref('')
const busy = ref(false)
const error = ref(null)
const done = ref('')
const fileName = ref('')
const data = ref(null)
const pv = ref(null)
const picked = ref(new Set())
const groupPick = ref('')
const onlyDiff = ref(true)
const shownRows = computed(() => (pv.value ? pv.value.items.filter((r) => !onlyDiff.value || !r.same) : []))
function groupLabel(g) { return g === 'workflow' ? t('setio.workflow') : tOr('uiset.group.' + g, tOr('setio.g.' + g, g)) }

function id(r) { return r.area + ':' + r.key }
// workflow keys: their labels are "wfs.<name>" (sandbox.required -> wfs.sandbox_required, apply.auto_tighten -> wfs.auto_tighten)
const WF_LABEL = { 'sandbox.required': 'wfs.sandbox_required', 'health.urls': 'wfs.health_urls' }
function label(r) {
  if (r.area !== 'workflow') return tOr('uiset.' + r.key, r.key)
  return tOr(WF_LABEL[r.key] || 'wfs.' + r.key.split('.').slice(1).join('_'), r.key)
}
function show(v) {
  if (v === null || v === undefined || v === '') return '—'
  const s = typeof v === 'string' ? v : JSON.stringify(v)
  return s.length > 120 ? s.slice(0, 119) + '…' : s
}
const pickable = computed(() => (pv.value ? pv.value.items.filter((r) => r.valid) : []))
const groupOpts = computed(() => {
  const gs = [...new Set(pickable.value.map((r) => r.group))].sort()
  return [{ value: '', label: t('setio.pick_group') }].concat(gs.map((g) => ({ value: g, label: groupLabel(g) })))
})
const cols = computed(() => [
  { key: 'sel', label: '', sortable: false, required: true, nowrap: true, text: () => '' },
  { key: 'group', label: t('setio.col.group'), nowrap: true, value: (r) => groupLabel(r.group) },
  { key: 'key', label: t('setio.col.setting'), text: (r) => label(r) + ' ' + r.key },
  { key: 'current', label: t('setio.col.current'), class: 'c-fill', value: (r) => show(r.current) },
  { key: 'incoming', label: t('setio.col.incoming'), value: (r) => show(r.incoming) },
  { key: 'state', label: t('setio.col.state'), nowrap: true, value: (r) => (!r.known ? 3 : !r.valid ? 2 : r.same ? 1 : 0) },
])
function toggle(r) { const s = new Set(picked.value); s.has(id(r)) ? s.delete(id(r)) : s.add(id(r)); picked.value = s }
function pickDifferent() { picked.value = new Set(pickable.value.filter((r) => !r.same).map(id)) }
function pickAll() { picked.value = new Set(pickable.value.map(id)) }
function pickGroup(g) {
  if (!g) return
  const s = new Set(picked.value)
  for (const r of pickable.value) if (r.group === g) s.add(id(r))
  picked.value = s
  groupPick.value = ''
}

async function doExport() {
  busy.value = true; error.value = null; done.value = ''
  try {
    const body = withSecrets.value ? { secrets: true, totp: otpEx.value } : {}
    const d = await api('POST', '/settings/export', { body })
    downloadText('jt-waf-mgr-settings-' + (d.node_id || 'node') + '-' + stamp() + (d.with_secrets ? '-with-secrets' : '') + '.json',
                 JSON.stringify(d, null, 1), 'application/json')
    otpEx.value = ''
  } catch (e) { error.value = e } finally { busy.value = false }
}
async function pick(e) {
  const f = e.target.files && e.target.files[0]
  e.target.value = ''
  if (!f) return
  error.value = null; done.value = ''; pv.value = null
  fileName.value = f.name
  try {
    if (f.size > 2 * 1024 * 1024) throw new Error(t('setio.too_large'))
    data.value = JSON.parse(await f.text())
    pv.value = await api('POST', '/settings/import/preview', { body: { file: data.value } })
    pickDifferent()
  } catch (err) { error.value = err instanceof SyntaxError ? new Error(t('setio.not_json')) : err }
}
async function doImport() {
  busy.value = true; error.value = null; done.value = ''
  try {
    const r = await api('POST', '/settings/import', { body: { file: data.value, keys: [...picked.value], totp: otpIm.value } })
    const n = r.changed.settings.length + r.changed.workflow.length
    done.value = t('setio.done', { n })
    otpIm.value = ''
    pv.value = await api('POST', '/settings/import/preview', { body: { file: data.value } })
    picked.value = new Set()
    emit('saved')
  } catch (e) { error.value = e } finally { busy.value = false }
}
</script>

<style scoped>
.setio-row { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 10px; margin: 8px 0; }
.setio-row .field { margin: 0; }
.setio-sep { width: 1px; align-self: stretch; background: var(--border); margin: 0 4px; }
.otp { width: 8em; }
.setio-val { overflow-wrap: anywhere; }
:deep(tr.setio-dim td) { opacity: .62; }
</style>
