<!-- IP reputation (0.4.94): which public lists are downloaded, InternetDB and MISP; the lists' state. The web service
     only queues "update now"; a separate sandboxed unit downloads and asks. -->
<template>
  <UiSettings :groups="['iprep']" @saved="(c) => { load(); emit('saved', c) }" />
  <section class="card">
    <h2><Icon name="shield" /> {{ t('iprep.lists_title') }}</h2>
    <p class="muted small">{{ t('iprep.lists_intro', { unit: 'jt-waf-mgr-iprep.service' }) }}</p>
    <ErrorBox :error="error" />
    <template v-if="st">
      <p v-if="!st.enabled" class="alert info">{{ t('iprep.off') }}</p>
      <DataTable id="iprep-lists" :columns="cols" :rows="st.lists" row-key="id" :page-size="20">
        <template #cell-name="{ row }"><a :href="row.url" target="_blank" rel="noopener noreferrer">{{ row.name }}</a></template>
        <template #cell-count="{ row }">{{ !row.on || row.count == null ? '—' : fmtNum(row.count) }}</template>
        <template #cell-weight="{ row }"><span class="badge" :class="LEVEL_CLS[row.weight]">{{ t('iprep.level.' + row.weight) }}</span></template>
        <template #cell-state="{ row }"><span v-if="!row.on" class="muted">{{ t('uiset.off') }}</span>
          <span v-else-if="row.error" class="warn small">{{ t('iprep.list_error', { error: row.error }) }}</span>
          <span v-else-if="row.updated">{{ fmtMinute(row.updated) }}</span><span v-else class="muted">{{ t('iprep.not_yet') }}</span></template>
      </DataTable>
      <p class="small iprep-meta">
        <span class="muted">{{ t('iprep.ran_at') }}</span><span class="gapl">{{ st.ran_at ? fmtMinute(st.ran_at) : '—' }}</span>
        <span v-if="st.requested" class="badge b-warn gapl">{{ t('countries.queued') }}</span>
        <span class="sep" aria-hidden="true">·</span>
        <span class="muted">{{ t('iprep.online') }}</span><span class="gapl">{{ [st.internetdb ? 'Shodan InternetDB' : '', st.misp ? 'MISP' : ''].filter(Boolean).join(t('common.list_sep')) || t('uiset.off') }}</span>
      </p>
      <div class="actions">
        <button type="button" class="btn" :disabled="busy || !isAdmin || !st.enabled || st.requested" @click="update"><Icon name="refresh" />{{ t('iprep.update_now') }}</button>
        <button type="button" class="btn ghost" :disabled="busy" @click="load"><Icon name="refresh" />{{ t('common.refresh') }}</button>
      </div>
    </template>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { get, post } from '../api.js'
import { t, tOr } from '../i18n.js'
import { hasRole } from '../store.js'
import { fmtMinute, fmtNum } from '../util.js'
import Icon from './Icon.vue'
import ErrorBox from './ErrorBox.vue'
import DataTable from './DataTable.vue'
import UiSettings from './UiSettings.vue'

const emit = defineEmits(['saved'])
const st = ref(null)
const error = ref(null)
const busy = ref(false)
const isAdmin = computed(() => hasRole('admin'))
const LEVEL_CLS = { high: 'b-blocked', medium: 'b-warn', info: 'b-logged' }
const cols = computed(() => [
  { key: 'name', label: t('iprep.col.name'), required: true, text: (r) => r.name },
  { key: 'category', label: t('iprep.col.category'), value: (r) => tOr('iprep.cat.' + r.category, r.category) },
  { key: 'weight', label: t('iprep.col.weight'), value: (r) => t('iprep.level.' + r.weight) },
  { key: 'count', label: t('iprep.col.count'), align: 'num', value: (r) => (r.on ? r.count || 0 : -1), text: (r) => (!r.on || r.count == null ? '—' : fmtNum(r.count)) },
  { key: 'state', label: t('iprep.col.updated'), text: (r) => r.error || r.updated || '' },
])
async function load() {
  error.value = null
  try { st.value = await get('/iprep/status') } catch (e) { error.value = e }
}
async function update() {
  busy.value = true
  error.value = null
  try { st.value = await post('/iprep/update', {}) } catch (e) { error.value = e } finally { busy.value = false }
}
onMounted(load)
</script>

<style scoped>
.iprep-meta { margin: 12px 0 4px; display: flex; flex-wrap: wrap; align-items: center; row-gap: 4px; }
.iprep-meta .sep { margin: 0 10px; color: var(--muted); }
</style>
