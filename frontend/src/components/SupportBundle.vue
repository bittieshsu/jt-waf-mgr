<!-- 0.5.48: the support bundle -- the events of a range with the rules, rule files and settings that decided them, as a
     zip to send to whoever helps with a false positive (POST /support/bundle, approvers; audited). Source addresses are
     pseudonymised by default; site names can be too. Starts from the events page's own filters. -->
<template>
  <section class="card supportbundle" :aria-label="t('supbundle.title')">
    <div class="cardhead">
      <h2><Icon name="download" /> {{ t('supbundle.title') }}</h2>
      <button type="button" class="btn small ghost" @click="$emit('close')"><Icon name="close" />{{ t('common.close') }}</button>
    </div>
    <p class="small muted">{{ t('supbundle.intro') }}</p>
    <div class="bfields">
      <div class="field"><label for="sb-since">{{ t('filter.since') }}</label>
        <DatePicker id="sb-since" v-model="f.since" mode="datetime" /></div>
      <div class="field"><label for="sb-until">{{ t('filter.until') }}</label>
        <DatePicker id="sb-until" v-model="f.until" mode="datetime" /></div>
      <label class="field"><span>{{ t('event.host') }}</span><input v-model.trim="f.host" maxlength="255" :placeholder="t('supbundle.all_sites')"></label>
      <label class="field"><span>{{ t('filter.src_ip') }}</span><input v-model.trim="f.src_ip" maxlength="64" placeholder="203.0.113.0/24"></label>
      <div class="field"><label for="sb-outcome">{{ t('event.outcome') }}</label>
        <SelectBox id="sb-outcome" v-model="f.outcome" :options="[{ value: 'all', label: t('supbundle.outcome_all') }, { value: 'blocked', label: t('supbundle.outcome_blocked') }]" /></div>
    </div>
    <label class="check"><input v-model="f.anon_ips" type="checkbox"> {{ t('supbundle.anon_ips') }}</label>
    <label class="check"><input v-model="f.anon_hosts" type="checkbox"> {{ t('supbundle.anon_hosts') }}</label>
    <p class="small muted">{{ t('supbundle.contents') }}</p>
    <ErrorBox :error="error" />
    <p v-if="done" class="alert ok small" role="status"><Icon name="check" /> {{ t('supbundle.done', { n: done.events, sha: done.sha256.slice(0, 16) }) }}</p>
    <div class="actions formacts">
      <button type="button" class="btn primary" :disabled="busy" @click="make"><Spinner v-if="busy" /><Icon v-else name="download" />{{ busy ? t('supbundle.making') : t('supbundle.make') }}</button>
    </div>
  </section>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { ApiError } from '../api.js'
import { t } from '../i18n.js'
import { saveBlob } from '../util.js'
import { state } from '../store.js'
import Icon from './Icon.vue'
import Spinner from './Spinner.vue'
import ErrorBox from './ErrorBox.vue'
import SelectBox from './SelectBox.vue'
import DatePicker from './DatePicker.vue'

const props = defineProps({ query: { type: Object, default: () => ({}) } })
defineEmits(['close'])
const q = props.query || {}
const f = reactive({
  since: q.since || new Date(Date.now() - 86400000).toISOString(), until: q.until || '',
  host: q.host || '', src_ip: q.src_ip || '', outcome: q.outcome === 'blocked' ? 'blocked' : 'all',
  anon_ips: true, anon_hosts: false,
})
const busy = ref(false)
const error = ref(null)
const done = ref(null)

async function make() {
  busy.value = true; error.value = null; done.value = null
  try {
    const res = await fetch('/api/v1/support/bundle', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', Accept: 'application/zip', 'X-CSRF-Token': state.csrf || '' },
      body: JSON.stringify({ since: f.since || null, until: f.until || null, host: f.host, src_ip: f.src_ip,
        outcome: f.outcome, anon_ips: f.anon_ips, anon_hosts: f.anon_hosts }),
    })
    if (!res.ok) {
      let err = {}
      try { err = (await res.json()).error || {} } catch { /* not JSON */ }
      if (res.status === 401) { window.location.assign('/login'); return }
      throw new ApiError(res.status, err.code, err.message, err.details)
    }
    const name = (/filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') || '') || [])[1] || 'jt-waf-mgr-support.zip'
    saveBlob(name, await res.blob())
    done.value = { events: Number(res.headers.get('X-Events') || 0), sha256: res.headers.get('X-Content-SHA256') || '' }
  } catch (e) { error.value = e } finally { busy.value = false }
}
</script>

<style scoped>
.bfields { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(220px, 100%), 1fr)); gap: 8px 14px; margin: 8px 0; }
.supportbundle label.check { display: block; margin: 6px 0; }
.formacts { margin-top: 12px; display: flex; gap: 10px; flex-wrap: wrap; }
</style>
