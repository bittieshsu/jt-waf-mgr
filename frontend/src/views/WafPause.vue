<!-- Pausing the WAF to troubleshoot a site: ModSecurity only detects (logs, refuses nothing) on every site or on one
     site, for a few hours or until resumed. Resuming puts back exactly what was there. -->
<template>
  <div class="page">
    <div class="pagehead"><h1>{{ t('pause.title') }}</h1></div>
    <p class="alert info small"><Icon name="info" /> {{ t('pause.intro') }}</p>
    <Loading v-if="!st && !error" />
    <ErrorBox :error="error" />
    <template v-if="st">
      <p v-if="!st.adopted" class="alert warn"><Icon name="warning" /> {{ t('pause.not_adopted') }}</p>
      <p v-if="st.last_failed" class="alert error"><Icon name="alert" /> {{ t('pause.last_failed', { id: st.last_failed.change_id, error: safeText(st.last_failed.error, 300) }) }}
        <RouterLink :to="'/changes/' + st.last_failed.change_id">{{ t('pause.see_change') }}</RouterLink></p>
      <section class="card">
        <h2><Icon name="shield" /> {{ t('pause.now') }}</h2>
        <p v-if="!st.active" class="okline"><span class="badge b-ok">{{ t('pause.not_paused') }}</span> {{ t('pause.not_paused_hint') }}</p>
        <div v-if="st.all" class="pauserow all">
          <div><strong>{{ t('pause.every_site') }}</strong>
            <div class="muted small">{{ t('pause.by_line', { by: safeText(st.all.by || '—', 60), at: fmtMinute(st.all.since_at), left: leftText(st.all) }) }}</div>
            <div class="small">{{ safeText(st.all.reason || '', 300) }}</div></div>
          <button v-if="canResume" type="button" class="btn small primary" :disabled="busy || !!st.busy" @click="resume({})"><Icon name="refresh" />{{ t('pause.resume') }}</button>
        </div>
        <div v-for="x in st.sites" :key="x.host" class="pauserow">
          <div><strong class="mono">{{ safeText(x.host, 120) }}</strong>
            <div class="muted small">{{ t('pause.by_line', { by: safeText(x.by || '—', 60), at: fmtMinute(x.since_at), left: leftText(x) }) }}</div>
            <div class="small">{{ safeText(x.reason || '', 300) }}</div></div>
          <button v-if="canResume" type="button" class="btn small primary" :disabled="busy || !!st.busy" @click="resume({ host: x.host })"><Icon name="refresh" />{{ t('pause.resume') }}</button>
        </div>
        <div v-if="st.active && canResume" class="actions">
          <button type="button" class="btn primary" :disabled="busy || !!st.busy" @click="resume({ all: true })"><Icon name="refresh" />{{ t('pause.resume_all') }}</button>
          <span class="muted small">{{ t('pause.resume_hint') }}</span>
        </div>
        <p v-if="st.busy" class="muted small" role="status"><Icon name="timer" /> {{ t('pause.busy', { id: st.busy }) }}
          <RouterLink :to="'/changes/' + st.busy">{{ t('pause.see_change') }}</RouterLink></p>
      </section>

      <section v-if="isAdmin" class="card">
        <h2><Icon name="warning" /> {{ t('pause.start') }}</h2>
        <form class="pauseform" @submit.prevent="start">
          <div class="field"><span>{{ t('pause.scope') }}</span>
            <div class="seg" role="group" :aria-label="t('pause.scope')">
              <button type="button" :class="{ on: scope === 'all' }" :aria-pressed="scope === 'all'" @click="scope = 'all'"><Icon name="globe" />{{ t('pause.scope_all') }}</button>
              <button type="button" :class="{ on: scope === 'site' }" :aria-pressed="scope === 'site'" @click="scope = 'site'"><Icon name="server" />{{ t('pause.scope_site') }}</button>
            </div></div>
          <div v-if="scope === 'site'" class="field"><label for="pause-host">{{ t('pause.site') }}</label>
            <SelectBox id="pause-host" v-model="host" :options="siteOpts" :placeholder="t('pause.pick_site')" />
            <span v-if="st.match === 'host'" class="small warn">{{ t('pause.host_match_warn') }}</span></div>
          <div class="field"><span>{{ t('pause.duration') }}</span>
            <div class="seg" role="group" :aria-label="t('pause.duration')">
              <button v-for="h in st.durations" :key="h" type="button" :class="{ on: hours === h }" :aria-pressed="hours === h" @click="hours = h"><Icon :name="h ? 'timer' : 'lock'" />{{ h ? t('pause.hours', { h }) : t('pause.forever') }}</button>
            </div>
            <span v-if="hours === 0" class="small warn">{{ t('pause.forever_hint') }}</span></div>
          <label class="field wide"><span>{{ t('pause.reason') }}</span>
            <input v-model="reason" type="text" maxlength="300" :placeholder="t('pause.reason_ph')"></label>
          <label class="field"><span>{{ t('change.totp') }}</span>
            <input v-model.trim="totp" inputmode="numeric" autocomplete="one-time-code" maxlength="7" class="mono" placeholder="123456"></label>
          <p class="small muted wide">{{ t('pause.what_happens') }}</p>
          <div class="actions wide">
            <button type="submit" class="btn danger" :disabled="busy || !!st.busy || !ready || !st.adopted"><Icon name="warning" />{{ t('pause.start_btn') }}</button>
          </div>
        </form>
      </section>
      <ErrorBox :error="actionError" />
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { get, post } from '../api.js'
import { t } from '../i18n.js'
import { hasRole, refreshPause } from '../store.js'
import { safeText, fmtMinute } from '../util.js'
import Icon from '../components/Icon.vue'
import Loading from '../components/Loading.vue'
import ErrorBox from '../components/ErrorBox.vue'
import SelectBox from '../components/SelectBox.vue'

const st = ref(null)
const error = ref(null)
const actionError = ref(null)
const busy = ref(false)
const sites = ref([])
const scope = ref('site')
const host = ref('')
const hours = ref(1)
const reason = ref('')
const totp = ref('')
const isAdmin = computed(() => hasRole('admin'))
const canResume = computed(() => hasRole('approver'))
const siteOpts = computed(() => sites.value.map((h) => ({ value: h, label: h })))
const ready = computed(() => reason.value.trim().length >= 5 && totp.value.length >= 6 && (scope.value === 'all' || host.value))

function leftText(x) {
  if (!x || !x.until_at) return t('pause.until_resumed')
  const s = Math.max(0, x.left_seconds || 0)
  return s >= 3600 ? t('pause.left_h', { h: Math.floor(s / 3600), m: Math.floor((s % 3600) / 60) }) : t('pause.left_m', { m: Math.max(1, Math.ceil(s / 60)) })
}
async function load() {
  try {
    st.value = await get('/waf/pause')
    error.value = null
  } catch (e) { error.value = e }
  refreshPause(true)
}
async function loadSites() {
  try {
    const v = await get('/vhosts')
    const names = new Set()
    for (const s of v.items || []) for (const n of s.server_names || []) if (n && n !== '_' && !n.startsWith('*') && !n.startsWith('~')) names.add(n.toLowerCase())
    sites.value = [...names].sort()
  } catch { /* the list stays empty: type nothing, pick nothing */ }
}
async function start() {
  busy.value = true
  actionError.value = null
  try {
    await post('/waf/pause', { scope: scope.value, host: scope.value === 'site' ? host.value : null, hours: hours.value, reason: reason.value, totp: totp.value })
    reason.value = ''
  } catch (e) { actionError.value = e } finally {
    totp.value = ''
    busy.value = false
    load()
  }
}
async function resume(body) {
  busy.value = true
  actionError.value = null
  try { await post('/waf/pause/resume', body) } catch (e) { actionError.value = e } finally {
    busy.value = false
    load()
  }
}
let timer = null
onMounted(() => { load(); loadSites(); timer = setInterval(load, 5000) })
onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.pauserow { display: flex; gap: 12px; align-items: center; justify-content: space-between; padding: 10px 12px; border: 1px solid var(--blocked);
  border-radius: 8px; background: var(--blocked-bg); margin-bottom: 8px; }
.pauserow.all { border-width: 2px; }
.okline { display: flex; gap: 8px; align-items: center; }
.pauseform { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 18px; align-items: start; }
.pauseform .wide { grid-column: 1 / -1; }
.pauseform .field { display: flex; flex-direction: column; gap: 6px; }
@media (max-width: 760px) { .pauseform { grid-template-columns: minmax(0, 1fr); } }
</style>
