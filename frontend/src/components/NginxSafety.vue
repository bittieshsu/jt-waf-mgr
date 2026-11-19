<template>
  <!-- 0.5.1: before anyone approves an nginx update -- what happens if it goes wrong, the way back, a copy to keep -->
  <section v-if="s" class="card nginxsafety">
    <h2><Icon name="shield" /> {{ t('ngsafe.title') }}</h2>
    <p class="muted small">{{ t('ngsafe.intro') }}</p>
    <h3 class="sub">{{ t('ngsafe.auto_title') }}</h3>
    <ul class="plainlist steps">
      <li><Icon name="check" /> {{ t('ngsafe.auto_keep') }}</li>
      <li><Icon name="check" /> {{ t('ngsafe.auto_health', { n: s.health_urls }) }}
        <span v-if="!s.health_urls" class="badge b-warn gapl">{{ t('ngsafe.no_health') }}</span></li>
      <li><Icon name="check" /> {{ t('ngsafe.auto_restore') }}</li>
      <li><Icon name="check" /> {{ t('ngsafe.auto_alert') }}</li>
      <li><Icon :name="s.auto_update ? 'warning' : 'info'" /> {{ s.auto_update ? t('ngsafe.auto_update_on') : t('ngsafe.auto_update_off') }}</li>
    </ul>

    <template v-if="!compact">
      <h3 class="sub">{{ t('ngsafe.back_title') }}</h3>
      <p v-if="!wb" class="muted small">{{ t('ngsafe.back_none') }}</p>
      <template v-else>
        <p class="small">{{ t('ngsafe.back_from', { id: wb.change_id, now: wb.installed_by_it || '—', to: wb.back_to || '—', at: fmtMinute(wb.applied_at) }) }}
          <RouterLink :to="'/changes/' + wb.change_id" class="gapl">#{{ wb.change_id }}</RouterLink></p>
        <p v-if="!wb.matches" class="alert warn small">{{ t('ngsafe.back_changed', { now: wb.current || '—' }) }}</p>
        <div v-if="isAdmin && wb.matches" class="filters inline">
          <label class="field grow"><span>{{ t('ngsafe.reason') }}</span>
            <input v-model="reason" maxlength="2000" :placeholder="t('ngsafe.reason_ph')"></label>
          <button type="button" class="btn danger" :disabled="busy || reason.trim().length < 3" @click="rollback"><Icon name="rollback" />{{ t('ngsafe.rollback') }}</button>
        </div>
      </template>
      <template v-if="mods.length > 1 && isAdmin">
        <h3 class="sub">{{ t('ngsafe.module_title') }}</h3>
        <p class="muted small">{{ t('ngsafe.module_intro') }}</p>
        <ul class="plainlist mods">
          <li v-for="m in mods" :key="m.sha256">
            <span class="mono small" :title="m.sha256">{{ m.sha256.slice(0, 16) }}…</span>
            <span class="small">{{ safeText(m.note, 200) }}</span>
            <span v-if="m.running" class="badge b-ok">{{ t('ngsafe.running') }}</span>
            <button v-else type="button" class="btn tiny" :disabled="busy || reason.trim().length < 3" :title="t('ngsafe.reason_first')" @click="switchModule(m)"><Icon name="change" />{{ t('ngsafe.use_module') }}</button>
          </li>
        </ul>
      </template>
      <p v-if="msg" class="alert success small">{{ msg }} <RouterLink v-if="newId" :to="'/changes/' + newId">#{{ newId }}</RouterLink></p>
    </template>

    <h3 class="sub">{{ t('ngsafe.cli_title') }}</h3>
    <p class="muted small">{{ t('ngsafe.cli_intro') }}</p>
    <CodeBlock :code="cliText" lang="shell" small />
    <p class="muted small">{{ t('ngsafe.tunnel', { port: port }) }}</p>
    <CodeBlock :code="'ssh -L ' + port + ':127.0.0.1:' + port + ' root@<WAF host>      # ' + t('ngsafe.tunnel_then', { port: port })" lang="shell" small />

    <template v-if="isAdmin">
      <h3 class="sub">{{ t('ngsafe.backup_title') }}</h3>
      <p class="muted small">{{ t('ngsafe.backup_intro') }}</p>
      <div class="filters inline">
        <label class="field"><span>{{ t('change.totp') }}</span>
          <input v-model.trim="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" class="mono w-sm" placeholder="123456"></label>
        <button type="button" class="btn" :disabled="dlBusy || !/^\d{6}$/.test(code)" @click="download"><Icon name="download" />{{ t('ngsafe.backup_download') }}</button>
      </div>
      <p v-if="dl" class="alert success small">{{ t('ngsafe.backup_done', { sha: dl.slice(0, 16) }) }}</p>
    </template>
    <ErrorBox :error="error" />
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { get, post, ApiError } from '../api.js'
import { state, hasRole } from '../store.js'
import { t } from '../i18n.js'
import { safeText, fmtMinute, saveBlob } from '../util.js'
import Icon from './Icon.vue'
import ErrorBox from './ErrorBox.vue'
import CodeBlock from './CodeBlock.vue'

const props = defineProps({ safety: { type: Object, default: null }, compact: { type: Boolean, default: false } })
const emit = defineEmits(['changed'])
const router = useRouter()
const own = ref(null)
const s = computed(() => props.safety || own.value)
const wb = computed(() => (s.value && s.value.way_back) || null)
const mods = computed(() => (s.value && s.value.trusted_modules) || [])
const port = computed(() => String((s.value && s.value.listen) || '127.0.0.1:8095').split(':').pop())
const isAdmin = computed(() => hasRole('admin'))
const me = computed(() => (state.user && state.user.username) || '<you>')
const cliText = computed(() => [
  'jt-waf-mgr nginx status',
  'jt-waf-mgr nginx rollback --reason "..." --as ' + me.value,
  'jt-waf-mgr changes approve <ID> --note "..." --totp <code> --as ' + me.value,
  'jt-waf-mgr nginx backup -o /var/tmp/nginx-backup.tar.gz --totp <code> --as ' + me.value,
].join('\n'))
const reason = ref('')
const busy = ref(false)
const msg = ref('')
const newId = ref(null)
const error = ref(null)
const code = ref('')
const dlBusy = ref(false)
const dl = ref('')

async function rollback() {
  busy.value = true; error.value = null; msg.value = ''
  try {
    const r = await post('/nginx/rollback', { reason: reason.value })
    newId.value = r.change_id; msg.value = t('ngsafe.proposed'); reason.value = ''
    emit('changed')
    router.push('/changes/' + r.change_id)
  } catch (e) { error.value = e } finally { busy.value = false }
}
async function switchModule(m) {
  busy.value = true; error.value = null; msg.value = ''
  try {
    const r = await post('/nginx/module', { sha256: m.sha256, reason: reason.value })
    newId.value = r.change_id; msg.value = t('ngsafe.proposed'); reason.value = ''
    emit('changed')
    router.push('/changes/' + r.change_id)
  } catch (e) { error.value = e } finally { busy.value = false }
}
async function download() {
  dlBusy.value = true; error.value = null
  try {
    const res = await fetch('/api/v1/nginx/backup', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', Accept: 'application/gzip', 'X-CSRF-Token': state.csrf || '' },
      body: JSON.stringify({ totp: code.value }),
    })
    if (!res.ok) {
      let err = {}
      try { err = (await res.json()).error || {} } catch { /* not JSON */ }
      if (res.status === 401) { window.location.assign('/login'); return }
      throw new ApiError(res.status, err.code, err.message, err.details)
    }
    const name = (/filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') || '') || [])[1] || 'nginx-backup.tar.gz'
    saveBlob(name, await res.blob())
    dl.value = res.headers.get('X-Content-SHA256') || ''
  } catch (e) { error.value = e } finally { dlBusy.value = false; code.value = '' }
}
onMounted(async () => {
  if (!props.safety) {
    try { own.value = (await get('/nginx/update')).safety || null } catch { /* the change page stands without it */ }
  }
})
</script>

<style scoped>
.nginxsafety h3.sub { font-size: 1em; margin: 14px 0 6px; }
/* the shared list puts its items at both ends: here they read left to right */
.nginxsafety .steps li { justify-content: flex-start; align-items: baseline; gap: 8px; padding: 3px 0; border-bottom: 0; text-align: left; }
.nginxsafety .mods li { display: grid; grid-template-columns: 11em minmax(0, 1fr) auto; align-items: center; gap: 4px 12px;
  justify-content: start; padding: 5px 0; }
.nginxsafety .mods li > :last-child { justify-self: end; }
@media (max-width: 720px) { .nginxsafety .mods li { grid-template-columns: minmax(0, 1fr) auto; } .nginxsafety .mods li > :nth-child(2) { grid-column: 1 / -1; grid-row: 2; } }
</style>
