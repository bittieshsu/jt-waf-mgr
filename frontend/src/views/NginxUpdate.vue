<template>
  <div class="page">
    <div class="pagehead"><h1>{{ t('ngup.title') }}</h1>
      <button v-if="isAdmin" type="button" class="btn small" :disabled="busy" @click="checkNow"><Icon name="refresh" />{{ t('ngup.check_now') }}</button></div>
    <ErrorBox :error="error" />
    <Loading v-if="!d && !error" />
    <template v-if="d">
      <p class="muted small">{{ t('ngup.intro') }}</p>
      <div class="tiles">
        <div class="tile stat"><div class="tl"><Icon name="server" />{{ t('ngup.installed') }}</div><div class="tv small mono">{{ safeText(d.installed || d.nginx_version, 40) || '—' }}</div></div>
        <div class="tile stat" :class="d.update ? 't-warn' : 't-ok'"><div class="tl"><Icon name="download" />{{ t('ngup.candidate') }}</div>
          <div class="tv small mono">{{ d.update ? safeText(d.candidate, 40) : t('ngup.no_update') }}</div></div>
        <div class="tile stat" :class="d.held ? 't-ok' : (d.hand_built.length ? 't-warn' : '')"><div class="tl"><Icon name="lock" />{{ t('ngup.held') }}</div>
          <div class="tv small">{{ d.held === null || d.held === undefined ? '—' : d.held ? t('common.yes') : t('common.no') }}</div></div>
        <div class="tile stat" :class="d.level === 'ok' ? 't-ok' : 't-warn'"><div class="tl"><Icon name="shield" />{{ t('ngup.module') }}</div>
          <div class="tv small">{{ t('ngup.level.' + d.level) }}</div></div>
      </div>
      <section class="card">
        <h2><Icon name="server" /> {{ t('ngup.now_title') }}</h2>
        <div class="kvgroups">
          <div class="kvpanel">
            <h3><Icon name="check" />{{ t('ngup.g_now') }}</h3>
            <dl class="kv">
              <dt>{{ t('ngup.state') }}</dt><dd><span class="badge" :class="d.level === 'ok' ? 'b-ok' : d.level === 'critical' ? 'b-blocked' : 'b-warn'">{{ t('ngup.reason.' + d.reason) }}</span></dd>
              <dt>{{ t('ngup.package') }}</dt><dd class="mono">{{ safeText(d.package, 60) || '—' }}</dd>
              <dt>{{ t('ngup.modules') }}</dt><dd>
                <div v-for="m in d.modules || []" :key="m" class="mono small breakall">{{ safeText(m, 200) }}
                  <span class="badge gapl" :class="d.hand_built.includes(m) ? 'b-int' : 'b-logged'">{{ d.hand_built.includes(m) ? t('ngup.by_hand') : t('ngup.packaged') }}</span></div>
                <span v-if="!(d.modules || []).length" class="muted">{{ d.static ? t('ngup.static') : '—' }}</span></dd>
            </dl>
          </div>
          <div class="kvpanel">
            <h3><Icon name="download" />{{ t('ngup.g_next') }}</h3>
            <dl class="kv">
              <dt>{{ t('ngup.check_state') }}</dt><dd><span v-if="c.state" class="badge" :class="STATE_CLS[c.state] || 'b-logged'">{{ tOr('ngup.st.' + c.state, c.state) }}</span><span v-else class="muted">{{ t('ngup.never') }}</span>
                <span v-if="c.at" class="muted small gapl">{{ fmtMinute(c.at) }}</span></dd>
              <template v-if="c.state === 'ready'"><dt>{{ t('ngup.verified') }}</dt><dd>{{ t('ngup.ready_detail', { v: c.candidate }) }}
                <div class="muted small mono breakall">{{ t('ngup.module_sha') }} {{ safeText(c.module_sha256, 64) }}</div></dd></template>
              <template v-if="c.error"><dt>{{ t('ngup.why') }}</dt><dd class="small breakall">{{ safeText(c.error, 300) }}</dd></template>
              <template v-if="c.modules_by_hand"><dt>{{ t('ngup.other_modules') }}</dt><dd class="mono small breakall">{{ c.modules_by_hand.map((x) => safeText(x, 200)).join(', ') }}</dd></template>
            </dl>
          </div>
        </div>
        <p v-if="advice" class="alert" :class="advice.cls">{{ advice.text }}</p>
        <div v-if="c.state === 'untrusted'" class="alert warn breakall">{{ t('ngup.untrusted') }}
          <CodeBlock :code="TRUST_CMD" lang="shell" small />
          <div class="small">{{ t('ngup.uploaded_sha') }} <span class="mono">{{ safeText(c.module_sha256, 64) }}</span></div></div>
        <div v-if="isAdmin && canHold" class="actions">
          <button type="button" class="btn small" :disabled="busy" @click="holdNginx"><Icon name="lock" />{{ t('ngup.hold') }}</button>
          <span class="muted small">{{ t('ngup.hold_hint') }}</span>
        </div>
        <div v-if="d.open_change" class="alert info">{{ t('ngup.open_change', { id: d.open_change }) }}
          <RouterLink :to="'/changes/' + d.open_change">{{ t('toggle.open_change') }}</RouterLink></div>
        <div v-else-if="isAdmin && ready" class="crsswitch">
          <label class="field"><span>{{ t('crsupd.reason') }}</span>
            <textarea v-model="reason" rows="2" maxlength="2000" class="w-lg" :placeholder="t('ngup.reason_hint')"></textarea></label>
          <div class="actions">
            <button type="button" class="btn small primary" :disabled="busy || reason.trim().length < 5" @click="propose">
              <Icon name="change" />{{ c.mode === 'finish' ? t('ngup.propose_finish', { v: c.target }) : t('ngup.propose', { from: d.installed, v: c.target }) }}</button>
          </div>
          <p class="muted small">{{ t('ngup.propose_hint') }}</p>
        </div>
        <p v-if="msg" class="muted small" role="status">{{ msg }}</p>
      </section>
      <section v-if="d.hand_built.length || d.waiting.length" class="card">
        <h2><Icon name="upload" /> {{ t('ngup.prepare_title') }}</h2>
        <p class="muted small">{{ t('ngup.prepare_hint') }}</p>
        <CodeBlock :code="buildCmd" lang="shell" small />
        <div v-if="isAdmin" class="crsupload">
          <label class="btn small ghost filebtn"><Icon name="code" />{{ soFile ? safeText(soFile.name, 60) : t('ngup.pick_so') }}
            <input type="file" accept=".so" :disabled="busy" @change="soFile = $event.target.files[0] || null"></label>
          <label class="btn small ghost filebtn"><Icon name="page" />{{ jsonFile ? safeText(jsonFile.name, 60) : t('ngup.pick_json') }}
            <input type="file" accept=".json,application/json" :disabled="busy" @change="jsonFile = $event.target.files[0] || null"></label>
          <button type="button" class="btn small primary" :disabled="busy || !soFile" @click="upload"><Icon name="upload" />{{ t('ngup.upload') }}</button>
        </div>
        <ul v-if="d.waiting.length" class="plainlist">
          <li v-for="w in d.waiting" :key="w.for"><span class="mono">{{ safeText(w.for, 70) }}</span>
            <span class="badge gapl" :class="w.trusted ? 'b-ok' : 'b-warn'">{{ w.trusted ? t('ngup.trusted') : t('ngup.st.untrusted') }}</span>
            <span class="muted small">{{ [w.os, w.libmodsecurity, w.uploaded_by && t('ngup.uploaded_by', { who: w.uploaded_by, at: fmtMinute(w.uploaded_at) })].filter(Boolean).map((x) => safeText(x, 120)).join(' · ') }}</span></li>
        </ul>
      </section>
      <ErrorBox :error="opError" />
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { get, post } from '../api.js'
import { t, tOr } from '../i18n.js'
import { safeText, fmtMinute } from '../util.js'
import { hasRole } from '../store.js'
import ErrorBox from '../components/ErrorBox.vue'
import Loading from '../components/Loading.vue'
import Icon from '../components/Icon.vue'
import CodeBlock from '../components/CodeBlock.vue'
import { uploadInParts } from '../upload.js'

const d = ref(null)
const error = ref(null)
const opError = ref(null)
const busy = ref(false)
const msg = ref('')
const soFile = ref(null)
const jsonFile = ref(null)
const isAdmin = computed(() => hasRole('admin'))
const c = computed(() => (d.value && d.value.check) || {})
const ready = computed(() => c.value.state === 'ready' && !!c.value.target)
const canHold = computed(() => d.value && d.value.package && d.value.held === false && d.value.hand_built.length > 0)
const reason = ref('')
async function propose() {
  busy.value = true
  opError.value = null
  try {
    const r = await post('/nginx/update/propose', { reason: reason.value.trim() })
    reason.value = ''
    msg.value = t('ngup.proposed', { id: r.change_id })
    await load()
  } catch (e) { opError.value = e } finally { busy.value = false }
}
async function holdNginx() {
  busy.value = true
  opError.value = null
  try { await post('/nginx/hold', {}); msg.value = t('ngup.hold_requested') } catch (e) { opError.value = e } finally { busy.value = false }
}
const TRUST_CMD = 'sudo jt-waf-mgr nginx-module-trust ngx_http_modsecurity_module.so --sha256 <SHA-256>'
const STATE_CLS = { ready: 'b-ok', current: 'b-ok', packaged: 'b-ok', no_module: 'b-warn', failed: 'b-blocked', error: 'b-blocked',
  other_hand_built: 'b-warn', running: 'b-int', unsupported: 'b-logged', untrusted: 'b-warn', unsupported_packaging: 'b-logged' }
const buildCmd = computed(() => {
  const v = d.value && d.value.update ? d.value.candidate : ''
  return 'sudo ./deploy/build-modsecurity-module.sh' + (v ? '      # ' + t('ngup.cmd_note', { v }) : '')
})
// what to do now, from the module state and the last check
const advice = computed(() => {
  const x = d.value
  if (!x) return null
  if (x.level === 'critical') return { cls: 'error', text: ready.value ? t('ngup.adv.finish_ready', { v: c.value.target }) : t('ngup.adv.broken') }
  if (!x.update) return x.hand_built.length && !x.held ? { cls: 'warn', text: t('ngup.adv.hold') } : null
  const s = c.value.state
  if (s === 'ready' && c.value.candidate === x.candidate) return { cls: 'success', text: t('ngup.adv.ready', { v: x.candidate }) }
  if (s === 'packaged') return x.level === 'ok' ? null : { cls: 'warn', text: t('ngup.adv.packaged') }
  if (x.hand_built.length) return { cls: 'warn', text: t('ngup.adv.wait', { v: x.candidate }) }
  return null
})
async function load() {
  try { d.value = await get('/nginx/update') } catch (e) { error.value = e }
}
async function checkNow() {
  busy.value = true
  opError.value = null
  try { await post('/nginx/update/check', {}); msg.value = t('ngup.requested') } catch (e) { opError.value = e } finally { busy.value = false }
}
async function upload() {
  busy.value = true
  opError.value = null
  msg.value = ''
  try {
    const finish = {}
    if (jsonFile.value) finish.description = await jsonFile.value.text()
    else if (d.value.update) finish.nginx_package = d.value.candidate
    const r = await uploadInParts('nginxmod', soFile.value, finish)
    msg.value = t('ngup.uploaded', { v: r.nginx_package })
    soFile.value = null
    jsonFile.value = null
    await load()
  } catch (e) { opError.value = e } finally { busy.value = false }
}
onMounted(load)
</script>
