<!-- "Someone says they were blocked": paste their address, the URL they opened, or a request id, and go straight to
     what the WAF recorded. Only navigation: the search itself is the ordinary event list / address lookup. -->
<template>
  <form class="findvisit" role="search" @submit.prevent="go">
    <label class="field grow"><span><Icon name="search" /> {{ t('find.label') }}</span>
      <input v-model.trim="q" :placeholder="t('find.placeholder')" maxlength="2000" spellcheck="false" class="mono"></label>
    <button type="submit" class="btn" :disabled="!q || busy"><Icon name="go" />{{ t('find.go') }}</button>
    <p v-if="msg" class="muted small" role="status">{{ msg }}</p>
  </form>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { get } from '../api.js'
import { t } from '../i18n.js'
import Icon from './Icon.vue'

const router = useRouter()
const q = ref('')
const msg = ref('')
const busy = ref(false)
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/
const IPV6 = /^[0-9a-f:]+:[0-9a-f:.]*$/i

async function go() {
  msg.value = ''
  const v = q.value
  if (IPV4.test(v) || IPV6.test(v)) return router.push('/lookup/' + encodeURIComponent(v))
  let host = '', path = ''
  try {
    if (/^https?:\/\//i.test(v)) { const u = new URL(v); host = u.hostname.toLowerCase(); path = u.pathname }
  } catch { /* not a URL */ }
  if (!host && v.startsWith('/')) path = v.split('?')[0]
  if (host || path) {
    const query = { outcome: 'blocked' }
    if (host) query.host = host
    if (path && path !== '/') query.q = path
    return router.push({ path: '/events', query })
  }
  // a request id (shown on the error page, or in a log line)
  busy.value = true
  try {
    const r = await get('/events', /^[0-9a-f]{32}$/i.test(v) ? { request_id: v, limit: 1 } : { unique_id: v, limit: 1 })
    if (r.items && r.items.length) return router.push('/events/' + r.items[0].id)
    msg.value = t('find.not_found')
  } catch { msg.value = t('find.not_found') } finally { busy.value = false }
}
</script>

<style scoped>
.findvisit { display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: flex-end; margin: 0 0 12px; }
.findvisit .field { min-width: 260px; }
.findvisit p { flex-basis: 100%; margin: 0; }
</style>
