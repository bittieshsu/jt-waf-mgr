<template>
  <div class="page">
    <h1>{{ t('settings.title') }}</h1>
    <WorkflowSettings :key="'c1-' + gen" />
    <RegressionSamples :key="'c2-' + gen" />
    <GeoipSettings @saved="load" :key="'c3-' + gen" />
    <UiSettings :groups="['llm', 'intel', 'hub', 'analyst', 'review', 'warroom', 'traffic', 'blocks', 'network']" @saved="load" :key="'c4-' + gen" />
    <CountrySettings @saved="load" :key="'c5-' + gen" />
    <DnsSettings @saved="load" :key="'c6-' + gen" />
    <SyslogDestinations :key="'c7-' + gen" />
    <UiSettings :groups="['policy']" @saved="load" :key="'c8-' + gen" />
    <SettingsTransfer @saved="afterImport" />
    <ErrorBox :error="error" />
    <section v-if="s" class="card">
      <h2><Icon name="page" /> {{ t('settings.config_title') }}</h2>
      <p class="alert info">{{ t('settings.readonly_note', { path: CONFIG_PATH }) }}</p>
      <div v-if="retentionItems.length" class="chartgrid">
        <div><h3 class="charthead">{{ t('chart.settings.retention') }}</h3>
          <HBars :items="retentionItems" :series="[{ key: 'days', label: t('chart.settings.days'), tone: 's1' }]" /></div>
        <div v-if="listItems.length"><h3 class="charthead">{{ t('chart.settings.lists') }}</h3>
          <HBars :items="listItems" :series="[{ key: 'n', label: t('chart.settings.entries'), tone: 's1' }]" /></div>
      </div>
      <dl class="kv">
        <template v-for="k in keys" :key="k">
          <dt>{{ tOr('settings.' + k, k) }}<div class="mono muted small">{{ k }}</div></dt>
          <dd><CodeBlock small lang="json" :code="fmt(s[k])" /></dd>
        </template>
      </dl>
    </section>
  </div>
</template>

<script setup>
import CodeBlock from '../components/CodeBlock.vue'
import Icon from '../components/Icon.vue'
import { ref, computed, onMounted } from 'vue'
import { get } from '../api.js'
import { t, tOr } from '../i18n.js'
import { safeMultiline } from '../util.js'
import ErrorBox from '../components/ErrorBox.vue'
import WorkflowSettings from '../components/WorkflowSettings.vue'
import RegressionSamples from '../components/RegressionSamples.vue'
import GeoipSettings from '../components/GeoipSettings.vue'
import CountrySettings from '../components/CountrySettings.vue'
import DnsSettings from '../components/DnsSettings.vue'
import UiSettings from '../components/UiSettings.vue'
import SettingsTransfer from '../components/SettingsTransfer.vue'
import SyslogDestinations from '../components/SyslogDestinations.vue'
import HBars from '../components/charts/HBars.vue'

const CONFIG_PATH = '/etc/jt-waf-mgr/config.toml'
const KNOWN = ['internal_networks', 'focus_sites', 'sensitive_fields', 'id_ranges', 'audit_log', 'nginx_conf', 'retention_days', 'password_min_length', 'require_totp_roles']
const s = ref(null)
const error = ref(null)
// set in the cards above (web interface): not repeated in this read-only list
const IN_UI = ['focus_sites', 'known_scanners', 'account_policy', 'geoip', 'countries', 'dns', 'compliance_level', 'syslog']
const keys = computed(() => {
  if (!s.value) return []
  const extra = Object.keys(s.value).filter((k) => !KNOWN.includes(k) && !IN_UI.includes(k)).sort()
  return KNOWN.filter((k) => k in s.value && !IN_UI.includes(k)).concat(extra)
})
// Charts from the values already shown below.
const retentionItems = computed(() => {
  const r = s.value && s.value.retention_days
  if (!r || typeof r !== 'object') return []
  return Object.keys(r).filter((k) => typeof r[k] === 'number').map((k) => ({ key: k, label: tOr('chart.settings.ret_' + k, k), values: { days: r[k] } }))
})
const listItems = computed(() => ['internal_networks', 'sensitive_fields']
  .filter((k) => s.value && Array.isArray(s.value[k]))
  .map((k) => ({ key: k, label: tOr('settings.' + k, k), values: { n: s.value[k].length } })))
function fmt(v) {
  if (v === null || v === undefined) return '—'
  if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') return safeMultiline(String(v))
  if (Array.isArray(v) && v.every((x) => typeof x !== 'object')) return safeMultiline(v.join('\n'))
  return safeMultiline(JSON.stringify(v, null, 2))
}
// after an import every card shows the new values (they load their own when they start)
const gen = ref(0)
function afterImport() { gen.value++; load() }
async function load() {
  try { s.value = await get('/settings') } catch (e) { error.value = e }
}
onMounted(load)
</script>
