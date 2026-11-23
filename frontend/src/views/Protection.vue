<!-- Application protection sets (0.5.33): ready-made rules for one application (Synology DSM, QNAP QTS), written from
     its publicly known vulnerabilities and attacks. For each site the software list names for the application, pick the
     rules (the recommended ones are ticked) and propose them as ONE change: the usual checks, the sandbox with each
     rule's own attack and ordinary requests, and a person's approval. -->
<template>
  <div class="page">
    <div class="pagehead"><h1>{{ t('protset.title') }}</h1></div>
    <p class="alert info small"><Icon name="info" /> {{ t('protset.intro') }}</p>
    <Loading v-if="!data && !error" />
    <ErrorBox :error="error" />
    <template v-if="data">
      <p v-if="!data.adopted && sites.length" class="alert warn small"><Icon name="warning" /> {{ t('protset.not_adopted') }}
        <RouterLink to="/managed">{{ goToLabel('/managed') }}</RouterLink></p>
      <section v-if="!sites.length" class="card">
        <p class="muted">{{ t('protset.none') }}</p>
        <p class="small">{{ t('protset.none_hint', { apps: data.sets.map((s) => s.app).join(', ') }) }}
          <RouterLink to="/intel">{{ t('protset.to_software') }}</RouterLink></p>
      </section>
      <section v-for="site in sites" :key="site.set + '|' + site.host" class="card protset" :data-host="site.host">
        <div class="cardhead">
          <h2><Icon name="shield" /> {{ site.app }} <span class="muted small gapl mono">{{ safeText(site.host, 120) }}</span></h2>
          <span class="badge" :class="summaryClass(site)">{{ summaryText(site) }}</span>
        </div>
        <DataTable :id="'protset-' + site.set + '-' + site.host" :columns="cols(site)" :rows="site.rules" row-key="id" :page-size="50" :expanded="open[site.host] || ''" clickable
                   @row-click="(r) => toggleOpen(site, r)">
          <template #cell-sel="{ row }"><input v-if="pickable(row)" type="checkbox" :checked="isPicked(site, row)" :aria-label="t('protset.pick', { name: ruleTitle(site, row) })" @click.stop @change="togglePick(site, row)" /><span v-else aria-hidden="true"></span></template>
          <template #cell-title="{ row }"><span class="prottitle">{{ ruleTitle(site, row) }}
            <span v-if="row.default" class="badge b-ok gapl">{{ t('protset.recommended') }}</span>
            <span v-if="row.needs_missing.length" class="badge b-logged gapl" :title="t('protset.needs_hint', { pkgs: row.needs_missing.join(', ') })">{{ t('protset.not_listed') }}</span></span></template>
          <template #cell-cves="{ row }"><span v-if="row.cves.length" class="cvelist"><span v-for="c in row.cves.slice(0, 3)" :key="c" class="chip tag mono">{{ safeText(c, 30) }}</span><span v-if="row.cves.length > 3" class="muted small"> +{{ row.cves.length - 3 }}</span></span><span v-else class="muted">—</span></template>
          <template #cell-state="{ row }"><RouterLink v-if="row.state === 'pending'" class="badge b-int" :to="'/changes/' + row.change_id" @click.stop>{{ t('protset.state.pending', { id: row.change_id }) }}</RouterLink>
            <span v-else class="badge" :class="stateClass(row.state)">{{ t('protset.state.' + row.state) }}<template v-if="row.rule_id"> · {{ row.rule_id }}</template></span></template>
          <template #expand="{ row }">
            <div class="protdetail">
              <p>{{ ruleWhy(site, row) }}</p>
              <p class="small"><strong>{{ t('protset.matches') }}：</strong><template v-if="row.regex"><span class="mono">{{ row.target === 'arg' ? row.arg + ' = ' : '' }}{{ safeText(row.regex, 400) }}</span>
                <span class="muted gapl">({{ t('wizard.target_opt.' + row.target) }})</span></template><span v-else>{{ t('wizard.target_opt.' + row.target) }}</span></p>
              <p v-if="row.cves.length" class="small"><strong>CVE：</strong><template v-for="(c, i) in row.cves" :key="c"><span v-if="i" class="muted"> · </span><a class="mono" :href="'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(c)" target="_blank" rel="noopener noreferrer">{{ c }}</a></template></p>
              <p v-if="row.refs.length" class="small"><strong>{{ t('protset.refs') }}：</strong><template v-for="(u, i) in row.refs" :key="u"><span v-if="i" class="muted"> · </span><a :href="u" target="_blank" rel="noopener noreferrer" :title="u">{{ safeText(refLabel(u), 80) }}</a></template></p>
            </div>
          </template>
        </DataTable>
        <div v-if="canPropose" class="actions protacts">
          <button type="button" class="btn primary" :disabled="busy || !data.adopted || !picks(site).length" @click="propose(site)"><Spinner v-if="busy === site.host" /><Icon v-else name="add" />{{ t('protset.propose', { n: picks(site).length }) }}</button>
          <span class="muted small">{{ t('protset.propose_hint') }}</span>
        </div>
        <ErrorBox :error="errors[site.host]" />
      </section>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { get, post } from '../api.js'
import { t, tOr } from '../i18n.js'
import { hasRole } from '../store.js'
import { safeText } from '../util.js'
import { goToLabel } from '../pageNames.js'
import Icon from '../components/Icon.vue'
import Spinner from '../components/Spinner.vue'
import Loading from '../components/Loading.vue'
import ErrorBox from '../components/ErrorBox.vue'
import DataTable from '../components/DataTable.vue'

const router = useRouter()
const data = ref(null)
const error = ref(null)
const busy = ref('')
const errors = reactive({})
const open = reactive({})
const picked = reactive({})
const canPropose = computed(() => hasRole('operator'))

const sites = computed(() => (data.value ? data.value.sets.flatMap((s) => s.sites.map((x) => ({ set: s.id, app: s.app, host: x.host, rules: x.rules }))) : []))

function key(site) { return site.set + '|' + site.host }
function pickable(row) { return ['available', 'update', 'disabled'].includes(row.state) }
function ruleTitle(site, row) { return tOr('protset.r.' + site.set + '.' + row.id, row.id) }
function ruleWhy(site, row) { return tOr('protset.w.' + site.set + '.' + row.id, '') }
// a source's label: its site, and the advisory / CVE / ZDI number when the address names one
function refLabel(u) {
  try {
    const x = new URL(u)
    const id = (x.pathname.match(/(Synology_SA_\d+_\d+|CVE-\d+-\d+|ZDI-\d+-\d+|QSA-\d+-\d+|NAS-\d{6}-\d+)/i) || [])[1]
    return x.hostname.replace(/^www\./, '') + (id ? ' ' + (/^(?:qsa|nas)-/i.test(id) ? id.toUpperCase() : id.replace(/_/g, '-')) : '')
  } catch { return u }
}
function isPicked(site, row) { return (picked[key(site)] || new Set()).has(row.id) }
function picks(site) { return site.rules.filter((r) => pickable(r) && isPicked(site, r)).map((r) => r.id) }
function togglePick(site, row) {
  const s = new Set(picked[key(site)] || [])
  if (s.has(row.id)) s.delete(row.id); else s.add(row.id)
  picked[key(site)] = s
}
function toggleOpen(site, row) { open[site.host] = open[site.host] === row.id ? '' : row.id }
function stateClass(st) { return { applied: 'b-ok', update: 'b-warn', disabled: 'b-logged', available: 'b-logged' }[st] || 'b-logged' }
function summaryClass(site) {
  const on = site.rules.filter((r) => r.state === 'applied').length
  return on === site.rules.length ? 'b-ok' : on ? 'b-warn' : 'b-logged'
}
function summaryText(site) {
  return t('protset.summary', { on: site.rules.filter((r) => r.state === 'applied').length, n: site.rules.length })
}
function cols(site) {
  return [
    ...(canPropose.value && site.rules.some(pickable) ? [{ key: 'sel', label: '', sortable: false, filterable: false, required: true, nowrap: true, text: () => '' }] : []),
    { key: 'title', label: t('protset.c_rule'), class: 'c-fill', text: (r) => ruleTitle(site, r) },
    { key: 'cves', label: 'CVE', text: (r) => r.cves.join(' ') },
    { key: 'state', label: t('protset.c_state'), nowrap: true, text: (r) => t('protset.state.' + r.state, { id: r.change_id || '' }) },
  ]
}

async function load() {
  try {
    const d = await get('/protsets')
    data.value = d
    for (const s of d.sets) {
      for (const x of s.sites) {
        const k = s.id + '|' + x.host
        if (!picked[k]) picked[k] = new Set(x.rules.filter((r) => r.default && ['available', 'update'].includes(r.state)).map((r) => r.id))
      }
    }
  } catch (e) { error.value = e }
}

async function propose(site) {
  busy.value = site.host
  errors[site.host] = null
  try {
    const r = await post('/protsets/propose', { set: site.set, host: site.host, rules: picks(site) })
    router.push('/changes/' + r.change_id)
  } catch (e) { errors[site.host] = e } finally { busy.value = '' }
}

onMounted(load)
</script>

<style scoped>
.protacts { margin-top: 12px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
.protdetail { white-space: normal; }
.protdetail p { margin: 4px 0; overflow-wrap: anywhere; }
.protdetail .mono { word-break: break-all; }
.protset .cardhead h2 { display: flex; align-items: baseline; flex-wrap: wrap; }
</style>
