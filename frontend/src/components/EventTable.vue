<!-- Event list (sort / filter / columns / pages through DataTable). Attacker-controlled fields stay text.
     filterable: each value has the value menu (its funnel icon, or a right-click): it emits filter(key, value, mode)
     with key one of host, src_ip, origin, outcome, decided_by, rule_id, family (the event-list query names) and mode
     'in' (filter) or 'out' (exclude). The value itself opens its page (address -> lookup, rule -> rule page); the
     time and request open the event. filters: the current query, to offer "remove filter" for an active one. -->
<template>
  <DataTable :id="tableId" :columns="cols" :rows="items" row-key="id" :default-sort="{ key: 'ts', dir: -1 }"
             :page-size="pageSize" :toolbar="toolbar" :empty="emptyText || ''" class="events">
    <template #cell-ts="{ row }"><RouterLink :to="'/events/' + row.id">{{ fmtShortTime(row.ts) }}</RouterLink></template>
    <template #cell-outcome="{ row }">
      <FilterValue v-if="filterable" :value="outKey(row)" :text="t('event.outcome')" :active="act('outcome', outKey(row))" @filter="(m) => emit('filter', 'outcome', outKey(row), m)"><OutcomeBadge :outcome="row.outcome" :decided-by="row.decided_by" :redirected="row.redirected" /></FilterValue>
      <OutcomeBadge v-else :outcome="row.outcome" :decided-by="row.decided_by" :redirected="row.redirected" />
    </template>
    <template #cell-host="{ row }">
      <FilterValue v-if="filterable && row.host" :value="row.host" :active="act('host', row.host)" @filter="(m) => emit('filter', 'host', row.host, m)"><TruncText :text="row.host" :max="80" /></FilterValue>
      <TruncText v-else :text="row.host" :max="80" />
    </template>
    <template #cell-request="{ row }">
      <RouterLink :to="'/events/' + row.id" class="reqlink">
        <span class="method">{{ safeText(row.method, 12) }}</span>
        <TruncText :text="pathWithQuery(row)" :max="300" mono />
      </RouterLink>
      <div v-if="row.message" class="sub"><TruncText :text="row.message" :max="200" /></div>
    </template>
    <template #cell-src_ip="{ row }"><span class="srcline">
      <FilterValue v-if="filterable" class="mono" :value="row.src_ip" :to="'/lookup/' + encodeURIComponent(row.src_ip)" :data-ip="row.src_ip"
                   :active="act('src_ip', row.src_ip)" @filter="(m) => emit('filter', 'src_ip', row.src_ip, m)">{{ safeText(row.src_ip, 45) }}</FilterValue>
      <RouterLink v-else :to="'/lookup/' + encodeURIComponent(row.src_ip)" class="mono" :data-ip="row.src_ip">{{ safeText(row.src_ip, 45) }}</RouterLink>
      <GeoTag :geo="row.src_geo" compact />
      <FilterValue v-if="filterable" :value="row.origin || 'external'" :text="t('event.origin')" :active="act('origin', row.origin || 'external')" @filter="(m) => emit('filter', 'origin', row.origin || 'external', m)"><OriginBadge :origin="row.origin" /></FilterValue>
      <OriginBadge v-else :origin="row.origin" />
    </span></template>
    <template #cell-status="{ row }"><span class="mono">{{ row.status ?? '—' }}</span></template>
    <template #cell-rules="{ row }">
      <template v-if="filterable">
        <FilterValue v-for="f in row.families || []" :key="'f' + f" quiet class="chip fam" :value="f" :text="t('family.' + f)" :active="act('family', f)" @filter="(m) => emit('filter', 'family', f, m)">{{ t('family.' + f) }}</FilterValue>
        <FilterValue v-for="r in (row.local_rule_ids || [])" :key="'l' + r" quiet class="chip local mono" :value="String(r)" :to="'/rules/' + r" :active="act('rule_id', String(r))" @filter="(m) => emit('filter', 'rule_id', String(r), m)">{{ r }}</FilterValue>
        <span class="rules-ids mono"><FilterValue v-for="r in otherIds(row).shown" :key="'r' + r" quiet class="ruleid" :value="String(r)" :to="'/rules/' + r" :active="act('rule_id', String(r))" @filter="(m) => emit('filter', 'rule_id', String(r), m)">{{ r }}</FilterValue><template v-if="otherIds(row).more"> +{{ otherIds(row).more }}</template></span>
      </template>
      <template v-else>
        <span v-for="f in row.families || []" :key="'f' + f" class="chip fam">{{ t('family.' + f) }}</span>
        <span v-for="r in (row.local_rule_ids || [])" :key="'l' + r" class="chip local mono">{{ r }}</span>
        <span class="rules-ids mono">{{ ruleIds(row) }}</span>
      </template>
    </template>
    <template #cell-decided_by="{ row }">
      <FilterValue v-if="filterable && row.decided_by" :value="row.decided_by" :text="t('decided.' + row.decided_by)" :active="act('decided_by', row.decided_by)" @filter="(m) => emit('filter', 'decided_by', row.decided_by, m)">{{ t('decided.' + row.decided_by) }}</FilterValue>
      <template v-else>{{ row.decided_by ? t('decided.' + row.decided_by) : '—' }}</template>
    </template>
    <template #cell-origin="{ row }">
      <FilterValue v-if="filterable" :value="row.origin || 'external'" :text="t('event.origin')" :active="act('origin', row.origin || 'external')" @filter="(m) => emit('filter', 'origin', row.origin || 'external', m)"><OriginBadge :origin="row.origin" /></FilterValue>
      <OriginBadge v-else :origin="row.origin" />
    </template>
  </DataTable>
</template>

<script setup>
import GeoTag from './GeoTag.vue'
import { countryName } from '../util.js'
function geoText(g) { return g && g.scope === 'external' ? [g.cc, countryName(g.cc, lang.value), g.org].filter(Boolean).join(' ') : '' }
import { computed } from 'vue'
import { t, lang } from '../i18n.js'
import { fmtShortTime, fmtTime, pathWithQuery, safeText } from '../util.js'
import DataTable from './DataTable.vue'
import OutcomeBadge from './OutcomeBadge.vue'
import OriginBadge from './OriginBadge.vue'
import TruncText from './TruncText.vue'
import FilterValue from './FilterValue.vue'

const props = defineProps({
  items: { type: Array, default: () => [] },
  hideHost: Boolean,
  emptyText: String,
  tableId: { type: String, default: 'events' },   // remembers columns / sort / page size per place
  pageSize: { type: Number, default: 25 },
  toolbar: { type: Boolean, default: true },
  filterable: Boolean,     // values (site, address, origin, outcome, rule, attack type) have the value menu
  filters: { type: Object, default: () => ({}) },   // the current query (key / not_key)
})
const emit = defineEmits(['filter'])
function outKey(row) { return row.redirected ? 'redirected' : row.outcome }
// 'in' when the value is the filter now, 'out' when it is excluded now
function act(key, v) {
  const f = props.filters || {}
  return String(f[key] ?? '') === String(v) ? 'in' : String(f['not_' + key] ?? '') === String(v) ? 'out' : ''
}

function outcomeText(e) {
  if (e.redirected) return t('outcome.redirected')
  return e.outcome === 'blocked' ? t('outcome.blocked') + (e.decided_by ? ' ' + t('decided.' + e.decided_by) : '') : t('outcome.logged')
}
const cols = computed(() => [
  { key: 'ts', label: t('event.time'), nowrap: true, required: true, text: (e) => fmtTime(e.ts) },
  { key: 'outcome', label: t('event.outcome'), value: (e) => (e.outcome === 'blocked' ? 0 : 1) + ':' + (e.decided_by || ''), text: outcomeText },
  ...(props.hideHost ? [] : [{ key: 'host', label: t('event.host'), class: 'c-host' }]),
  { key: 'request', label: t('event.request'), class: 'c-req', value: (e) => pathWithQuery(e), text: (e) => (e.method || '') + ' ' + pathWithQuery(e) + ' ' + (e.message || '') },
  { key: 'src_ip', label: t('event.source'), nowrap: true, class: 'c-src', text: (e) => (e.src_ip || '') + ' ' + t('origin.' + (e.origin || 'external')) + ' ' + geoText(e.src_geo) },
  { key: 'status', label: t('event.status'), align: 'num' },
  { key: 'rules', label: t('event.rules'), class: 'c-rules', value: (e) => (e.rule_ids || []).join(' '),
    text: (e) => (e.families || []).map((f) => t('family.' + f)).join(' ') + ' ' + (e.rule_ids || []).join(' ') },
  { key: 'decided_by', label: t('event.decided_by'), hidden: true, text: (e) => (e.decided_by ? t('decided.' + e.decided_by) : '') },
  { key: 'origin', label: t('event.origin'), hidden: true, text: (e) => t('origin.' + (e.origin || 'external')) },
])

function otherIds(e) {
  const local = new Set(e.local_rule_ids || [])
  const ids = (e.rule_ids || []).filter((r) => !local.has(r))
  return { shown: ids.slice(0, 6), more: Math.max(0, ids.length - 6) }
}
function ruleIds(e) {
  const o = otherIds(e)
  return o.shown.join(' ') + (o.more ? ' +' + o.more : '')
}
</script>

