<!-- Ranked horizontal bars, one or more stacked series, value at the tip, hover / focus tooltip.
     items: [{ key, label, values: { <seriesKey>: n }, to? (router link), mono?, sub?, active?, head? (the value menu's first row) }]
     series: [{ key, label, tone }]   (2+ series get a legend)
     pickable: the label keeps following `to` (or is plain text); its funnel icon, a right-click on it, or a click on
     the bar opens the value menu, which emits `pick(item, mode)` (mode 'in' filter, 'out' exclude -- the latter only
     with `excludable`). item.active: true / 'in' (the current filter) or 'out' (excluded now). -->
<template>
  <div class="hbars" :class="{ 'hb-inl': inlineSub }">
    <div v-if="!items.length" class="empty small">{{ t('common.no_data') }}</div>
    <div v-for="it in items" :key="it.key" class="hb-row" :class="{ 'hb-on': pickable && it.active }">
      <div class="hb-label" :class="{ mono: it.mono || mono }" :data-ip="pickable ? null : (it.ip || null)">
        <div v-if="pickable" class="hb-line">
          <FilterValue :value="it.key" :text="clip(it.label, 100)" :head="String(it.head || it.label || '')" :field="field" :to="it.to || null" :data-ip="it.ip || ''" :active="mode(it)" :excludable="excludable"
                       @filter="(m) => pick(it, m)">{{ clip(it.label) }}</FilterValue>
        </div>
        <template v-else><RouterLink v-if="it.to" :to="it.to">{{ clip(it.label) }}</RouterLink><span v-else>{{ clip(it.label) }}</span></template>
        <div v-if="it.sub && !inlineSub" class="sub">{{ clip(it.sub, 120) }}</div>
      </div>
      <!-- inlineSub: the sub text (origin, country) is a column of its own, aligned from row to row -->
      <div v-if="inlineSub" class="hb-sub sub">{{ it.sub ? clip(it.sub, 120) : '' }}</div>
      <div class="hb-bar" :class="{ 'hb-pickbar': pickable }" tabindex="0" @pointermove="show($event, it)" @pointerleave="hide" @focus="show($event, it)" @blur="hide"
           @click="pickable && menu($event, it)" @keydown.enter.prevent="pickable && menu($event, it)" @contextmenu="pickable && menu($event, it)">
        <span v-for="s in series.filter((x) => (it.values[x.key] || 0) > 0)" :key="s.key" class="hb-seg" :class="'tone-' + s.tone" :style="{ width: w(it.values[s.key]) + '%' }"></span>
      </div>
      <div class="hb-num">{{ fmtNum(sum(it)) }}</div>
    </div>
    <div v-if="series.length > 1 && items.length" class="legend">
      <span v-for="s in series" :key="s.key" class="lg-item"><span class="lg" :class="'tone-' + s.tone"></span>{{ s.label }}</span>
    </div>
    <ChartTip :tip="tip" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '../../i18n.js'
import { fmtNum } from '../../util.js'
import { useTip } from './tip.js'
import ChartTip from './ChartTip.vue'
import FilterValue from '../FilterValue.vue'
import { filterItems, openValueMenu } from '../../valueMenu.js'

const props = defineProps({
  items: { type: Array, default: () => [] },
  series: { type: Array, default: () => [{ key: 'value', label: '', tone: 's1' }] },
  valueLabel: { type: String, default: '' },      // tooltip label for a single series without its own label
  mono: Boolean,
  pickable: Boolean,
  openLabel: { type: String, default: '' },
  inlineSub: Boolean,     // the sub text (origin, country) on the label's line instead of a second line
  field: { type: String, default: '' },    // what the values are (the value menu's first row)
  excludable: Boolean,    // the value menu also offers "exclude"
})
const emit = defineEmits(['pick'])
const { tip, at, hide } = useTip()
function sum(it) { return props.series.reduce((s, x) => s + (it.values[x.key] || 0), 0) }
const max = computed(() => Math.max(1, ...props.items.map(sum)))
function w(n) { return ((n || 0) / max.value) * 100 }
function clip(s, n = 80) { s = String(s ?? ''); return s.length > n ? s.slice(0, n - 1) + '…' : s }
function show(e, it) {
  at(e, clip(it.label, 100), props.series.map((s) => ({ value: fmtNum(it.values[s.key] || 0), label: s.label || props.valueLabel || t('chart.count'), tone: props.series.length > 1 ? s.tone : null })))
}
function mode(it) { return it.active === 'out' ? 'out' : it.active ? 'in' : '' }
function pick(it, m = 'in') { hide(); emit('pick', it, m) }
function menu(e, it) {
  e.preventDefault()
  hide()
  openValueMenu(e, filterItems({ value: it.key, active: mode(it) || null, excludable: props.excludable, onFilter: (m) => pick(it, m),
    openTo: it.to || null, openLabel: props.openLabel, head: String(it.head || it.label || ''), field: props.field }))
}
</script>
