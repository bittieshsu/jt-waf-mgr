<!-- A value that can be filtered on: the value itself opens its page (`to`) or is plain text; the small funnel icon
     next to it -- or a right-click on the value -- opens the value menu (filter / exclude / open / copy).
     active: 'in' (the current filter), 'out' (excluded now) or ''.  quiet: the icon shows on hover / focus only.
     head: the value as the menu's first row shows it (default: the text shown here); field: what the value is.
     Emits filter(mode) with mode 'in' or 'out'. -->
<template>
  <span class="fv" :class="{ quiet, 'fv-in': active === 'in', 'fv-out': active === 'out' }" @contextmenu="open">
    <RouterLink v-if="to" :to="to" class="fv-text" :data-ip="dataIp || null"><slot /></RouterLink>
    <span v-else class="fv-text" :data-ip="dataIp || null"><slot /></span>
    <button type="button" class="fv-btn" :title="t('filter.menu')" :aria-label="t('filter.menu') + ': ' + label" aria-haspopup="menu" @click.stop="open"><Icon name="filter" /></button>
  </span>
</template>

<script setup>
import { computed } from 'vue'
import { t } from '../i18n.js'
import { filterItems, openValueMenu } from '../valueMenu.js'
import Icon from './Icon.vue'

const props = defineProps({
  value: { type: [String, Number], default: '' },
  text: { type: String, default: '' },          // what the value is called in the menu button's label
  to: { type: [String, Object], default: null },
  openTo: { type: [String, Object], default: null },
  openLabel: { type: String, default: '' },
  dataIp: { type: String, default: '' },
  active: { type: String, default: '' },
  excludable: { type: Boolean, default: true },
  head: { type: String, default: '' },
  field: { type: String, default: '' },
  quiet: Boolean,
})
const emit = defineEmits(['filter'])
const label = computed(() => props.text || String(props.value ?? ''))
function open(e) {
  e.preventDefault()
  const box = e.currentTarget && e.currentTarget.closest ? e.currentTarget.closest('.fv') : null
  const shown = box && box.querySelector('.fv-text') ? box.querySelector('.fv-text').textContent : ''
  openValueMenu(e, filterItems({ value: props.value, active: props.active || null, excludable: props.excludable,
    onFilter: (mode) => emit('filter', mode), openTo: props.openTo, openLabel: props.openLabel,
    head: props.head || shown || label.value, field: props.field }))
}
</script>
