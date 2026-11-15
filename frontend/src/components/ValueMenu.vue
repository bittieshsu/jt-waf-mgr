<!-- The one value menu of the app (valueMenu.js): mounted once in App.vue, positioned at the pointer or under the
     funnel icon, kept inside the window. Esc, a click outside, scrolling or a page change close it. -->
<template>
  <Teleport to="body">
    <div v-if="vmenu.open" ref="el" class="vmenu" role="menu" :style="{ left: pos.x + 'px', top: pos.y + 'px' }" @keydown="onKey">
      <template v-for="it in vmenu.items" :key="it.key">
        <RouterLink v-if="it.to" :to="it.to" class="vm-item" role="menuitem" @click="closeValueMenu(false)"><Icon :name="it.icon" />{{ it.label }}</RouterLink>
        <button v-else type="button" class="vm-item" role="menuitem" @click="run(it)"><Icon :name="it.icon" />{{ it.label }}</button>
      </template>
    </div>
  </Teleport>
</template>

<script setup>
import { nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { vmenu, closeValueMenu } from '../valueMenu.js'
import { hide as hideIpCard } from '../ipcard.js'
import { hideTip } from '../tooltip.js'
import Icon from './Icon.vue'

const el = ref(null)
const pos = reactive({ x: 0, y: 0 })
const route = useRoute()
let openedAt = 0

watch(() => vmenu.open && vmenu.items, async (on) => {
  if (!on) return
  hideIpCard()                              // the address card, a tooltip and the menu never cover each other
  hideTip()
  openedAt = Date.now()
  pos.x = vmenu.x
  pos.y = vmenu.y
  await nextTick()
  const m = el.value
  if (!m) return
  const r = m.getBoundingClientRect()
  pos.x = Math.max(6, Math.min(vmenu.x, window.innerWidth - r.width - 6))
  pos.y = vmenu.y + r.height > window.innerHeight - 6 ? Math.max(6, vmenu.y - r.height - 8) : vmenu.y
  const first = m.querySelector('.vm-item')
  if (first) first.focus({ preventScroll: true })
})
watch(() => route.fullPath, () => closeValueMenu(false))

function run(it) {
  closeValueMenu(true)
  it.run()
}
function onKey(e) {
  const items = [...(el.value ? el.value.querySelectorAll('.vm-item') : [])]
  const i = items.indexOf(document.activeElement)
  if (e.key === 'Escape') { e.preventDefault(); closeValueMenu(true) }
  else if (e.key === 'ArrowDown') { e.preventDefault(); items[(i + 1) % items.length].focus() }
  else if (e.key === 'ArrowUp') { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus() }
  else if (e.key === 'Tab') closeValueMenu(false)
}
function onDown(e) { if (vmenu.open && el.value && !el.value.contains(e.target)) closeValueMenu(false) }
// scrolling the page closes it -- not the scroll that opening it caused (the funnel brought into view, the focus)
function onScroll(e) {
  if (!vmenu.open || Date.now() - openedAt < 400 || (el.value && e && e.target instanceof Node && el.value.contains(e.target))) return
  closeValueMenu(false)
}
onMounted(() => {
  document.addEventListener('pointerdown', onDown, true)
  window.addEventListener('scroll', onScroll, true)
  window.addEventListener('resize', onScroll)
})
onBeforeUnmount(() => {
  document.removeEventListener('pointerdown', onDown, true)
  window.removeEventListener('scroll', onScroll, true)
  window.removeEventListener('resize', onScroll)
})
</script>
