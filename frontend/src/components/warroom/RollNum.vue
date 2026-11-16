<!-- A number that rolls when it changes, like an odometer: each changed character slides in from above (moving down)
     when the number grew, from below (moving up) when it shrank. Characters that stay the same do not move. The first
     value, a change that is not a number (a dash, another language) and a viewer who asked for less motion: no roll.
     props: value (the formatted text, e.g. "1,234" or "45%")   still (no motion) -->
<template>
  <span class="rn"><span class="sr-only">{{ text }}</span><span v-for="c in cells" :key="c.key" class="rn-cell" aria-hidden="true"><span v-if="c.dir" class="rn-stack" :class="'rn-' + c.dir"><span>{{ c.dir === 'down' ? c.now : c.was }}</span><span>{{ c.dir === 'down' ? c.was : c.now }}</span></span><template v-else>{{ c.now }}</template></span></span>
</template>

<script setup>
import { computed, ref, watch } from 'vue'

const props = defineProps({
  value: { type: [String, Number], default: '' },
  still: Boolean,
})
const text = computed(() => String(props.value ?? ''))
const cells = ref([])
const systemStill = () => !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches)
let gen = 0

// the number in a formatted text ("1,234" -> 1234, "45%" -> 45); NaN when there is none ("—")
function num(s) {
  const d = String(s).replace(/[^\d.-]/g, '')
  return /\d/.test(d) ? Number(d) : NaN
}

function build(now, was) {
  now = String(now ?? '')
  const old = was == null ? null : String(was)
  const a = num(now), b = old == null ? NaN : num(old)
  const dir = old == null || props.still || systemStill() || !Number.isFinite(a) || !Number.isFinite(b) || a === b ? '' : (a > b ? 'down' : 'up')
  gen++
  const out = []
  const n = now.length, m = old ? old.length : 0
  for (let i = 0; i < n; i++) {
    const ch = now[i]
    const j = m - (n - i)                      // the same place counted from the right (units under units)
    const prev = j >= 0 ? old[j] : ''
    const moving = dir && prev !== ch
    out.push({ key: moving ? 'g' + gen + '-' + i : 's' + (n - i) + '-' + ch, now: ch, was: prev || ' ', dir: moving ? dir : '' })
  }
  cells.value = out
}
watch(() => props.value, (v, o) => build(v, o), { immediate: true })
</script>

<style scoped>
.rn { display: inline-flex; font-variant-numeric: tabular-nums; }
.rn-cell { display: inline-block; height: 1.15em; line-height: 1.15em; overflow: hidden; vertical-align: bottom; white-space: pre; }
.rn-stack { display: flex; flex-direction: column; }
.rn-stack > span { display: block; height: 1.15em; text-align: center; }
/* grew: the new character comes down from above; shrank: it comes up from below */
.rn-down { animation: rn-down .55s cubic-bezier(.2, .8, .2, 1) both; }
.rn-up { animation: rn-up .55s cubic-bezier(.2, .8, .2, 1) both; }
@keyframes rn-down { from { transform: translateY(-50%); } to { transform: none; } }
@keyframes rn-up { from { transform: none; } to { transform: translateY(-50%); } }
@media (prefers-reduced-motion: reduce) { .rn-down, .rn-up { animation: none; } .rn-down { transform: none; } .rn-up { transform: translateY(-50%); } }
</style>
