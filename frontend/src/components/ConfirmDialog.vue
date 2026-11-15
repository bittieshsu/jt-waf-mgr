<!-- The confirmation dialog of the app (confirmDialog.js): the page's own colours and language. Enter or the
     confirm button says yes; Esc, the cancel button or a click outside says no; Tab stays inside; focus goes back to
     the button that asked. A dangerous action (danger) starts on "cancel". -->
<template>
  <Teleport to="body">
    <div v-if="cdialog.open" class="modalback cdback" @click.self="answerConfirm(false)">
      <section ref="el" class="card modal cdialog" role="alertdialog" aria-modal="true" :aria-labelledby="'cd-title'"
               :aria-describedby="'cd-msg'" tabindex="-1" @keydown="onKey">
        <h2 id="cd-title"><Icon :name="cdialog.danger ? 'warning' : 'help'" />{{ cdialog.title || t('confirm.title') }}</h2>
        <p id="cd-msg" class="cd-msg">{{ cdialog.message }}</p>
        <div class="actions cd-actions">
          <button ref="cancelBtn" type="button" class="btn ghost" data-cd="cancel" @click="answerConfirm(false)"><Icon name="cancel" />{{ t('common.cancel') }}</button>
          <button ref="okBtn" type="button" class="btn" :class="cdialog.danger ? 'danger' : 'primary'" data-cd="ok" @click="answerConfirm(true)">
            <Icon :name="cdialog.danger ? 'warning' : 'check'" />{{ cdialog.ok || t('common.ok') }}</button>
        </div>
      </section>
    </div>
  </Teleport>
</template>

<script setup>
import { nextTick, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { cdialog, answerConfirm } from '../confirmDialog.js'
import { hide as hideIpCard } from '../ipcard.js'
import { hideTip } from '../tooltip.js'
import { closeValueMenu } from '../valueMenu.js'
import { t } from '../i18n.js'
import Icon from './Icon.vue'

const el = ref(null)
const okBtn = ref(null)
const cancelBtn = ref(null)
const route = useRoute()

watch(() => cdialog.open, async (on) => {
  if (!on) return
  hideIpCard()
  hideTip()
  closeValueMenu(false)
  await nextTick()
  const b = cdialog.danger ? cancelBtn.value : okBtn.value
  if (b) b.focus({ preventScroll: true })
})
watch(() => route.fullPath, () => { if (cdialog.open) answerConfirm(false) })

function onKey(e) {
  if (e.key === 'Escape') {
    e.preventDefault()
    e.stopPropagation()
    answerConfirm(false)
  } else if (e.key === 'Tab') {
    const bs = [cancelBtn.value, okBtn.value].filter(Boolean)
    const i = bs.indexOf(document.activeElement)
    e.preventDefault()
    bs[(i + (e.shiftKey ? bs.length - 1 : 1)) % bs.length].focus()
  }
}
</script>
