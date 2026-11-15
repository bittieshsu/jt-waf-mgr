// The app's own confirmation dialog (never the browser's window.confirm / alert / prompt: they ignore the theme and
// the language, and a browser may suppress them). One dialog, mounted once in App.vue (ConfirmDialog.vue):
//   if (!(await askConfirm(message, { ok: label, danger: true }))) return
import { reactive } from 'vue'

export const cdialog = reactive({ open: false, message: '', title: '', ok: '', danger: false, resolve: null, opener: null })

export function askConfirm(message, { title = '', ok = '', danger = false } = {}) {
  if (cdialog.resolve) cdialog.resolve(false)          // a second question replaces the first (answered "no")
  return new Promise((resolve) => {
    Object.assign(cdialog, { open: true, message, title, ok, danger, resolve, opener: document.activeElement })
  })
}

export function answerConfirm(yes) {
  const { resolve, opener } = cdialog
  Object.assign(cdialog, { open: false, resolve: null, opener: null })
  if (resolve) resolve(!!yes)
  if (opener && opener.focus && document.contains(opener)) opener.focus({ preventScroll: true })
}
