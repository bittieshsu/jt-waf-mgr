// The value menu (like Graylog's field-value actions): a right-click on a value, or its small funnel icon, opens one
// menu with "filter by this value" / "exclude this value" (when the list supports it), an "open" link where there is
// a page for it, and "copy". Clicking the value itself does its own thing (opens its page), never filters.
import { reactive } from 'vue'
import { t } from './i18n.js'

export const vmenu = reactive({ open: false, x: 0, y: 0, items: [], opener: null })

// items for a filterable value. active: 'in' (it is the filter now), 'out' (it is excluded now) or null.
export function filterItems({ value, active = null, excludable = true, onFilter, openTo = null, openLabel = '' }) {
  const items = []
  if (onFilter) {
    items.push({ key: 'in', icon: active === 'in' ? 'clear' : 'filter', label: t(active === 'in' ? 'filter.menu_in_off' : 'filter.menu_in'), run: () => onFilter('in') })
    if (excludable) items.push({ key: 'out', icon: active === 'out' ? 'clear' : 'hide', label: t(active === 'out' ? 'filter.menu_out_off' : 'filter.menu_out'), run: () => onFilter('out') })
  }
  if (openTo) items.push({ key: 'open', icon: 'external', label: openLabel || t('filter.open'), to: openTo })
  if (value !== undefined && value !== null && String(value) !== '') items.push({ key: 'copy', icon: 'page', label: t('filter.menu_copy'), run: () => copy(String(value)) })
  return items
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    try { document.execCommand('copy') } catch { /* nothing more to try */ }
    ta.remove()
  }
}

// ev: the contextmenu event (menu at the pointer) or the click on the funnel (menu under it)
export function openValueMenu(ev, items) {
  if (!items.length) return
  let x, y
  if (ev && ev.type === 'contextmenu' && (ev.clientX || ev.clientY)) {
    x = ev.clientX
    y = ev.clientY
  } else {
    const r = (ev && ev.currentTarget ? ev.currentTarget : document.body).getBoundingClientRect()
    x = r.left
    y = r.bottom + 4
  }
  Object.assign(vmenu, { open: true, x, y, items, opener: ev ? ev.currentTarget : null })
}

export function closeValueMenu(refocus) {
  const o = vmenu.opener
  vmenu.open = false
  vmenu.items = []
  vmenu.opener = null
  if (refocus && o && o.focus) o.focus()
}
