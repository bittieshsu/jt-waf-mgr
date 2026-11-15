// The name a link button uses for the page it goes to ("Go to the Rules page"): the same words as the menu.
import { t } from './i18n.js'

const KEYS = {
  '/': 'nav.dashboard', '/events': 'nav.events_list', '/alerts': 'nav.alerts', '/analysis': 'nav.analysis', '/reviews': 'nav.reviews', '/intel': 'nav.intel',
  '/lookup': 'nav.lookup', '/traffic': 'nav.traffic', '/blocks': 'nav.blocks', '/rules': 'nav.rules_list', '/vhosts': 'nav.vhosts',
  '/countries': 'nav.countries', '/crs': 'nav.crs', '/managed': 'nav.managed', '/changes': 'nav.changes_list',
  '/changes/new': 'changes.new', '/config-changes': 'nav.config_changes', '/guide': 'nav.guide', '/account': 'nav.account',
  '/admin/users': 'nav.users', '/admin/tokens': 'nav.tokens', '/admin/audit': 'nav.audit', '/admin/system': 'nav.system',
  '/admin/compliance': 'nav.compliance', '/admin/settings': 'nav.settings', '/admin/notify': 'nav.notify',
}

export function goToLabel(path) {
  const k = KEYS[String(path || '').split('?')[0]]
  return k ? t('guide.go_page', { page: t(k) }) : t('guide.open_page')
}
