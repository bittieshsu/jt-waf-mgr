"""What is not installed or not turned on yet, for the dashboard (0.5.31).

A new host starts with most protection off: no OWASP CRS, nothing adopted, no site with the WAF on, no notifications.
The system check lists each of these somewhere in a long page; the dashboard names them in one place, with where to
fix each one. Two levels:

- important: the WAF does not protect, or nobody hears about it (no CRS, not adopted, no site with the WAF on, the
  apply program not armed, no notifications, CrowdSec virtual patches off);
- suggested: a feature that adds protection or saves work (event analysis, threat intelligence, IP reputation,
  country lists, temporary IP blocks).

Only reads the configuration and files already loaded; cheap enough for every dashboard load.
"""
import os

APPLY_PATH = '/etc/systemd/system/multi-user.target.wants/jt-waf-mgr-apply.path'


def _installed():
    return os.path.exists('/etc/systemd/system/jt-waf-mgr.service')


def _item(key, level, link, hash_=None, **details):
    out = {'key': key, 'level': level, 'link': link}
    if hash_:
        out['hash'] = hash_
    if details:
        out['details'] = details
    return out


def _notify_ready(cfg):
    n = cfg['notify']
    if not n.get('enabled'):
        return False
    return any(n.get(k) for k in n if k.endswith('_enabled'))


def _crs_item(app):
    """No CRS loaded. 0.5.32: say how far it got -- downloaded and verified but not installed, or a change waiting --
    instead of only "not installed" (the CRS page's switch turns on the download, not the installation)."""
    from . import changes, crsupdate
    try:
        row = app.db.one("SELECT id FROM changes WHERE op='crs' AND state NOT IN (%s) ORDER BY id DESC LIMIT 1"
                         % ','.join('?' * len(changes.FINAL)), changes.FINAL)
    except Exception:          # noqa: BLE001
        row = None
    if row:
        return _item('crs_pending', 'important', '/changes/%d' % row[0], change=row[0])
    st = crsupdate.read_status(app.cfg) if app.cfg['crs'].get('manage') else {}
    staged = (st.get('staged') or {}).get('version')
    if staged:
        return _item('crs_staged', 'important', '/crs', version=staged)
    return _item('crs_missing', 'important', '/crs')


def _single_admin_needed(app):
    """One person can approve (no second approver or admin) and the proposer may not approve their own change: every
    change waits for ever."""
    try:
        if app.workflow.setting('approval.single_admin_mode'):
            return False
        n = app.db.one("SELECT COUNT(*) FROM users WHERE disabled=0 AND role IN ('admin', 'approver')")[0]
    except Exception:          # noqa: BLE001
        return False
    return n == 1


def items(app, installed=None):
    """[{'key', 'level': 'important' | 'suggested', 'link', 'hash'?, 'details'?}], important first."""
    cfg = app.cfg
    out = []
    try:
        n, m = app.site.load()
    except Exception:          # noqa: BLE001 -- the dashboard never fails over this
        n = m = None
    if m is not None:
        crs = m.crs_status()
        if not crs.get('version'):
            out.append(_crs_item(app))
    try:
        adopted = app.workflow.managed.adopted()
    except Exception:          # noqa: BLE001
        adopted = True
    if not adopted:
        out.append(_item('not_adopted', 'important', '/managed'))
    if n is not None:
        servers = n.servers()
        if servers and not any(s.get('waf') in ('on', 'block') for s in servers):
            out.append(_item('no_waf_site', 'important', '/vhosts'))
    single = _single_admin_needed(app)
    if single:
        out.append(_item('single_admin_off', 'important', '/admin/settings', '#workflow-settings'))
    if (installed if installed is not None else _installed()) and not os.path.exists(APPLY_PATH):
        out.append(_item('apply_off', 'important', None))
    if not _notify_ready(cfg):
        out.append(_item('notify_off', 'important', '/admin/notify', '#uiset-notify'))
    if not cfg['hub'].get('enabled'):
        out.append(_item('hub_off', 'important', '/crowdsec'))
    if not (cfg['llm'].get('enabled') and cfg['analyst'].get('enabled')):
        out.append(_item('analyst_off', 'suggested', '/admin/settings', '#uiset-llm'))
    if not cfg['intel'].get('enabled'):
        out.append(_item('intel_off', 'suggested', '/admin/settings', '#uiset-intel'))
    if not cfg['iprep'].get('enabled'):
        out.append(_item('iprep_off', 'suggested', '/admin/settings', '#uiset-iprep'))
    if not cfg['countries'].get('enabled'):
        out.append(_item('countries_off', 'suggested', '/admin/settings', '#uiset-countries'))
    if not cfg['blocks'].get('enabled'):
        out.append(_item('blocks_off', 'suggested', '/admin/settings', '#uiset-blocks'))
    return out
