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
            out.append(_item('crs_missing', 'important', '/crs'))
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
    if (installed if installed is not None else _installed()) and not os.path.exists(APPLY_PATH):
        out.append(_item('apply_off', 'important', None))
    if not _notify_ready(cfg):
        out.append(_item('notify_off', 'important', '/admin/notify', '#uiset-notify'))
    if not cfg['hub'].get('enabled'):
        out.append(_item('hub_off', 'important', '/admin/settings', '#uiset-hub'))
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
