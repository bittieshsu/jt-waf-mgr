#!/usr/bin/env python3
"""Wazuh active response: block the alert's source address on the nginx in front of your sites, through the
jt-waf-mgr IP block API (scope blocks:write), and lift the block when Wazuh sends "delete".

Install on the agent (or manager) that runs the response, as root:
    install -m 750 -o root -g wazuh jt-waf-block.py /var/ossec/active-response/bin/jt-waf-block.py
    install -m 640 -o root -g wazuh /dev/null /var/ossec/etc/jt-waf-block.conf    # then fill it in:
        url = https://waf.example.com
        token = jwm_...            (an API token with blocks:write, limited to this host's address)
        source = wazuh/<this host>
        ttl = 3600                 (seconds, 60 to 604800; the API refuses longer)
and in ossec.conf a <command> (executable jt-waf-block.py, timeout_allowed yes) plus an <active-response> naming the
rules that should block. Standard library only; it never blocks an address the API refuses (internal networks, the
protected list, known scanners).
"""
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request

CONF = os.environ.get('JT_WAF_BLOCK_CONF', '/var/ossec/etc/jt-waf-block.conf')
LOG = '/var/ossec/logs/active-responses.log'
NAME = 'jt-waf-block'


def log(msg):
    try:
        with open(LOG, 'a') as fh:
            fh.write('%s: %s\n' % (NAME, msg))
    except OSError:
        pass


def conf():
    c = {'ttl': '3600', 'source': 'wazuh'}
    with open(CONF) as fh:
        for line in fh:
            line = line.split('#', 1)[0].strip()
            if '=' in line:
                k, v = line.split('=', 1)
                c[k.strip()] = v.strip()
    if not c.get('url', '').startswith('https://') or not c.get('token'):
        raise ValueError('url (https) and token are required in %s' % CONF)
    return c


def call(c, method, path, body=None):
    req = urllib.request.Request(c['url'].rstrip('/') + '/api/v1' + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={'Authorization': 'Bearer ' + c['token'], 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=10, context=ssl.create_default_context()) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def main():
    msg = json.loads(sys.stdin.readline() or '{}')
    command = msg.get('command')
    alert = (msg.get('parameters') or {}).get('alert') or {}
    ip = ((alert.get('data') or {}).get('srcip') or '').strip()
    if command not in ('add', 'delete') or not ip:
        return 0
    if command == 'add':
        # a stateful response asks execd first whether this address is already being handled
        sys.stdout.write(json.dumps({'version': 1, 'origin': {'name': NAME, 'module': 'active-response'},
                                     'command': 'check_keys', 'parameters': {'keys': [ip]}}) + '\n')
        sys.stdout.flush()
        answer = json.loads(sys.stdin.readline() or '{}')
        if answer.get('command') != 'continue':
            return 0
    try:
        c = conf()
    except (OSError, ValueError) as e:
        log('configuration: %s' % e)
        return 1
    rule = (alert.get('rule') or {})
    if command == 'add':
        st = call(c, 'POST', '/blocks', {'ip': ip, 'ttl': int(c['ttl']), 'source': c['source'],
                                         'reason': 'Wazuh rule %s: %s' % (rule.get('id', '?'), str(rule.get('description', ''))[:150])})
    else:
        st = call(c, 'DELETE', '/blocks/%s?source=%s' % (urllib.parse.quote(ip), urllib.parse.quote(c['source'])))
    log('%s %s -> HTTP %s' % (command, ip, st))
    return 0 if st in (200, 201, 404) else 1


if __name__ == '__main__':
    sys.exit(main())
