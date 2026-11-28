#!/usr/bin/env python3
"""The reverse proxy examples on the project page (docs/proxy.html), written by the same generator as the sites page's
"example for a new site" (jtwafmgr.vhostconf.example), with synthetic names and addresses only.

  tools/make_proxy_examples.py           rewrite the block between the markers in docs/proxy.html
  tools/make_proxy_examples.py --check   exit 1 when the page differs from what the generator writes now
"""
import html
import os
import sys

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOP)
from jtwafmgr import vhostconf  # noqa: E402

PAGE = os.path.join(TOP, 'docs', 'proxy.html')
NETS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '::1']
CERT = {'cert': '/etc/ssl/example/fullchain.pem', 'key': '/etc/ssl/example/privkey.pem'}
MEM = 8 << 30          # an 8 GB host: no "too big for this host" note in the examples

# (id, options): each has its own place on the page, between <!-- proxy-example:ID:begin --> and ...:end -->
EXAMPLES = [
    ('ex-generic', dict(CERT, preset='generic', host='app.example.com', backend='http://192.0.2.20:8080')),
    ('ex-websocket', dict(CERT, preset='generic', host='chat.example.com', backend='http://192.0.2.21:3000',
                          websocket=True)),
    ('ex-synology', dict(CERT, preset='synology', host='nas.example.com', port=5001,
                         backend='https://192.0.2.18:5001', photos_ios=True)),
    ('ex-qnap', dict(CERT, preset='qnap', host='qnap.example.com', port=443, backend='https://192.0.2.19:443')),
]


def markers(eid):
    return '<!-- proxy-example:%s:begin -->' % eid, '<!-- proxy-example:%s:end -->' % eid


def examples():
    """[(id, file path, text)]"""
    out = []
    for eid, opts in EXAMPLES:
        o = vhostconf.example(opts, NETS, mem_bytes=MEM)
        out.append((eid, o['path'], o['text']))
    return out


def block(eid, path, text):
    """One example: its file, a copy button, the text, and the commands that load it."""
    name = os.path.basename(path)
    steps = 'sudo ln -s %s /etc/nginx/sites-enabled/%s\nsudo nginx -t && sudo systemctl reload nginx' % (path, name)
    b, e = markers(eid)
    return '\n'.join([
        b,
        '<div class="ex" id="%s-box">' % eid,
        '  <div class="exbar"><span class="exlbl" data-t="save_as"></span> <code class="path">%s</code>'
        '<button type="button" class="copy" data-copy="%s" data-t="copy"></button></div>' % (html.escape(path), eid),
        '  <pre class="conf"><code id="%s">%s</code></pre>' % (eid, html.escape(text)),
        '  <div class="exbar"><span class="exlbl" data-t="then_run"></span>'
        '<button type="button" class="copy" data-copy="%s-steps" data-t="copy"></button></div>' % eid,
        '  <pre class="cmd"><code id="%s-steps">%s</code></pre>' % (eid, html.escape(steps)),
        '</div>',
        e])


def render(page_text):
    """The page with every generated example in its place (ValueError when a marker is missing)."""
    for eid, path, text in examples():
        b, e = markers(eid)
        i, j = page_text.find(b), page_text.find(e)
        if i < 0 or j < i:
            raise ValueError('markers for %s not found' % eid)
        page_text = page_text[:i] + block(eid, path, text) + page_text[j + len(e):]
    return page_text


def main(argv):
    with open(PAGE, encoding='utf-8') as fh:
        cur = fh.read()
    new = render(cur)
    if '--check' in argv:
        if new != cur:
            print('docs/proxy.html: the examples differ from the generator (run tools/make_proxy_examples.py)')
            return 1
        print('proxy examples: OK (%d)' % len(EXAMPLES))
        return 0
    if new != cur:
        with open(PAGE, 'w', encoding='utf-8') as fh:
            fh.write(new)
    print('proxy examples: written (%d)' % len(EXAMPLES))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
