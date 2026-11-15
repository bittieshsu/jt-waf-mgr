#!/usr/bin/env python3
"""Draw the three ways to use jt-waf-mgr (docs/modes/deploy-modes.<lang>.svg), one picture per language:
  1. nginx is the web server: the sites live on the nginx host;
  2. nginx is a reverse proxy: the sites run on other servers behind it;
  3. both on one host: some sites local, some proxied.
In every case ModSecurity (with the OWASP CRS) inspects the requests inside nginx and jt-waf-mgr manages it.
Plain SVG, text as text (no fonts embedded), colours of the project site. Run after changing the words below."""
import os
from xml.sax.saxutils import escape

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'docs', 'modes')

BLUE, BLUE_D, ORANGE, INK, TEXT, MUTED, BORDER, PANEL2 = '#2563c4', '#1a4c9c', '#e8703f', '#0f172a', '#334155', '#64748b', '#d5dde9', '#f6f8fc'
FONT = "system-ui, -apple-system, 'Segoe UI', Roboto, 'Noto Sans TC', 'Noto Sans JP', sans-serif"

WORDS = {
    'en': {
        'titles': ('nginx is the web server', 'nginx as a reverse proxy', 'Both on one host'),
        'users': 'Visitors / Internet', 'host': 'nginx host', 'mgr': 'manages it',
        'local': 'Local sites', 'local_sub': 'static, PHP-FPM ...', 'backend': 'Web server', 'proxy': 'proxy',
        'caps': ('The sites live on this host: ModSecurity inspects every request before nginx answers it.',
                 'The sites run on other servers: nginx forwards only the requests that pass the WAF.',
                 'Some sites local, some proxied: one WAF, one set of rules, switched on site by site.'),
    },
    'zh-TW': {
        'titles': ('nginx 就是網站伺服器', 'nginx 當反向代理', '混用'),
        'users': '使用者 / 網際網路', 'host': 'nginx 主機', 'mgr': '管理與核准',
        'local': '本機網站', 'local_sub': '靜態、PHP-FPM…', 'backend': '後端網站', 'proxy': '反向代理',
        'caps': ('網站就在這台主機上：nginx 回應前，ModSecurity 先檢查每個請求。',
                 '網站在其他伺服器上：nginx 只轉送通過 WAF 的請求。',
                 '有些站台在本機、有些反向代理到其他伺服器：同一套 WAF 與規則，可以逐站啟用。'),
    },
    'ja': {
        'titles': ('nginx が Web サーバー', 'nginx がリバースプロキシ', '両方を 1 台で'),
        'users': '利用者 / インターネット', 'host': 'nginx ホスト', 'mgr': '管理・承認',
        'local': 'ローカルサイト', 'local_sub': '静的、PHP-FPM…', 'backend': 'Web サーバー', 'proxy': 'プロキシ',
        'caps': ('サイトはこのホスト上にあり、nginx が応答する前に ModSecurity が各リクエストを検査します。',
                 'サイトは別のサーバーにあり、WAF を通過したリクエストだけを nginx が転送します。',
                 '一部はローカル、一部はプロキシ。WAF とルールは 1 つで、サイトごとに有効にできます。'),
    },
}

PW, GAP, M = 300, 20, 20          # panel width, gap, outer margin
W, H = M * 2 + PW * 3 + GAP * 2, 480


def width(s, size):
    """Rough text width: CJK characters a full em, the rest about half."""
    return sum(size if ord(c) > 0x2e80 else size * 0.56 for c in s)


def wrap(s, size, maxw):
    lines, cur = [], ''
    tokens = []
    word = ''
    for c in s:                          # CJK breaks anywhere, Latin at spaces
        if ord(c) > 0x2e80:
            if word:
                tokens.append(word)
                word = ''
            tokens.append(c)
        elif c == ' ':
            tokens.append(word + ' ')
            word = ''
        else:
            word += c
    if word:
        tokens.append(word)
    for tk in tokens:
        if cur and width(cur + tk, size) > maxw:
            lines.append(cur.rstrip())
            cur = tk.lstrip()
        else:
            cur += tk
    if cur.strip():
        lines.append(cur.rstrip())
    # no punctuation at the start of a line (kinsoku): it stays on the line before
    for k in range(1, len(lines)):
        while lines[k] and lines[k][0] in '。、，．：；）」』!?':
            lines[k - 1] += lines[k][0]
            lines[k] = lines[k][1:]
    return [x for x in lines if x]


def text(x, y, s, size=13, color=TEXT, weight=400, anchor='middle'):
    return '<text x="%g" y="%g" font-size="%g" fill="%s" font-weight="%d" text-anchor="%s">%s</text>' % (
        x, y, size, color, weight, anchor, escape(s))


def box(x, y, w, h, fill, stroke, r=8, dash=False, sw=1.2):
    return '<rect x="%g" y="%g" width="%g" height="%g" rx="%g" fill="%s" stroke="%s" stroke-width="%g"%s/>' % (
        x, y, w, h, r, fill, stroke, sw, ' stroke-dasharray="5 4"' if dash else '')


def arrow(x1, y1, x2, y2, color=BLUE_D):
    return '<line x1="%g" y1="%g" x2="%g" y2="%g" stroke="%s" stroke-width="1.8" marker-end="url(#ah)"/>' % (x1, y1, x2, y2, color)


def path(points, color=BLUE_D, head=True):
    d = 'M' + ' L'.join('%g %g' % pt for pt in points)
    return '<path d="%s" fill="none" stroke="%s" stroke-width="1.8" stroke-linejoin="round"%s/>' % (
        d, color, ' marker-end="url(#ah)"' if head else '')


def panel(i, w):
    """Requests go visitors -> nginx with ModSecurity -> the sites; jt-waf-mgr sits beside the WAF (it manages it,
    requests never pass through it)."""
    x0 = M + i * (PW + GAP)
    out = [box(x0, 14, PW, H - 28, '#ffffff', BORDER, r=14)]
    out.append('<circle cx="%g" cy="44" r="13" fill="%s"/>' % (x0 + 30, BLUE))
    out.append(text(x0 + 30, 49, str(i + 1), 14, '#ffffff', 700))
    out.append(text(x0 + 52, 49, w['titles'][i], 15.5, INK, 700, 'start'))
    wx, ww = x0 + 30, 140                     # the WAF
    wc = wx + ww / 2
    out.append(box(wc - 85, 72, 170, 36, PANEL2, BORDER, r=18))
    out.append(text(wc, 95, w['users'], 12.5, TEXT))
    host_bottom = 232 if i == 1 else 314
    out.append(box(x0 + 16, 136, PW - 32, host_bottom - 136, '#eef4fd', BLUE, r=10, dash=True))
    out.append(text(x0 + PW - 28, 155, w['host'], 12.5, BLUE_D, 700, 'end'))     # right: the request arrow comes in on the left
    out.append(box(wx, 172, ww, 46, BLUE, BLUE, r=7))
    out.append(text(wc, 191, 'nginx +', 12.5, '#ffffff', 700))
    out.append(text(wc, 209, 'ModSecurity + CRS', 12.5, '#ffffff', 700))
    mx = wx + ww + 18                         # jt-waf-mgr, beside it
    mw = x0 + PW - 30 - mx
    out.append('<line x1="%g" y1="195" x2="%g" y2="195" stroke="%s" stroke-width="1.6" stroke-dasharray="4 3"/>' % (wx + ww, mx, ORANGE))
    out.append(box(mx, 172, mw, 46, '#ffffff', ORANGE, r=7, sw=1.6))
    out.append(text(mx + mw / 2, 191, 'jt-waf-mgr', 12, INK, 700))
    out.append(text(mx + mw / 2, 209, w['mgr'], 11, MUTED))
    if i == 0:                                # every site on this host
        out.append(arrow(wc, 218, wc, 246))
        out.append(box(x0 + 30, 250, PW - 60, 48, '#ffffff', '#94a3b8', r=7))
        out.append(text(x0 + PW / 2, 270, w['local'], 13, INK, 700))
        out.append(text(x0 + PW / 2, 288, w['local_sub'], 11.5, MUTED))
    if i == 1:                                # every site on other servers
        a, b = x0 + 26 + 56, x0 + PW - 26 - 56
        out.append(path([(wc, 218), (wc, 262)], head=False))
        out.append(path([(a, 262), (b, 262)], head=False))
        for c in (a, b):
            out.append(arrow(c, 262, c, 296))
            out.append(box(c - 56, 300, 112, 40, PANEL2, '#94a3b8', r=7))
            out.append(text(c, 325, w['backend'] + ' ' + ('A' if c == a else 'B'), 12.5, INK, 600))
        out.append(text(wc + 8, 254, w['proxy'], 11.5, BLUE_D, 600, 'start'))
    if i == 2:                                # some here, some there
        b = x0 + PW - 26 - 56
        out.append(arrow(wc, 218, wc, 246))
        out.append(box(wx, 250, ww, 48, '#ffffff', '#94a3b8', r=7))
        out.append(text(wc, 270, w['local'], 12.5, INK, 700))
        out.append(text(wc, 288, w['local_sub'], 11, MUTED))
        out.append(path([(wc, 232), (b, 232), (b, 336)]))
        out.append(box(b - 56, 340, 112, 40, PANEL2, '#94a3b8', r=7))
        out.append(text(b, 365, w['backend'], 12.5, INK, 600))
        out.append(text(b - 6, 330, w['proxy'], 11.5, BLUE_D, 600, 'end'))
    out.append(arrow(wc, 108, wc, 170))           # drawn last: its head stays on top of the WAF box
    for k, line in enumerate(wrap(w['caps'][i], 12.5, PW - 36)):
        out.append(text(x0 + 18, 410 + k * 19, line, 12.5, TEXT, 400, 'start'))
    return out


def svg(lang):
    w = WORDS[lang]
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d" font-family="%s" role="img" aria-label="%s">'
             % (W, H, W, H, escape(FONT, {'"': '&quot;'}), escape(' / '.join(w['titles'])).replace('"', '&quot;')),
             '<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
             '<path d="M0 0 L10 5 L0 10 z" fill="%s"/></marker></defs>' % BLUE_D,
             '<rect width="%d" height="%d" rx="16" fill="#eef2f8"/>' % (W, H)]
    for i in range(3):
        parts += panel(i, w)
    parts.append('</svg>')
    return '\n'.join(parts) + '\n'


def main():
    os.makedirs(OUT, exist_ok=True)
    for lang in WORDS:
        with open(os.path.join(OUT, 'deploy-modes.%s.svg' % lang), 'w', encoding='utf-8') as fh:
            fh.write(svg(lang))
    print('written:', ', '.join('docs/modes/deploy-modes.%s.svg' % l for l in WORDS))


if __name__ == '__main__':
    main()
