#!/usr/bin/env python3
"""Turn the project-site thumbnails taken by the browser test into their published form.

  tools/make_thumbs.py E2E_SHOTS_DIR docs/shots

The browser test (tools/e2e/e2e.cjs) saves one screen of each page at twice the resolution as
thumb-<lang>-<name>.png (2400 x 1800). The thumbnail is a separate, smaller picture: scaled here to WIDTH pixels
(about twice the widest place the site shows one, so a high-density screen still gets full detail) with Lanczos
and a light sharpening, instead of leaving a 2400-pixel picture for the browser to shrink (which blurred the text);
clicking it opens the full picture (docs/shots/<lang>/<name>.png). Stored as lossless WebP: a lossy WebP halves
the colour resolution (4:2:0), which blurs small coloured text. A screen of the interface is flat colour, so the
lossless file is small; a picture that is not (the war room's gradients) is stored lossy, quality 92. Output: docs/shots/<lang>/thumb/<name>.webp. Needs Pillow (development machine only;
nothing here ships in the release).
"""
import os
import re
import sys

from PIL import Image, ImageFilter

WIDTH = 1200                    # the site shows a thumbnail at most about 600 CSS pixels wide
LOSSLESS_MAX = 400 * 1024       # larger than this lossless: the picture is not flat colour; stored lossy instead



def shrink(im):
    """The thumbnail of a picture: WIDTH pixels wide (never enlarged), Lanczos, a light unsharp mask for the text."""
    im = im.convert('RGB')
    if im.width > WIDTH:
        im = im.resize((WIDTH, round(im.height * WIDTH / im.width)), Image.LANCZOS)
        im = im.filter(ImageFilter.UnsharpMask(radius=0.8, percent=60, threshold=2))
    return im


def save(im, dst_file):
    im.save(dst_file, 'WEBP', lossless=True, quality=60, method=4)
    if os.path.getsize(dst_file) > LOSSLESS_MAX:
        # gradients and noise (the war room) do not pack losslessly: a high-quality lossy file
        im.save(dst_file, 'WEBP', quality=92, method=4)


def main(src, dst):
    n = 0
    for f in sorted(os.listdir(src)):
        m = re.fullmatch(r'thumb-(zh-TW|en|ja)-([a-z-]+)\.png', f)
        if not m:
            continue
        out = os.path.join(dst, m.group(1), 'thumb')
        os.makedirs(out, exist_ok=True)
        with Image.open(os.path.join(src, f)) as im:
            save(shrink(im), os.path.join(out, m.group(2) + '.webp'))
        n += 1
    if not n:
        sys.exit('no thumb-*.png in ' + src)
    print('thumbnails: %d written' % n)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
