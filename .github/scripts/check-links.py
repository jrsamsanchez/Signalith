#!/usr/bin/env python3
"""Check every link on signalith.io as built from a checkout.

Usage: check-links.py <repo> [--external]
Copies site/ and builds the docs into a temp dir (mkdocs build --strict), then
checks each internal href/src (file and #anchor) and, with --external, each
outside URL once. Exits 1 if an internal link is broken, or an outside page is
gone (404 or 410) or its host isn't found. Other outside errors (403, 429, 5xx,
timeouts: sites that turn away scripts or are briefly down) are only warned about.
The Links workflow runs it every night.
"""
import html.parser, os, shutil, subprocess, sys, tempfile, urllib.parse, urllib.request, ssl
from concurrent.futures import ThreadPoolExecutor

repo = os.path.abspath(sys.argv[1]); external = '--external' in sys.argv
mkdocs = os.environ.get('MKDOCS', 'mkdocs')
out = tempfile.mkdtemp(prefix='sigsite-')
shutil.copytree(os.path.join(repo, 'site'), out, dirs_exist_ok=True)
r = subprocess.run([mkdocs, 'build', '--strict', '-q', '-f', os.path.join(repo, 'mkdocs.yml'), '-d', os.path.join(out, 'docs')], capture_output=True, text=True)
if r.returncode:
    print('MKDOCS STRICT FAILED\n' + r.stdout + r.stderr); sys.exit(1)

class P(html.parser.HTMLParser):
    def __init__(s): super().__init__(); s.links = []; s.ids = set()
    def handle_starttag(s, tag, a):
        a = dict(a)
        for k in ('id', 'name'):
            if a.get(k): s.ids.add(a[k])
        for k in ('href', 'src', 'poster'):
            if a.get(k) and not (tag == 'link' and a.get('rel') in ('preconnect', 'dns-prefetch')): s.links.append(a[k])
        if a.get('srcset'):
            s.links += [x.strip().split(' ')[0] for x in a['srcset'].split(',') if x.strip()]

pages, ids = {}, {}
for d, _, fs in os.walk(out):
    for f in fs:
        if f.endswith('.html'):
            p = os.path.join(d, f); q = P()
            try: q.feed(open(p, encoding='utf-8', errors='replace').read())
            except Exception: pass
            pages[p] = q.links; ids[p] = q.ids

def resolve(page, path):
    t = os.path.normpath(os.path.join(out, path.lstrip('/')) if path.startswith('/') else os.path.join(os.path.dirname(page), path))
    if os.path.isdir(t): t = os.path.join(t, 'index.html')
    return t

bad, ext = [], {}
for page, links in pages.items():
    rel = os.path.relpath(page, out)
    if rel.startswith('docs/') and not rel.startswith('docs/index') and '/assets/' in rel: continue
    for l in links:
        u = urllib.parse.urlsplit(l)
        if u.scheme in ('mailto', 'tel', 'data', 'javascript'): continue
        if u.scheme in ('http', 'https'):
            if u.netloc in ('signalith.io', 'www.signalith.io'):
                u = urllib.parse.urlsplit(u.path + ('#' + u.fragment if u.fragment else ''))
            elif u.hostname in ('localhost', '127.0.0.1') or (u.hostname or '').endswith(('example.com', 'example.org', '.local', '.internal')):
                continue
            else:
                ext.setdefault(l.split('#')[0], rel); continue
        if not u.path and u.fragment:
            if u.fragment not in ids[page] and u.fragment not in ('', 'top'): bad.append((rel, l, 'no such anchor'))
            continue
        if not u.path: continue
        t = resolve(page, urllib.parse.unquote(u.path))
        if not os.path.exists(t): bad.append((rel, l, 'missing')); continue
        if u.fragment and t.endswith('.html') and u.fragment not in ids.get(t, set()):
            bad.append((rel, l, 'no such anchor'))

for b in sorted(set(bad)): print('BROKEN  %-28s %s  (%s)' % b)
if external:
    ctx = ssl.create_default_context(cafile=os.environ.get('SSL_CERT_FILE') or None)
    def get(url):
        for m in ('HEAD', 'GET'):
            try:
                req = urllib.request.Request(url, method=m, headers={'User-Agent': 'Mozilla/5.0 signalith-link-check'})
                return url, urllib.request.urlopen(req, timeout=20, context=ctx).status
            except urllib.error.HTTPError as e:
                if m == 'GET' or e.code not in (403, 405, 404, 429): return url, e.code
            except Exception as e:
                if m == 'GET': return url, type(e).__name__
        return url, '?'
    gone = []
    with ThreadPoolExecutor(12) as ex:
        for url, st in ex.map(get, sorted(ext)):
            if isinstance(st, int) and st < 400: continue
            if st in (404, 410, 'URLError'):
                gone.append(url); print('GONE    %s  %s  (on %s)' % (st, url, ext[url]))
            else:
                print('WARNING %s  %s  (on %s)' % (st, url, ext[url]))
print('checked %d pages, %d outside URLs; %d broken internal links' % (len(pages), len(ext), len(set(bad))))
if external:
    print('%d outside pages gone' % len(gone)); bad += gone
shutil.rmtree(out)
sys.exit(1 if bad else 0)
