import json, urllib.request, concurrent.futures
from pathlib import Path
root=Path('test-pack'); tree=json.loads(Path('corpus-tree.json').read_text(encoding='utf-8-sig'))
revision=tree['sha']
entries=sorted([e for e in tree['tree'] if e['path'].endswith('.eml') and e.get('size',0)<18000],key=lambda e:e['size'])[:20]
def fetch(e):
 url=f"https://raw.githubusercontent.com/cw-l/email-corpus/{revision}/{e['path']}"
 data=urllib.request.urlopen(url,timeout=60).read()
 filename=e['path'].split('/')[-1]
 (root/'source-emails'/filename).write_bytes(data)
 return dict(file=filename,source=url,revision=revision,size=len(data))
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: rows=list(pool.map(fetch,entries))
for file in ['LICENSE','README.md']:
 data=urllib.request.urlopen(f'https://raw.githubusercontent.com/cw-l/email-corpus/{revision}/{file}',timeout=60).read()
 (root/('SOURCE-'+file)).write_bytes(data)
(root/'sources.json').write_text(json.dumps(rows,indent=2))
print(f'Downloaded {len(rows)} published redacted email samples and attribution.')
