import urllib.request, json
from pathlib import Path
repo='CrabInHoney/urlbert-tiny-v4-phishing-classifier'
meta=json.load(urllib.request.urlopen('https://huggingface.co/api/models/'+repo,timeout=40)); rev=meta['sha']; root=Path('models/url-phishing')
files=['config.json','tokenizer.json','tokenizer_config.json','special_tokens_map.json','vocab.txt','model.safetensors','README.md']
for name in files:
 urllib.request.urlretrieve(f'https://huggingface.co/{repo}/resolve/{rev}/{name}',root/name)
(root/'provenance.json').write_text(json.dumps({'repository':repo,'revision':rev,'positive_label':'LABEL_1','source':'Model card maps LABEL_0 to good and LABEL_1 to phishing.'},indent=2))
print('URL model downloaded:',rev)
