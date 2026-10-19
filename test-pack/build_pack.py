import json, re, hashlib, zipfile
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from html.parser import HTMLParser
import qrcode
root=Path('test-pack')
for d in ['emails','texts','qr','invalid']: (root/d).mkdir(exist_ok=True)
class Plain(HTMLParser):
 def __init__(self): super().__init__(); self.parts=[]; self.hidden=0
 def handle_starttag(self,tag,attrs):
  if tag in ('script','style'): self.hidden+=1
 def handle_endtag(self,tag):
  if tag in ('script','style'): self.hidden=max(0,self.hidden-1)
 def handle_data(self,data):
  if not self.hidden: self.parts.append(data)
def content(m):
 parts={ 'text/plain':[], 'text/html':[] }
 for part in m.walk():
  if part.get_content_disposition()=='attachment': continue
  kind=part.get_content_type()
  if kind not in parts: continue
  try: text=part.get_content()
  except (LookupError,UnicodeError): continue
  if kind=='text/html':
   p=Plain(); p.feed(text); text=' '.join(p.parts)
  parts[kind].append(text)
 return re.sub(r'\s+',' ',' '.join(parts['text/plain'] or parts['text/html'])).strip()
selection=[('38fad061d58c','advance-fee','phishing'),('4ccb4568d9b6','parcel-payment','phishing'),('81e9afbb2261','delivery-reschedule','phishing'),('85cfaf1ad8f7','compensation','phishing'),('f2b44fc0df1f','inheritance','phishing'),('07440dc598cc','investment-lure','phishing'),('23340c1b08c0','health-advertising','exploratory'),('3bb65af8afe8','testosterone-advertising','exploratory'),('3daaf474610c','grant-notification','exploratory')]
sources=json.loads((root/'sources.json').read_text()); cases=[]
for prefix,name,label in selection:
 src=next(x for x in sources if x['file'].startswith(prefix)); path=root/'source-emails'/src['file']; raw=path.read_bytes(); m=BytesParser(policy=policy.default).parsebytes(raw)
 body=content(m); subject=str(m.get('Subject','')); text=(subject+'\n'+body).strip()
 # Explicit derived fixture: remove HTML markup, sender identifiers and attachments; no URL refanging.
 normalized=EmailMessage(); normalized['From']='corpus-sample@example.invalid'; normalized['To']='tester@example.invalid'; normalized['Subject']=subject; normalized.set_content(body)
 ep=root/'emails'/(name+'.eml'); ep.write_bytes(normalized.as_bytes(policy=policy.SMTP))
 tp=root/'texts'/(name+'.txt'); tp.write_text(text,encoding='utf-8')
 cases.append(dict(id=name,label=label,origin='real-world redacted corpus; normalized text derivative',source=src['source'],source_file='source-emails/'+src['file'],source_sha256=hashlib.sha256(raw).hexdigest(),email=str(ep.resolve()),text=text,changes='Plain-text MIME reconstruction; HTML/styles and attachment parts removed; sender/recipient replaced; source defanging retained. No semantic truncation.'))
benign=[('meeting','Team meeting','Hi Alex, our team meeting is tomorrow at 10. Please bring your notes. See you then.'),('password-guidance','Security guidance','Never share your password or one-time code. If you need to change your password, open the official app yourself.'),('invoice-discussion','Invoice discussion','Could you confirm whether invoice 1042 was received? There is no change to our bank details. Please use our usual contact number if you have questions.'),('delivery-update','Delivery update','Your library book has arrived at the front desk. You can collect it during normal opening hours. No payment is required.')]
for name,subject,body in benign:
 m=EmailMessage(); m['From']='colleague@example.invalid'; m['To']='tester@example.invalid'; m['Subject']=subject; m.set_content(body)
 ep=root/'emails'/('benign-'+name+'.eml'); ep.write_bytes(m.as_bytes(policy=policy.SMTP))
 text=subject+'\n'+body; (root/'texts'/('benign-'+name+'.txt')).write_text(text,encoding='utf-8')
 cases.append(dict(id='benign-'+name,label='benign',origin='synthetic comparison control',email=str(ep.resolve()),text=text))
qr_cases=[]
for name in ['advance-fee','parcel-payment','benign-meeting','benign-password-guidance']:
 case=next(c for c in cases if c['id']==name); payload=case['text'][:350]; image=root/'qr'/(name+'.png'); qr=qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=12, border=6); qr.add_data(payload); qr.make(fit=True); qr.make_image().save(image)
 qr_cases.append(dict(id='qr-'+name,label=case['label'],origin='generated QR encoding test-case text; not an original attack QR',file=str(image.resolve()),payload=payload,derived_from=name,transformation='First 350 characters of source-derived text; QR decoding fixture, not full email classification.'))
qrcode.make('https://example.com').save(root/'qr'/'benign-url.png')
qr_cases.append(dict(id='qr-benign-url',label='exploratory',origin='synthetic URL control',file=str((root/'qr'/'benign-url.png').resolve()),payload='https://example.com'))
from PIL import Image
Image.new('RGB',(400,400),'white').save(root/'invalid'/'no-qr.png')
(root/'invalid'/'not-an-image.png').write_bytes(b'Not an image: upload validation fixture.')
manifest={'description':'Curated functional/quality test set, not an independently verified benchmark. Phishing labels are manual assessments of corpus lures. Exploratory advertising examples have no phishing ground truth. Benign controls are synthetic. Real-world source samples may overlap model training data; no held-out claim.','emails':cases,'qr':qr_cases}
(root/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
# Reuse existing connection, auth and functional tests; do not embed secrets.
c=json.loads(Path('postman/Maso.postman_collection.json').read_text(encoding='utf-8'))
base_tests=next(i for f in c['item'] for i in f['item'] if i['name']=='Ordinary message')['event'][0]['script']['exec']
def events(lines): return [{'listen':'test','script':{'type':'text/javascript','exec':lines}}]
def quality(label):
 if label=='phishing': return ['if (pm.response.code === 200) pm.test("Quality probe: captured scam should be flagged", () => pm.expect(pm.response.json().risk_level).to.be.oneOf(["Suspicious", "Dangerous"]));']
 if label=='benign': return ['if (pm.response.code === 200) pm.test("Quality probe: benign control should not be flagged", () => pm.expect(pm.response.json().risk_level).to.eql("Safe"));']
 return []
def request(name,path,body,label):
 return {'name':name,'request':{'method':'POST','header':([{'key':'Content-Type','value':'application/json'}] if body['mode']=='raw' else []),'url':'{{base_url}}'+path,'body':body},'event':events(base_tests+quality(label))}
def upload(name,endpoint,path,label): return request(name,'/api/v1/analyze/'+endpoint+'?expand_links=false&external_checks=false',{'mode':'formdata','formdata':[{'key':'file','type':'file','src':path}]},label)
folders=[c['item'][0]]
folders.append({'name':'1. Real-world email text and benign comparisons','description':'Model-quality assertions may fail; failures reveal false positives/negatives, not necessarily an API bug. 503 means no model verdict. Samples are not a validated held-out benchmark.','item':[request(x['id'],'/api/v1/analyze',{'mode':'raw','raw':json.dumps({'content':x['text'],'expand_links':False,'external_checks':False},indent=2),'options':{'raw':{'language':'json'}}},x['label']) for x in cases]})
folders.append({'name':'2. Normalized email uploads','description':'Text-only derivatives for semantic model testing. Select local files if Postman requests access.','item':[upload(x['id'],'email',x['email'],x['label']) for x in cases]})
folders.append({'name':'3. Generated QR fixtures','description':'Generated from captured email TEXT, plus benign controls. Not authentic criminal QR artifacts.','item':[upload(x['id'],'qr',x['file'],x['label']) for x in qr_cases]})
invalid=[]
for filename in ['no-qr.png','not-an-image.png']:
 r=upload(filename,'qr',str((root/'invalid'/filename).resolve()),'exploratory'); r['event']=events(['pm.test("Invalid QR rejected", () => pm.response.to.have.status(422));']); invalid.append(r)
folders.append({'name':'4. Invalid upload controls','item':invalid})
# Original captures are diagnostic: HTML token volume may exceed the classifier budget.
originals=[]
for x in cases:
 if 'source_file' not in x: continue
 r=upload('Original '+x['id'],'email',str((root/x['source_file']).resolve()),'exploratory')
 r['event']=events(['pm.test("Original capture handled explicitly", () => pm.expect(pm.response.code).to.be.oneOf([200,422,503]));','if (pm.response.code === 200) pm.test("AI completed", () => pm.expect(pm.response.json().checks.ai).to.eql("completed"));','if (pm.response.code !== 200) console.warn("No classification verdict for original capture", pm.response.json());'])
 originals.append(r)
folders.append({'name':'5. Original source email captures — diagnostic','description':'Unmodified published redacted captures. HTML-heavy emails may exceed the 512-token model limit; 422/503 is explicit no-verdict handling, not successful classification.','item':originals})
c['info']['name']='Maso — Real-World Test Pack'; c['info']['description']='Real-world redacted scam/spam emails, normalized derivatives, generated QR fixtures and synthetic benign controls. No malicious destinations are contacted. Select Maso Local; set api_key locally. Run sequentially with a 45000 ms timeout. Read README before interpreting quality tests.'; c['item']=folders
(root/'Maso-Real-World.postman_collection.json').write_text(json.dumps(c,indent=2),encoding='utf-8')
(root/'Maso-Local.postman_environment.json').write_bytes(Path('postman/Maso-Local.postman_environment.json').read_bytes())
(root/'README.md').write_text('''# Maso real-world test pack

## Run in Postman
1. Start Maso from VS Code with `start.cmd`. Model setup must be complete; run Model readiness first.
2. Import Maso-Real-World.postman_collection.json and Maso-Local.postman_environment.json.
3. Select Maso Local, set api_key locally from .env, and use http://127.0.0.1:8000 as base_url (change for your chosen port).
4. Set request timeout to 45000 ms and run sequentially. The model accepts one active inference per process.
5. Run folders 1–4. Scripts > Post-response contains assertions; Test Results shows pass/fail.
6. Upload paths point to C:/Projects/Maso/test-pack. If needed, select each file under Body > form-data > file. Postman may request permission to read this folder.
7. Folder 5 is diagnostic for raw MIME/HTML captures. A 422/503 is no verdict, not a correct phishing detection.

## Contents and provenance
- 9 real-world redacted source samples selected from cw-l/email-corpus: six scam-lure cases plus three exploratory spam/ambiguous cases.
- 13 normalized .eml files and matching text files: nine source derivatives plus four synthetic benign controls.
- 5 generated QR fixtures: two encode captured scam email text, two benign text, one benign URL. These are newly generated test images, NOT original criminal QR artifacts.
- 2 invalid image controls.
- Original published source files, license, source README, source URLs, revision and SHA-256 hashes in manifest.json. Additional downloaded source samples remain available under source-emails.

Source: https://github.com/cw-l/email-corpus
Revision: 75b488148d5560109d6fb0c6646d417d7271f66a
The publisher describes the corpus as real-world spam/scam/phishing with contributor identifiers redacted and URLs defanged. We preserve that defanging and never contact the destinations. Source files are not rendered or executed. Upload .eml files through Postman rather than opening them in an email client.

Normalized files are explicit derivatives: readable body text replaces HTML MIME; styles and attachments are omitted; sender/recipient are synthetic. Full source files remain separate. Normalized emails are not truncated. QR payloads use at most the first 350 characters and are explicitly marked as excerpts in manifest.json. These derivatives test semantic model inference, not sender authentication or original MIME fidelity.

## Reading results
Functional assertions require HTTP 200, checks.ai=completed, no rules check, valid score/color/verdict and network checks not requested. Quality probes expect scam-lure cases to be Suspicious/Dangerous and synthetic benign controls to be Safe. Those expectations are manual test labels, not independently verified ground truth. Advertising/grant examples are exploratory, without class assertions.

Expect possible failures: false negatives and false positives are exactly what this pack is designed to reveal. Do not change expected labels merely to make tests pass. This small curated set is not a statistically representative benchmark; possible training overlap is unknown. Bare URL/QR classification is not validated by the email model. A model failure or oversized input can yield 503; this is never a phishing verdict. Read manifest.json for all provenance and transformations.

No live model evaluation has been run as part of creating this pack. Fixtures are checked for MIME parsing, QR decoding and collection integrity.
''',encoding='utf-8')
print('Created',sum(len(f['item']) for f in folders),'Postman requests with functional/quality assertions.')
