import zipfile,xml.etree.ElementTree as E
n={'a':'http://schemas.openxmlformats.org/drawingml/2006/main','p':'http://schemas.openxmlformats.org/presentationml/2006/main'}
with zipfile.ZipFile(r'C:\Users\Predator\Downloads\Maso Agent.pptx') as z:
 for f in ['ppt/slides/slide1.xml','ppt/slides/slide5.xml','ppt/slideMasters/slideMaster1.xml']:
  r=E.fromstring(z.read(f));print(f)
  for q in r.findall('.//p:spTree/*',n):
   txt=''.join(t.text or '' for t in q.findall('.//a:t',n));print(q.tag.split('}')[-1],len(list(q.iter())),txt[:35])
