import zipfile,xml.etree.ElementTree as E,collections
n={'a':'http://schemas.openxmlformats.org/drawingml/2006/main','p':'http://schemas.openxmlformats.org/presentationml/2006/main'}
with zipfile.ZipFile(r'C:\Users\Predator\Downloads\Maso Agent.pptx') as z:
 r=E.fromstring(z.read('ppt/slides/slide1.xml'));sp=[s for s in r.findall('.//p:spTree/p:sp',n) if not s.findall('.//a:t',n)][0]
 print(E.tostring(sp,encoding='unicode')[:1800]);print(collections.Counter(q.tag.split('}')[-1] for q in sp.iter()))
