import zipfile,xml.etree.ElementTree as E
n={'a':'http://schemas.openxmlformats.org/drawingml/2006/main','p':'http://schemas.openxmlformats.org/presentationml/2006/main'}
with zipfile.ZipFile(r'C:\Users\Predator\Downloads\Maso Agent.pptx') as z:
 for f in ['ppt/slides/slide1.xml','ppt/slideLayouts/slideLayout1.xml','ppt/slideMasters/slideMaster1.xml']:
  print(f)
  for q in E.fromstring(z.read(f)).findall('.//p:spTree/*',n):
   if q.tag.endswith('}sp') and not q.findall('.//a:t',n):
    print('coords',E.tostring(q.find('.//a:xfrm',n),encoding='unicode')[:300]);print('colors',[x.attrib for x in q.findall('.//a:srgbClr',n)])
