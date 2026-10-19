import zipfile,xml.etree.ElementTree as E,json
p=r'C:\Users\Predator\Downloads\Maso Agent.pptx'
n={'a':'http://schemas.openxmlformats.org/drawingml/2006/main','p':'http://schemas.openxmlformats.org/presentationml/2006/main'}
with zipfile.ZipFile(p) as z:
 root=E.fromstring(z.read('ppt/presentation.xml'));print('SIZE',root.find('p:sldSz',n).attrib)
 names=sorted([s for s in z.namelist() if __import__('re').match(r'ppt/slides/slide\d+.xml$',s)],key=lambda s:int(__import__('re').search(r'(\d+)\.xml',s).group(1)))
 for name in names:
  root=E.fromstring(z.read(name));print('\nSLIDE',name);print('\n'.join(t.text or '' for t in root.findall('.//a:t',n)))
 print('MEDIA',[s for s in z.namelist() if s.startswith('ppt/media/')])
