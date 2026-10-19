import zipfile,xml.etree.ElementTree as E
from pathlib import Path
n={'a':'http://schemas.openxmlformats.org/drawingml/2006/main','p':'http://schemas.openxmlformats.org/presentationml/2006/main'}
with zipfile.ZipFile(r'C:\Users\Predator\Downloads\Maso Agent.pptx') as z:
 r=E.fromstring(z.read('ppt/slides/slide1.xml'));sp=[s for s in r.findall('.//p:spTree/p:sp',n) if not s.findall('.//a:t',n)][0]
 pa=sp.find('.//a:path',n);d=[]
 for a in pa:
  tag=a.tag.split('}')[-1];pts=[p.attrib['x']+','+p.attrib['y'] for p in a]
  if tag=='moveTo':d.append('M'+' '.join(pts))
  elif tag=='lnTo':d.append('L'+' '.join(pts))
  elif tag=='cubicBezTo':d.append('C'+' '.join(pts))
  elif tag=='close':d.append('Z')
 svg='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '+pa.attrib['w']+' '+pa.attrib['h']+'"><path fill="currentColor" d="'+' '.join(d)+'"/></svg>'
 Path('tmp/slides/vectors/original-circuit.svg').write_text(svg)
print('Original circuit pattern preserved as SVG')
