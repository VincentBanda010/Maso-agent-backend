from pathlib import Path
import zipfile
from PIL import Image,ImageOps,ImageDraw
with zipfile.ZipFile(r'C:\Users\Predator\Downloads\Maso Agent.pptx') as z:
 for n in z.namelist():
  if n.startswith('ppt/media/'):
   p=Path('tmp/slides')/Path(n).name;p.write_bytes(z.read(n));im=Image.open(p);print(p,im.size)
