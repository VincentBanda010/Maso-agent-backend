from PIL import Image
im=Image.open('tmp/slides/maso-live.png');im.crop((426,0,826,690)).save('tmp/slides/maso-crop.png')
