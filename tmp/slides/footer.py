from PIL import Image
im=Image.open('tmp/slides/image3.png');im.crop((0,1000,2048,1102)).save('tmp/slides/footer.png')
