import asyncio,json,os
from pathlib import Path
from app.providers import Providers
async def main():
 for line in Path('.env').read_text(encoding='utf-8').splitlines():
  if line.startswith('MASO_') and '=' in line:
   k,v=line.split('=',1); os.environ.setdefault(k,v.strip())
 p=Providers(); p.load()
 scores={url:await p.classify(url) for url in ['https://www.google.com','https://www.google1.com']}
 print(json.dumps({'scores':scores},indent=2))
asyncio.run(main())
