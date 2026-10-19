import asyncio, json, os
from pathlib import Path
from app.providers import Providers
async def main():
 for line in Path('.env').read_text().splitlines():
  if '=' in line and line.startswith('MASO_'):
   k,v=line.split('=',1); os.environ.setdefault(k,v.strip())
 p=Providers(); p.load(); rows=[]
 for value in ['https://www.wikipedia.org','https://www.google.com','https://example.com','https://www.microsoft.com','https://paypal.com.account-verify.example.com/login','https://microsoft-password-reset.example.com/verify','http://192.0.2.1/login','https://example.com@account-check.example.org/verify','Hi Alex, our meeting is tomorrow at 10. Please bring your notes. See you then.', "I'm your manager. Buy five gift cards immediately and send me the codes. Keep this confidential and do not call me."]:
  score=await p.classify(value)
  rows.append({'input':value,'phishing_confidence':score})
 Path('docs/model-routing-results.json').write_text(json.dumps(rows,indent=2))
 print(json.dumps(rows,indent=2))
asyncio.run(main())
