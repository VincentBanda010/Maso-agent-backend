import asyncio, json, os
from pathlib import Path
from app.providers import Providers
from app.engine import analyze
from app.schemas import AnalysisRequest

async def main():
    for line in Path('.env').read_text(encoding='utf-8').splitlines():
        if line.startswith('MASO_') and '=' in line:
            key,value=line.split('=',1); os.environ.setdefault(key,value.strip())
    provider=Providers(); provider.load()
    manifest=json.loads(Path('test-pack/manifest.json').read_text(encoding='utf-8'))
    cases=[{'id':c['id'],'expected':c['label'],'content':c['text']} for c in manifest['emails'] if c['label'] in ('phishing','benign')]
    cases += [{'id':url,'expected':'benign','content':url} for url in ['https://www.wikipedia.org','https://www.google.com','https://example.com','https://www.microsoft.com','https://www.bbc.com','https://www.gov.za']]
    rows=[]
    for c in cases:
        try:
            r=await analyze(AnalysisRequest(content=c['content']),provider)
            correct=(r.risk_level!='Safe') if c['expected']=='phishing' else (r.risk_level=='Safe')
            rows.append({'id':c['id'],'expected':c['expected'],'risk_level':r.risk_level,'score':r.score,'safety_status':r.safety_status,'matched_expected_label':correct,'elapsed_ms':r.elapsed_ms})
        except Exception as exc:
            rows.append({'id':c['id'],'expected':c['expected'],'error_type':type(exc).__name__,'matched_expected_label':False})
    report={'limitations':'Small curated diagnostic set, not a held-out accuracy benchmark. Expected scam labels are manual; benign message controls are synthetic. Training overlap is unknown. Network checks were disabled. Errors are not correct classifications.','matched':sum(r['matched_expected_label'] for r in rows),'total':len(rows),'cases':rows}
    Path('docs/current-model-evaluation.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
asyncio.run(main())
