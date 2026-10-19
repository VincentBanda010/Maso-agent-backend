"""Live feed + real-model verification. Does not open listed websites or print their URLs."""
import asyncio,json,os
from pathlib import Path
import httpx
from app.openphish import OpenPhishFeed, FEED_URL, MAX_BYTES, fingerprint
from app.providers import Providers
from app.schemas import AnalysisRequest
from app.engine import analyze

async def main():
    for line in Path('.env').read_text(encoding='utf-8').splitlines():
        if line.startswith('MASO_') and '=' in line:
            k,v=line.split('=',1); os.environ.setdefault(k,v.strip())
    async with httpx.AsyncClient(timeout=25,trust_env=False,follow_redirects=False) as client:
        response=await client.get(FEED_URL)
        response.raise_for_status()
        raw=response.content
    if len(raw)>MAX_BYTES: raise ValueError('Oversized feed')
    urls=[line.strip() for line in raw.decode('utf-8-sig').splitlines() if line.strip()]
    listed=next(url for url in urls if len(url)<160)
    feed=OpenPhishFeed(); feed.ingest(raw,response.headers.get('last-modified',''))
    provider=Providers()
    matched=await provider.reputation([listed])
    control=await provider.reputation(['https://www.google.com/'])
    if matched is not True or control is not False: raise RuntimeError('Live match/control verification failed')
    await asyncio.to_thread(provider.load)
    result=await analyze(AnalysisRequest(content=listed,external_checks=True,expand_links=False),provider)
    assert result.safety_status=='unsafe'
    assert result.checks['threat_intelligence']=='completed'
    assert any(f.code=='known_threat' for f in result.findings)
    report={'live_feed_download':True,'listed_url_match':matched,'control_url_match':control,
        'listed_url_sha256':fingerprint(listed),'real_model_inference':result.checks['ai'],
        'risk_level':result.risk_level,'model_risk_level':result.model_risk_level,
        'safety_status':result.safety_status,'feed':feed.metadata(),
        'note':'Listed URLs were not opened. A no-match is not a safety guarantee. No raw feed URLs are redistributed in this report.'}
    Path('docs/openphish-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__': asyncio.run(main())
