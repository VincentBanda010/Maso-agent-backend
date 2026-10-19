"""OpenPhish Community feed adapter. Submitted URLs never leave the server."""
import asyncio
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import httpx

FEED_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt'
TTL = 12 * 60 * 60
MAX_BYTES = 2 * 1024 * 1024


def canonical_url(url):
    parts=urlsplit(url)
    if parts.scheme.lower() not in ('http','https') or not parts.hostname:
        raise ValueError('Unsupported feed address')
    if parts.username is not None or parts.password is not None:
        # Preserve credentials for exact matching; never strip to a different URL.
        authority=parts.netloc
    else:
        host=parts.hostname.encode('idna').decode('ascii').lower()
        if ':' in host: host='['+host+']'
        port=parts.port
        authority=host if port is None or (parts.scheme.lower(),port) in [('http',80),('https',443)] else f'{host}:{port}'
    return urlunsplit((parts.scheme.lower(),authority,parts.path or '/',parts.query,''))


def fingerprint(url):
    return hashlib.sha256(canonical_url(url).encode()).hexdigest()


class OpenPhishFeed:
    def __init__(self, cache_path=None):
        self.cache_path=Path(cache_path or os.getenv('MASO_OPENPHISH_CACHE',str(Path(__file__).resolve().parent.parent/'data'/'openphish.json')))
        self.hashes=set()
        self.fetched_at=0.0
        self.upstream_modified=''
        self.feed_sha256=''
        self.lock=asyncio.Lock()
        self._read_cache()

    def _read_cache(self):
        try:
            data=json.loads(self.cache_path.read_text(encoding='utf-8'))
            timestamp=float(data['fetched_at'])
            hashes=data['hashes']
            if data['source']!=FEED_URL or not isinstance(hashes,list) or not hashes or len(hashes)>50000:
                return
            if not all(isinstance(h,str) and len(h)==64 and all(c in '0123456789abcdef' for c in h) for h in hashes): return
            if not 0 <= time.time()-timestamp < TTL: return
            self.hashes=set(hashes); self.fetched_at=timestamp
            self.upstream_modified=data['upstream_modified']; self.feed_sha256=data['feed_sha256']
        except (OSError,ValueError,KeyError,TypeError):
            return  # An invalid cache is never used as a completed lookup.

    @property
    def fresh(self):
        return bool(self.hashes) and 0 <= time.time()-self.fetched_at < TTL

    def metadata(self):
        return {'provider':'OpenPhish Community','status':'ready' if self.fresh else 'unavailable',
            'entries':len(self.hashes),'fetched_at':datetime.fromtimestamp(self.fetched_at,timezone.utc).isoformat() if self.fetched_at else '',
            'upstream_modified':self.upstream_modified,'feed_sha256':self.feed_sha256,
            'refresh_interval_seconds':TTL}

    def ingest(self, raw, modified=''):
        if len(raw)>MAX_BYTES: raise ValueError('Feed too large')
        urls=[line.strip() for line in raw.decode('utf-8-sig').splitlines() if line.strip()]
        if not urls or len(urls)>50000: raise ValueError('Invalid feed size')
        hashes={fingerprint(url) for url in urls}
        timestamp=time.time()
        data={'source':FEED_URL,'fetched_at':timestamp,'upstream_modified':modified,
            'feed_sha256':hashlib.sha256(raw).hexdigest(),'hashes':sorted(hashes)}
        self.cache_path.parent.mkdir(parents=True,exist_ok=True)
        temporary=self.cache_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(data),encoding='utf-8')
        temporary.replace(self.cache_path)
        self.hashes=hashes; self.fetched_at=timestamp
        self.upstream_modified=modified; self.feed_sha256=data['feed_sha256']

    async def refresh(self):
        async with self.lock:
            if self.fresh: return
            async with httpx.AsyncClient(timeout=8,trust_env=False,follow_redirects=False) as client:
                async with client.stream('GET',FEED_URL) as response:
                    response.raise_for_status()
                    chunks=[]; total=0
                    async for chunk in response.aiter_bytes():
                        total+=len(chunk)
                        if total>MAX_BYTES: raise ValueError('Feed too large')
                        chunks.append(chunk)
                    self.ingest(b''.join(chunks),response.headers.get('last-modified',''))

    async def lookup(self, urls):
        await self.refresh()
        if not self.fresh: raise RuntimeError('Feed unavailable')
        # Exact normalized URL matches only: shared hosting and unrelated paths are not blocked.
        return any(fingerprint(url) in self.hashes for url in urls)
