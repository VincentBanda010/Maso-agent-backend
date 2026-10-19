import time
import httpx
import pytest
from app.openphish import OpenPhishFeed, fingerprint


def test_feed_matches_exact_url_not_whole_domain(tmp_path):
    feed=OpenPhishFeed(tmp_path/'feed.json')
    feed.ingest(b'https://bad.example/phish?id=1\n')
    assert fingerprint('https://BAD.example:443/phish?id=1#fragment') in feed.hashes
    assert fingerprint('https://bad.example/other') not in feed.hashes
    assert fingerprint('https://bad.example/phish?id=2') not in feed.hashes
    assert 'bad.example' not in feed.cache_path.read_text()


@pytest.mark.parametrize('raw',[b'',b'not a URL',b'<html>error</html>',b'x'*(2*1024*1024+1)], ids=['empty','invalid-url','html-error','oversized'])
def test_invalid_feed_is_not_accepted(tmp_path,raw):
    feed=OpenPhishFeed(tmp_path/'feed.json')
    with pytest.raises((ValueError,UnicodeError)):
        feed.ingest(raw)
    assert not feed.fresh


async def test_cache_avoids_per_user_feed_downloads(tmp_path,monkeypatch):
    feed=OpenPhishFeed(tmp_path/'feed.json'); feed.ingest(b'https://bad.example/path\n')
    async def forbidden(*args,**kwargs): raise AssertionError('Unexpected network call')
    monkeypatch.setattr(httpx.AsyncClient,'send',forbidden)
    assert await feed.lookup(['https://bad.example/path']) is True
    assert await feed.lookup(['https://example.com']) is False
    reloaded=OpenPhishFeed(tmp_path/'feed.json')
    assert reloaded.fresh
    assert await reloaded.lookup(['https://bad.example/path']) is True


async def test_stale_feed_does_not_return_clean_on_failure(tmp_path,monkeypatch):
    feed=OpenPhishFeed(tmp_path/'feed.json'); feed.ingest(b'https://bad.example/path\n')
    feed.fetched_at=time.time()-13*3600
    async def failed(*args,**kwargs): raise httpx.ConnectError('offline')
    monkeypatch.setattr(httpx.AsyncClient,'send',failed)
    with pytest.raises(httpx.ConnectError):
        await feed.lookup(['https://example.com'])
    assert not feed.fresh


async def test_refresh_from_http_transport(tmp_path,monkeypatch):
    real_client=httpx.AsyncClient
    def handler(request):
        assert request.url.host=='raw.githubusercontent.com'
        assert 'private.example' not in str(request.url)
        return httpx.Response(200,content=b'https://listed.example/path\n',headers={'last-modified':'test-date'})
    monkeypatch.setattr('app.openphish.httpx.AsyncClient',lambda **kwargs: real_client(transport=httpx.MockTransport(handler),**kwargs))
    feed=OpenPhishFeed(tmp_path/'feed.json')
    assert await feed.lookup(['https://private.example/secret']) is False
    assert await feed.lookup(['https://listed.example/path']) is True
    assert feed.metadata()['upstream_modified']=='test-date'
