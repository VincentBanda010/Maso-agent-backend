"""Connect only to validated public addresses, including at every redirect."""
import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit, urljoin

import aiohttp
from aiohttp.abc import AbstractResolver


class UnsafeURL(ValueError):
    pass


def parse_url(url: str):
    if len(url) > 4096 or any(ord(c) < 33 or ord(c) == 127 for c in url) or "\\" in url:
        raise UnsafeURL("Malformed URL")
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise UnsafeURL("Only HTTP and HTTPS URLs are supported")
        if parts.username is not None or parts.password is not None:
            raise UnsafeURL("URLs with embedded credentials are blocked")
        if parts.port not in (None, 80, 443):
            raise UnsafeURL("Only ports 80 and 443 are supported")
        return parts
    except ValueError as exc:
        raise UnsafeURL(str(exc)) from exc


def public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast and not ip.is_unspecified


async def resolve_public(host: str, port: int) -> list[str]:
    # The validated addresses are pinned in the connector. No second DNS lookup.
    rows = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(row[4][0] for row in rows))
    if not addresses or any(not public_ip(ip) for ip in addresses):
        raise UnsafeURL("Private, reserved or local destinations are blocked")
    return addresses


class PinnedResolver(AbstractResolver):
    def __init__(self, addresses):
        self.addresses = addresses

    async def resolve(self, host, port=0, family=socket.AF_INET):
        return [{"hostname": host, "host": ip, "port": port,
                 "family": socket.AF_INET6 if ":" in ip else socket.AF_INET,
                 "proto": 0, "flags": 0} for ip in self.addresses]

    async def close(self):
        pass


async def expand(url: str) -> tuple[str, list[str]]:
    current, chain = url, []
    for hop in range(6):
        parts = parse_url(current)
        addresses = await resolve_public(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
        connector = aiohttp.TCPConnector(resolver=PinnedResolver(addresses), use_dns_cache=False)
        async with aiohttp.ClientSession(connector=connector, trust_env=False,
                cookie_jar=aiohttp.DummyCookieJar(), timeout=aiohttp.ClientTimeout(total=2)) as session:
            # HEAD avoids downloading hostile page bodies. TLS verifies the original hostname.
            async with session.head(current, allow_redirects=False, headers={"User-Agent": "MasoSafety/1.0"}) as response:
                if response.status not in (301, 302, 303, 307, 308):
                    if response.status >= 400:
                        raise UnsafeURL("Destination did not permit a header-only check")
                    return current, chain
                target = response.headers.get("Location")
                if not target or hop == 5:
                    raise UnsafeURL("Missing redirect destination or too many redirects")
                current = urljoin(current, target)
                parse_url(current)
                if current == url or current in chain:
                    raise UnsafeURL("Redirect loop")
                chain.append(current)
    raise UnsafeURL("Too many redirects")
