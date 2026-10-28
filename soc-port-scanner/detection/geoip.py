"""GeoIP enrichment module for the SOC Detection Engine.

Queries the ip-api.com free GeoIP service (no API key required, 45 req/min)
to enrich scan alerts with attacker geolocation and ISP metadata.

API Docs : http://ip-api.com/docs
Rate Limit: 45 requests/minute per IP (free tier)
"""

from __future__ import annotations

import json
import time
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from typing import Dict, Optional


IP_API_ENDPOINT = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,lat,lon,query"


@dataclass
class GeoLocation:
    """Geographic and ISP metadata for an IP address."""

    ip: str
    country: str
    country_code: str
    region: str
    city: str
    isp: str
    org: str
    asn: str
    lat: float
    lon: float
    is_private: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)

    @property
    def summary(self) -> str:
        """Short human-readable summary."""
        if self.is_private:
            return f"{self.ip} [Private/Local Network]"
        return f"{self.ip} → {self.city}, {self.country} ({self.country_code}) | {self.org or self.isp}"


class _RateLimiter:
    """Thread-safe sliding-window rate limiter."""

    def __init__(self, calls: int, period: float) -> None:
        self.calls = calls
        self.period = period
        self._lock = threading.Lock()
        self._timestamps: list[float] = []

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            self._timestamps = [t for t in self._timestamps if now - t < self.period]
            if len(self._timestamps) >= self.calls:
                sleep_for = self.period - (now - self._timestamps[0])
                if sleep_for > 0:
                    time.sleep(sleep_for)
            self._timestamps.append(time.monotonic())


_rate_limiter = _RateLimiter(calls=40, period=60.0)

# Cache: ip_str -> GeoLocation
_cache: Dict[str, GeoLocation] = {}

# Private IP prefixes (no geolookup needed)
_PRIVATE_PREFIXES = (
    "127.", "10.", "192.168.", "169.254.", "::1", "fc", "fd",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
)


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def lookup_geoip(ip: str, timeout: float = 5.0) -> Optional[GeoLocation]:
    """Resolve an IP address to geographic and ISP metadata.

    Private/loopback addresses are immediately returned as local without a
    network request. Public IPs are queried through ip-api.com.

    Args:
        ip: IPv4 or IPv6 address string.
        timeout: HTTP request timeout in seconds.

    Returns:
        GeoLocation dataclass, or None on unrecoverable network error.
    """
    if ip in _cache:
        return _cache[ip]

    if _is_private(ip):
        geo = GeoLocation(
            ip=ip,
            country="Private Network",
            country_code="--",
            region="RFC1918 / Loopback",
            city="Local",
            isp="Internal",
            org="Internal",
            asn="N/A",
            lat=0.0,
            lon=0.0,
            is_private=True,
        )
        _cache[ip] = geo
        return geo

    _rate_limiter.wait()

    url = IP_API_ENDPOINT.format(ip=ip)
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None

    if data.get("status") != "success":
        return None

    geo = GeoLocation(
        ip=ip,
        country=data.get("country", "Unknown"),
        country_code=data.get("countryCode", "--"),
        region=data.get("regionName", "Unknown"),
        city=data.get("city", "Unknown"),
        isp=data.get("isp", "Unknown"),
        org=data.get("org", ""),
        asn=data.get("as", ""),
        lat=float(data.get("lat", 0.0)),
        lon=float(data.get("lon", 0.0)),
        is_private=False,
    )
    _cache[ip] = geo
    return geo
