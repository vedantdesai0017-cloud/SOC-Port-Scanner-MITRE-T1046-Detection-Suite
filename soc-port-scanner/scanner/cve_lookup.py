"""CVE Lookup module for SOC Port Scanner.

Queries the NIST National Vulnerability Database (NVD) API v2.0 to retrieve
known CVEs matching a product name and version string obtained from banner grabbing.

API Endpoint : https://services.nvd.nist.gov/rest/json/cves/2.0
Rate Limits  : 5 requests / 30 seconds (unauthenticated)
               50 requests / 30 seconds (with NVD_API_KEY env variable)
Docs         : https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import os
import time
import urllib.error
import urllib.parse
import urllib.request
import json
import threading
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_RESULTS_PER_PAGE = 5


@dataclass
class CVEEntry:
    """Represents a single CVE record from the NVD database."""

    cve_id: str
    description: str
    cvss_score: Optional[float]
    cvss_severity: str  # CRITICAL / HIGH / MEDIUM / LOW / NONE
    published: str
    nvd_url: str

    def to_dict(self) -> Dict:
        return asdict(self)


class _RateLimiter:
    """Simple thread-safe rate limiter for NVD API calls."""

    def __init__(self, calls: int, period: float) -> None:
        self.calls = calls
        self.period = period
        self._lock = threading.Lock()
        self._timestamps: List[float] = []

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            # Remove timestamps older than the period
            self._timestamps = [t for t in self._timestamps if now - t < self.period]
            if len(self._timestamps) >= self.calls:
                sleep_for = self.period - (now - self._timestamps[0])
                if sleep_for > 0:
                    time.sleep(sleep_for)
            self._timestamps.append(time.monotonic())


# Global rate limiter: 5 req / 30s unauthenticated, 50 req / 30s with API key
_rate_limiter = _RateLimiter(
    calls=50 if os.getenv("NVD_API_KEY") else 5,
    period=30.0,
)

# Simple in-memory cache: query_string -> List[CVEEntry]
_cache: Dict[str, List[CVEEntry]] = {}


def _extract_cvss(cve_data: dict) -> tuple[Optional[float], str]:
    """Extract CVSS base score and severity from NVD CVE item metrics."""
    metrics = cve_data.get("metrics", {})

    # Try CVSS v3.1 first, then v3.0, then v2
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity", "NONE")
            return (float(score) if score is not None else None, str(severity).upper())

    return None, "NONE"


def lookup_cves(
    product: str,
    version: str,
    max_results: int = _DEFAULT_RESULTS_PER_PAGE,
    timeout: float = 8.0,
) -> List[CVEEntry]:
    """Query the NVD API for CVEs matching a product name and version.

    Args:
        product: Product name (e.g. "OpenSSH", "Apache HTTP Server").
        version: Version string (e.g. "8.9", "2.4.54").
        max_results: Maximum number of CVE entries to return.
        timeout: HTTP request timeout in seconds.

    Returns:
        List of CVEEntry objects sorted by CVSS score descending.
        Returns empty list on network errors or no results.
    """
    keyword = f"{product} {version}".strip()
    cache_key = keyword.lower()

    if cache_key in _cache:
        return _cache[cache_key]

    _rate_limiter.wait()

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }

    api_key = os.getenv("NVD_API_KEY")
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    url = f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        _cache[cache_key] = []
        return []

    cve_items = data.get("vulnerabilities", [])
    results: List[CVEEntry] = []

    for item in cve_items:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "Unknown")

        # Extract English description
        desc = next(
            (
                d.get("value", "")
                for d in cve_data.get("descriptions", [])
                if d.get("lang") == "en"
            ),
            "No description available.",
        )

        score, severity = _extract_cvss(cve_data)
        published = cve_data.get("published", "")[:10]

        results.append(
            CVEEntry(
                cve_id=cve_id,
                description=desc[:300] + ("..." if len(desc) > 300 else ""),
                cvss_score=score,
                cvss_severity=severity,
                published=published,
                nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        )

    # Sort by CVSS score descending (None scores go to the bottom)
    results.sort(key=lambda c: c.cvss_score or 0.0, reverse=True)
    _cache[cache_key] = results
    return results


def format_cve_summary(cves: List[CVEEntry]) -> str:
    """Format a list of CVEs into a compact human-readable summary string."""
    if not cves:
        return "No CVEs found."

    lines = []
    severity_colors = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "NONE": "⚪",
    }

    for cve in cves:
        icon = severity_colors.get(cve.cvss_severity, "⚪")
        score_str = f"CVSS {cve.cvss_score:.1f}" if cve.cvss_score else "N/A"
        lines.append(f"  {icon} {cve.cve_id} [{score_str} {cve.cvss_severity}] {cve.nvd_url}")

    return "\n".join(lines)
