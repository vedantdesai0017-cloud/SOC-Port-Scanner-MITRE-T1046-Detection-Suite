"""Banner version parsing utilities for CVE correlation.

Extracts product names and version strings from TCP banner text
using common patterns for SSH, HTTP, FTP, SMTP, and database services.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ServiceVersion:
    """Parsed product name and version from a service banner."""

    product: str
    version: str
    raw_banner: str

    @property
    def search_query(self) -> str:
        """Construct a clean NVD keyword search string."""
        return f"{self.product} {self.version}".strip()


# Ordered list of (pattern, product_name) tuples.
# Each pattern must capture a version string in group 1.
_BANNER_PATTERNS: list[tuple[re.Pattern, str]] = [
    # SSH: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
    (re.compile(r"SSH-[\d.]+-OpenSSH[_\s]([\d.p]+)", re.I), "OpenSSH"),
    # HTTP Server header: Apache/2.4.54  or  nginx/1.23.1
    (re.compile(r"Apache/([\d.]+)", re.I), "Apache HTTP Server"),
    (re.compile(r"nginx/([\d.]+)", re.I), "nginx"),
    (re.compile(r"Microsoft-IIS/([\d.]+)", re.I), "Microsoft IIS"),
    (re.compile(r"lighttpd/([\d.]+)", re.I), "lighttpd"),
    # FTP: 220 ProFTPD 1.3.7 Server
    (re.compile(r"ProFTPD\s+([\d.]+)", re.I), "ProFTPD"),
    (re.compile(r"vsftpd\s+([\d.]+)", re.I), "vsftpd"),
    (re.compile(r"FileZilla Server\s+([\d.]+)", re.I), "FileZilla Server"),
    # SMTP: 220 mail.example.com ESMTP Postfix  /  Sendmail
    (re.compile(r"Postfix\s+SMTP\s+([\d.]+)", re.I), "Postfix"),
    (re.compile(r"Sendmail\s+([\d./]+)", re.I), "Sendmail"),
    (re.compile(r"Exim\s+([\d.]+)", re.I), "Exim"),
    # MySQL: 5.5.68-MariaDB / 8.0.31
    (re.compile(r"([\d.]+)-MariaDB", re.I), "MariaDB"),
    (re.compile(r"\x00\x00\x00\x0a([\d.]+)", re.I), "MySQL"),
    # Redis: -ERR ... NOAUTH / +OK or inline version
    (re.compile(r"Redis\s+([\d.]+)", re.I), "Redis"),
    # OpenSSL in HTTP headers
    (re.compile(r"OpenSSL/([\d.]+[a-z]?)", re.I), "OpenSSL"),
    # Generic version fallback: capture "word/version" or "word version"
    (re.compile(r"([A-Za-z][A-Za-z0-9\-_]+)[/ ]([\d]+\.[\d]+\.[\d]+)"), None),
]


def parse_banner(banner: str) -> Optional[ServiceVersion]:
    """Attempt to extract a product name and version from a banner string.

    Args:
        banner: Raw banner text from banner grabbing.

    Returns:
        ServiceVersion if a known product and version were detected, else None.
    """
    if not banner or not banner.strip():
        return None

    for pattern, product_name in _BANNER_PATTERNS:
        match = pattern.search(banner)
        if not match:
            continue

        if product_name is None:
            # Generic fallback pattern has 2 capture groups
            product_name = match.group(1)
            version = match.group(2)
        else:
            version = match.group(1)

        return ServiceVersion(
            product=product_name,
            version=version,
            raw_banner=banner,
        )

    return None
