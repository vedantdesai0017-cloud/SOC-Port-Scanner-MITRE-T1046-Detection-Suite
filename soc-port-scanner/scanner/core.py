"""Core TCP Connect port scanner engine.

Implements multithreaded TCP scanning with ThreadPoolExecutor, service resolution,
banner grabbing, rate limiting, and port randomization.
"""

from __future__ import annotations

import random
import socket
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class PortResult:
    """Represents the scan result for a single target port."""

    ip: str
    port: int
    state: str  # "open", "closed", "filtered"
    service: str
    banner: str
    cves: List[Dict] = field(default_factory=list)  # Populated by CVE lookup (optional)

    def to_dict(self) -> Dict[str, object]:
        """Convert dataclass to dictionary."""
        return asdict(self)


# Extended service mapping for ports that socket.getservbyport may not resolve
COMMON_SERVICE_MAP: Dict[int, str] = {
    8080: "http-proxy",
    8443: "https-alt",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
    9200: "elasticsearch",
    2375: "docker",
    2376: "docker-tls",
    5000: "upnp/flask",
    8000: "http-alt",
    8888: "http-alt",
    3000: "node/react",
}


def resolve_service(port: int) -> str:
    """Resolve port number to standard service name using socket library and fallback database.

    Args:
        port: TCP port number.

    Returns:
        Human-readable service name or 'unknown'.
    """
    try:
        return socket.getservbyport(port, "tcp")
    except (OSError, socket.error):
        return COMMON_SERVICE_MAP.get(port, "unknown")


def grab_banner(sock: socket.socket, port: int, timeout: float = 1.0) -> str:
    """Attempt banner grabbing from an open TCP socket.

    First tries receiving immediate service greetings (SSH, FTP, SMTP),
    and if none arrives, sends a protocol-appropriate probe (HTTP HEAD or newline).

    Args:
        sock: Connected socket.
        port: Destination port number.
        timeout: Socket read timeout in seconds.

    Returns:
        Sanitized banner string, or empty string if no banner was retrieved.
    """
    sock.settimeout(timeout)
    banner_bytes = b""

    # Attempt passive receive first (common for SSH, FTP, SMTP banners)
    try:
        banner_bytes = sock.recv(1024)
    except (socket.timeout, OSError):
        pass

    # If no initial greeting was sent by server, send a probe
    if not banner_bytes:
        try:
            if port in (80, 8080, 8000, 8888, 3000, 5000):
                probe = b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
            else:
                probe = b"\r\n"
            sock.sendall(probe)
            banner_bytes = sock.recv(1024)
        except (socket.timeout, OSError):
            pass

    if not banner_bytes:
        return ""

    # Decode and sanitize banner (clean non-printable characters)
    text = banner_bytes.decode("utf-8", errors="replace").strip()
    # Keep the first line or first 120 chars to avoid bloated output
    first_line = text.split("\r\n")[0].split("\n")[0].strip()
    clean_banner = "".join(c if (c.isprintable() or c == " ") else "?" for c in first_line)
    return clean_banner[:120]


class RateLimiter:
    """Thread-safe rate limiter ensuring minimum interval between outgoing probes."""

    def __init__(self, delay_seconds: float) -> None:
        """Initialize with delay between probes.

        Args:
            delay_seconds: Minimum delay in seconds between connection attempts.
        """
        self.delay = delay_seconds
        self.lock = threading.Lock()
        self.last_time = 0.0

    def wait(self) -> None:
        """Block until the minimum interval since the last probe has elapsed."""
        if self.delay <= 0:
            return
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_time
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
            self.last_time = time.monotonic()


class PortScanner:
    """Multithreaded TCP Connect port scanner with banner grabbing and rate limiting."""

    def __init__(
        self,
        timeout: float = 1.0,
        threads: int = 50,
        rate_limit: float = 0.0,
        randomize_ports: bool = False,
    ) -> None:
        """Initialize the port scanner.

        Args:
            timeout: Socket connection timeout in seconds.
            threads: Maximum number of worker threads.
            rate_limit: Minimum delay in seconds between port probes (0 = no limit).
            randomize_ports: If True, randomize port order to evade simple sequential detection.
        """
        self.timeout = timeout
        self.threads = max(1, threads)
        self.rate_limiter = RateLimiter(rate_limit) if rate_limit > 0 else None
        self.randomize_ports = randomize_ports
        self._stop_event = threading.Event()

    def stop(self) -> None:
        """Signal all worker threads to abort scanning gracefully."""
        self._stop_event.set()

    def scan_port(self, ip: str, port: int) -> Optional[PortResult]:
        """Perform a single TCP connect scan on the given IP and port.

        Args:
            ip: Target IP address.
            port: Target port number.

        Returns:
            PortResult if port is open, or None if closed/filtered.
        """
        if self._stop_event.is_set():
            return None

        if self.rate_limiter:
            self.rate_limiter.wait()

        if self._stop_event.is_set():
            return None

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            # TCP Connect 3-way handshake (SYN -> SYN/ACK -> ACK)
            result_code = sock.connect_ex((ip, port))
            if result_code == 0:
                service = resolve_service(port)
                banner = grab_banner(sock, port, timeout=min(self.timeout, 1.0))
                return PortResult(
                    ip=ip,
                    port=port,
                    state="open",
                    service=service,
                    banner=banner,
                )
            return None
        except (socket.timeout, OSError):
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def scan(
        self,
        ip: str,
        ports: List[int],
        progress_callback: Optional[Callable[[PortResult], None]] = None,
    ) -> List[PortResult]:
        """Scan a list of ports on a target IP address using a thread pool.

        Args:
            ip: Target IP address string.
            ports: List of port numbers to scan.
            progress_callback: Optional callback invoked immediately when an open port is discovered.

        Returns:
            List of PortResult objects for all discovered open ports.
        """
        self._stop_event.clear()
        target_ports = list(ports)
        if self.randomize_ports:
            random.shuffle(target_ports)

        open_ports: List[PortResult] = []
        lock = threading.Lock()

        from concurrent.futures import ThreadPoolExecutor, as_completed

        def worker(p: int) -> Optional[PortResult]:
            return self.scan_port(ip, p)

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_port = {
                    executor.submit(worker, p): p for p in target_ports
                }

                for future in as_completed(future_to_port):
                    if self._stop_event.is_set():
                        break
                    try:
                        res = future.result()
                        if res and res.state == "open":
                            with lock:
                                open_ports.append(res)
                            if progress_callback:
                                progress_callback(res)
                    except Exception:
                        pass
        except KeyboardInterrupt:
            self.stop()
            print("\n[!] Ctrl+C detected. Cancelling remaining tasks...", file=sys.stderr)

        return sorted(open_ports, key=lambda r: r.port)
