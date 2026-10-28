"""Unit tests for port scanning core, parser, and utilities."""

import socket
import threading
import time
from typing import List

import pytest

from scanner.core import PortResult, PortScanner, RateLimiter, grab_banner, resolve_service
from scanner.utils import (
    DEFAULT_COMMON_PORTS,
    expand_targets,
    is_private_or_lab_ip,
    parse_port_range,
    verify_target_authorization,
)


# --- Port Parsing Tests ---


def test_parse_port_range_default():
    """Verify default ports returned when no input provided."""
    assert parse_port_range(None) == DEFAULT_COMMON_PORTS
    assert parse_port_range("") == DEFAULT_COMMON_PORTS
    assert parse_port_range("   ") == DEFAULT_COMMON_PORTS


def test_parse_port_range_single_and_list():
    """Verify single and comma-separated ports."""
    assert parse_port_range("80") == [80]
    assert parse_port_range("80, 443, 22") == [22, 80, 443]


def test_parse_port_range_hyphenated():
    """Verify hyphenated ranges."""
    assert parse_port_range("20-25") == [20, 21, 22, 23, 24, 25]


def test_parse_port_range_mixed():
    """Verify mixed ranges with duplicates."""
    result = parse_port_range("22, 80-82, 80, 443")
    assert result == [22, 80, 81, 82, 443]


def test_parse_port_range_invalid_values():
    """Verify ValueError for invalid port inputs."""
    with pytest.raises(ValueError, match="between 1 and 65535"):
        parse_port_range("0")

    with pytest.raises(ValueError, match="between 1 and 65535"):
        parse_port_range("70000")

    with pytest.raises(ValueError, match="start port .* cannot exceed end port"):
        parse_port_range("100-50")

    with pytest.raises(ValueError, match="Invalid integer"):
        parse_port_range("abc-def")

    with pytest.raises(ValueError, match="Invalid port"):
        parse_port_range("22,foo,80")


# --- Target Expansion Tests ---


def test_expand_targets_single_ip():
    """Verify single IP addresses."""
    assert expand_targets("127.0.0.1") == ["127.0.0.1"]
    assert expand_targets("192.168.1.100") == ["192.168.1.100"]


def test_expand_targets_cidr():
    """Verify CIDR notation expands to usable host IPs."""
    # /30 network has 4 addresses: network, 2 usable hosts, broadcast
    hosts = expand_targets("192.168.1.0/30")
    assert hosts == ["192.168.1.1", "192.168.1.2"]

    # /32 network represents exactly 1 host
    single = expand_targets("10.0.0.5/32")
    assert single == ["10.0.0.5"]


def test_expand_targets_hostname():
    """Verify hostname resolution."""
    hosts = expand_targets("localhost")
    assert "127.0.0.1" in hosts


def test_expand_targets_invalid():
    """Verify error on empty or unresolvable targets."""
    with pytest.raises(ValueError, match="cannot be empty"):
        expand_targets("")

    with pytest.raises(ValueError, match="Failed to resolve hostname"):
        expand_targets("this-domain-does-not-exist-at-all-123456789.invalid")


# --- Safety / Authorization Tests ---


def test_is_private_or_lab_ip():
    """Verify private, loopback, and public IP detection."""
    assert is_private_or_lab_ip("127.0.0.1") is True
    assert is_private_or_lab_ip("10.0.0.1") is True
    assert is_private_or_lab_ip("172.16.0.5") is True
    assert is_private_or_lab_ip("192.168.1.254") is True
    assert is_private_or_lab_ip("169.254.1.1") is True  # link-local

    # Public routable IPs
    assert is_private_or_lab_ip("8.8.8.8") is False
    assert is_private_or_lab_ip("1.1.1.1") is False


def test_verify_target_authorization_private():
    """Verify that private targets pass without prompting."""
    assert verify_target_authorization(["127.0.0.1", "192.168.1.1"]) is True


def test_verify_target_authorization_public():
    """Verify prompt logic for non-private targets."""
    # User confirms 'y'
    assert verify_target_authorization(["8.8.8.8"], force=False, prompt_fn=lambda _: "y") is True
    # User denies 'n'
    assert verify_target_authorization(["8.8.8.8"], force=False, prompt_fn=lambda _: "n") is False
    # Force flag bypasses prompt
    assert verify_target_authorization(["8.8.8.8"], force=True) is True


# --- Service Resolution and Banner Grabbing Tests ---


def test_resolve_service():
    """Verify service resolution for common ports."""
    assert resolve_service(80) == "http"
    assert resolve_service(443) == "https"
    assert resolve_service(8080) in ("http-proxy", "http-alt")
    assert resolve_service(65432) == "unknown"


def test_rate_limiter():
    """Verify rate limiter enforces minimum delay."""
    delay = 0.05
    limiter = RateLimiter(delay_seconds=delay)
    start = time.monotonic()
    limiter.wait()
    limiter.wait()
    elapsed = time.monotonic() - start
    assert elapsed >= delay * 0.8  # Allow slight timing jitter


# --- Live Local Socket Scanner Test ---


@pytest.fixture
def mock_tcp_server():
    """Start an ephemeral local TCP server returning a mock banner for testing."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))  # OS assigns free ephemeral port
    port = sock.getsockname()[1]
    sock.listen(5)

    stop_event = threading.Event()

    def server_loop():
        while not stop_event.is_set():
            try:
                sock.settimeout(0.5)
                client_sock, _ = sock.accept()
                client_sock.sendall(b"SSH-2.0-MockOpenSSH_9.0\r\n")
                client_sock.close()
            except (socket.timeout, OSError):
                continue

    thread = threading.Thread(target=server_loop, daemon=True)
    thread.start()

    yield port

    stop_event.set()
    sock.close()
    thread.join(timeout=1.0)


# --- Scanner Core & Mocking Tests ---


def test_port_scanner_mocked_open_and_closed():
    """Verify PortScanner correctly handles open and closed ports via mocked sockets."""
    from unittest.mock import MagicMock, patch

    mock_sock = MagicMock()
    # Port 80 is open (connect_ex returns 0), Port 81 is closed (connect_ex returns 10061)
    def fake_connect_ex(addr):
        ip, port = addr
        return 0 if port == 80 else 10061

    mock_sock.connect_ex.side_effect = fake_connect_ex
    mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"

    with patch("socket.socket", return_value=mock_sock):
        scanner = PortScanner(timeout=0.5, threads=2)
        results = scanner.scan("127.0.0.1", [80, 81])

    assert len(results) == 1
    assert results[0].port == 80
    assert results[0].state == "open"
    assert results[0].service == "http"
    assert "HTTP/1.1 200 OK" in results[0].banner


def test_port_scanner_detects_open_port(mock_tcp_server):
    """Verify PortScanner discovers a live open port if network sandbox allows."""
    open_port = mock_tcp_server
    scanner = PortScanner(timeout=0.5, threads=2)

    # Check if sandbox permits live loopback
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        err = probe.connect_ex(("127.0.0.1", open_port))
    except Exception:
        err = 10013
    finally:
        probe.close()

    if err == 10013:
        pytest.skip("Loopback socket creation restricted by local sandbox environment (WSAEACCES).")

    results = scanner.scan("127.0.0.1", [open_port])
    assert len(results) == 1
    assert results[0].port == open_port
    assert results[0].state == "open"

