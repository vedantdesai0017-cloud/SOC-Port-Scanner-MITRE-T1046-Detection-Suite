"""Network utilities, input validation, and safety controls for the port scanner.

Provides functions for parsing port specifications, expanding target expressions
(IPs, hostnames, CIDRs), and enforcing authorization checks for public targets.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import List, Sequence

# Top 20 well-known ports scanned when no specific ports are provided
DEFAULT_COMMON_PORTS: List[int] = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    111,   # RPCBind
    135,   # MSRPC
    139,   # NetBIOS
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    993,   # IMAPS
    995,   # POP3S
    1723,  # PPTP
    3306,  # MySQL
    3389,  # RDP
    5900,  # VNC
    8080,  # HTTP-Proxy
    8443,  # HTTPS-Alt
]


def parse_port_range(port_spec: str | None) -> List[int]:
    """Parse a flexible port specification string into a sorted, deduplicated list of ports.

    Supported formats:
        - None or empty string -> default common ports
        - Single port: "80"
        - Comma-separated list: "22,80,443"
        - Hyphenated range: "100-200"
        - Mixed expression: "21-25,80,443,8000-8080"

    Args:
        port_spec: String containing comma-separated port numbers or ranges.

    Returns:
        List of unique integer port numbers, sorted in ascending order.

    Raises:
        ValueError: If a port is outside 1-65535 or contains invalid characters.
    """
    if not port_spec or not port_spec.strip():
        return list(DEFAULT_COMMON_PORTS)

    ports: set[int] = set()
    tokens = [t.strip() for t in port_spec.split(",") if t.strip()]

    if not tokens:
        raise ValueError("Invalid port specification: no valid port tokens found.")

    for token in tokens:
        if "-" in token:
            parts = token.split("-")
            if len(parts) != 2:
                raise ValueError(
                    f"Invalid port range '{token}'. Range must be formatted as START-END (e.g. 100-200)."
                )
            try:
                start = int(parts[0].strip())
                end = int(parts[1].strip())
            except ValueError as exc:
                raise ValueError(
                    f"Invalid integer in port range '{token}': {exc}"
                ) from exc

            if start < 1 or end > 65535:
                raise ValueError(
                    f"Port range '{token}' out of bounds. Ports must be between 1 and 65535."
                )
            if start > end:
                raise ValueError(
                    f"Invalid port range '{token}': start port ({start}) cannot exceed end port ({end})."
                )

            ports.update(range(start, end + 1))
        else:
            try:
                port = int(token)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid port '{token}'. Must be a valid integer between 1 and 65535."
                ) from exc

            if port < 1 or port > 65535:
                raise ValueError(
                    f"Port '{port}' out of bounds. Ports must be between 1 and 65535."
                )
            ports.add(port)

    return sorted(ports)


def expand_targets(target_spec: str) -> List[str]:
    """Expand a target string into a list of individual IP address strings.

    Accepts:
        - Single IPv4 / IPv6 address (e.g. "127.0.0.1", "::1")
        - CIDR network notation (e.g. "192.168.1.0/30")
        - Hostname (e.g. "localhost", "scanme.nmap.org")

    Args:
        target_spec: Raw user target input.

    Returns:
        List of resolved IP address strings.

    Raises:
        ValueError: If the target cannot be resolved or is an invalid network spec.
    """
    target = target_spec.strip()
    if not target:
        raise ValueError("Target specification cannot be empty.")

    # 1. Attempt CIDR network parsing
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            # For /31 and /32, hosts() is empty or single; fallback to network.hosts() or all IPs
            if network.num_addresses <= 2:
                return [str(ip) for ip in network]
            return [str(ip) for ip in network.hosts()]
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR network '{target}': {exc}") from exc

    # 2. Attempt raw IP address parsing
    try:
        ip_obj = ipaddress.ip_address(target)
        return [str(ip_obj)]
    except ValueError:
        pass  # Not a literal IP, try resolving as hostname

    # 3. Resolve as hostname
    try:
        resolved_ip = socket.gethostbyname(target)
        return [resolved_ip]
    except socket.gaierror as exc:
        raise ValueError(
            f"Failed to resolve hostname '{target}'. Ensure it is reachable and DNS is working."
        ) from exc


def is_private_or_lab_ip(ip_str: str) -> bool:
    """Check if an IP address belongs to private, loopback, or link-local address spaces.

    Evaluates:
        - RFC 1918 Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        - Loopback ranges (127.0.0.0/8, ::1)
        - Link-local ranges (169.254.0.0/16, fe80::/10)
        - Reserved / documentation spaces (e.g. 192.0.2.0/24)

    Args:
        ip_str: IPv4 or IPv6 address string.

    Returns:
        True if the IP is private/local/lab-safe, False if public/routable.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
        )
    except ValueError:
        return False


def verify_target_authorization(
    targets: Sequence[str],
    force: bool = False,
    prompt_fn=input,
) -> bool:
    """Enforce authorization confirmation before scanning any public or non-private IP.

    Adheres to the strict project rule:
    Only scan localhost, lab VMs, or authorized targets (e.g., scanme.nmap.org).
    If any target is public, prompts user for confirmation unless `force=True`.

    Args:
        targets: Sequence of target IP address strings.
        force: If True, bypass interactive prompt (useful for scripted tests).
        prompt_fn: Callable for user input (default built-in input, injectable for testing).

    Returns:
        True if approved, False if denied.
    """
    public_targets = [ip for ip in targets if not is_private_or_lab_ip(ip)]

    if not public_targets:
        return True

    print("\n" + "=" * 70)
    print("  [!] CAUTION: NON-PRIVATE / PUBLIC TARGET DETECTED")
    print("=" * 70)
    print(f"Target(s) outside private RFC1918/loopback ranges: {', '.join(public_targets)}")
    print(
        "Scanning networks without explicit prior written authorization is illegal\n"
        "under computer crime laws (e.g. CFAA 18 U.S.C. 1030 in the US, Computer Misuse Act in the UK).\n"
        "Approved test targets: 'localhost', your own lab VMs, or 'scanme.nmap.org'."
    )
    print("=" * 70)

    if force:
        print("[*] Authorization warning bypassed via --force / non-interactive mode.")
        return True

    try:
        answer = prompt_fn(
            "Do you have explicit permission to scan this target? [y/N]: "
        ).strip().lower()
        return answer in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Scan aborted by user.")
        return False
