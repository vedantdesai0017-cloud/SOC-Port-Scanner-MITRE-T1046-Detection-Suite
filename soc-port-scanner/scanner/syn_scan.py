"""Optional TCP SYN (Half-Open) Stealth Scan module using Scapy.

A TCP SYN scan sends a SYN packet and waits for a SYN-ACK (indicating open)
or RST (indicating closed). If a SYN-ACK is received, the scanner sends a RST
to terminate the connection immediately without completing the 3-way handshake.

Requires:
    - Scapy package (`pip install scapy`)
    - Administrative / Root privileges (raw socket creation)
"""

from __future__ import annotations

import os
import sys
from typing import Dict, List, Optional

from scanner.core import PortResult, resolve_service


def is_admin_or_root() -> bool:
    """Check if the current process has administrative or root privileges."""
    try:
        # POSIX (Linux, macOS)
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
        # Windows
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def syn_scan_port(target_ip: str, port: int, timeout: float = 1.5) -> Optional[PortResult]:
    """Perform a half-open TCP SYN scan on a single port using Scapy.

    Args:
        target_ip: Destination IPv4 address.
        port: Destination port number.
        timeout: Packet wait timeout in seconds.

    Returns:
        PortResult if port is open, or None if closed/filtered.

    Raises:
        ImportError: If scapy is not installed.
        PermissionError: If the process does not have raw socket / admin privileges.
    """
    try:
        from scapy.all import IP, TCP, RandShort, conf, sr1
        conf.verb = 0  # Suppress Scapy verbose output
    except ImportError as exc:
        raise ImportError(
            "Scapy is required for SYN scanning. Install it via 'pip install scapy'."
        ) from exc

    if not is_admin_or_root():
        raise PermissionError(
            "SYN scan requires administrative / root privileges to create raw sockets. "
            "Please run your terminal as Administrator (Windows) or use 'sudo' (Linux/macOS)."
        )

    src_port = RandShort()
    syn_packet = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="S")

    try:
        response = sr1(syn_packet, timeout=timeout, verbose=0)
    except PermissionError as exc:
        raise PermissionError(
            "Raw socket creation failed. Ensure administrative privileges and Npcap/libpcap are installed."
        ) from exc

    if response is None:
        # Packet dropped or filtered
        return None

    if response.haslayer(TCP):
        tcp_layer = response.getlayer(TCP)
        # TCP Flags: SYN=0x02, ACK=0x10, RST=0x04
        # SYN-ACK is 0x12 (18)
        if tcp_layer.flags == 0x12:
            # Teardown connection immediately with RST so the handshake is never completed
            rst_packet = IP(dst=target_ip) / TCP(sport=src_port, dport=port, flags="R")
            try:
                from scapy.all import send
                send(rst_packet, verbose=0)
            except Exception:
                pass

            service = resolve_service(port)
            return PortResult(
                ip=target_ip,
                port=port,
                state="open",
                service=service,
                banner="[SYN-ACK Stealth / No Banner]",
            )
        # RST or RST-ACK means closed
        return None

    return None


def run_syn_scan(
    target_ip: str,
    ports: List[int],
    timeout: float = 1.5,
) -> List[PortResult]:
    """Execute a sequential TCP SYN scan across a list of ports.

    Args:
        target_ip: Target IP address.
        ports: List of destination ports.
        timeout: Packet timeout per probe.

    Returns:
        List of PortResult objects for open ports.
    """
    open_results: List[PortResult] = []
    for port in ports:
        try:
            res = syn_scan_port(target_ip, port, timeout=timeout)
            if res:
                open_results.append(res)
        except (ImportError, PermissionError) as exc:
            print(f"[!] SYN scan error: {exc}", file=sys.stderr)
            raise
    return open_results
