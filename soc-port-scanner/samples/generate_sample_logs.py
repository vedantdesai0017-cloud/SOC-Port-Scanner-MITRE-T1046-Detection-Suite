"""Synthetic network traffic log generator.

Generates realistic network firewall/connection logs combining legitimate background
traffic (HTTP, HTTPS, DNS, NTP) with simulated port scans from attacker IPs.
Used for validating detection rules and demonstrating SOC alert generation.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from typing import List


def generate_logs(output_file: str, base_time: datetime | None = None) -> int:
    """Generate sample network connection logs with benign traffic and injected port scans.

    Args:
        output_file: Destination file path.
        base_time: Starting reference datetime (default: current UTC time - 10 minutes).

    Returns:
        Total number of log events written.
    """
    if base_time is None:
        base_time = datetime.now(timezone.utc) - timedelta(minutes=10)

    events: List[dict] = []

    # 1. Benign background network traffic over 10 minutes
    benign_clients = ["192.168.1.101", "192.168.1.102", "192.168.1.103", "192.168.1.104"]
    web_server = "192.168.1.10"
    dns_server = "192.168.1.1"
    db_server = "192.168.1.15"

    for minute in range(10):
        t_base = base_time + timedelta(minutes=minute)
        for client in benign_clients:
            # Client browsing web server (ports 80 and 443)
            for _ in range(random.randint(2, 5)):
                ts = t_base + timedelta(seconds=random.randint(0, 50))
                events.append({
                    "timestamp": ts.isoformat(),
                    "src_ip": client,
                    "dest_ip": web_server,
                    "dest_port": random.choice([80, 443]),
                    "proto": "TCP",
                    "action": "ALLOW",
                })

            # Client querying DNS (port 53)
            ts = t_base + timedelta(seconds=random.randint(0, 50))
            events.append({
                "timestamp": ts.isoformat(),
                "src_ip": client,
                "dest_ip": dns_server,
                "dest_port": 53,
                "proto": "UDP",
                "action": "ALLOW",
            })

            # Client 101 talking to database (port 5432)
            if client == "192.168.1.101":
                ts = t_base + timedelta(seconds=random.randint(0, 50))
                events.append({
                    "timestamp": ts.isoformat(),
                    "src_ip": client,
                    "dest_ip": db_server,
                    "dest_port": 5432,
                    "proto": "TCP",
                    "action": "ALLOW",
                })

    # 2. Injected Malicious Port Scan #1: Fast Aggressive Scanner
    # Attacker IP: 192.168.1.185 scanning Target 192.168.1.10
    # Touches 30 distinct ports within 20 seconds at Minute 3
    scan_start = base_time + timedelta(minutes=3, seconds=10)
    attacker_1 = "192.168.1.185"
    scan_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017, 5000, 3000
    ]

    for idx, port in enumerate(scan_ports):
        # 0.5s intervals between probes
        ts = scan_start + timedelta(seconds=idx * 0.5)
        events.append({
            "timestamp": ts.isoformat(),
            "src_ip": attacker_1,
            "dest_ip": web_server,
            "dest_port": port,
            "proto": "TCP",
            "action": "DROP" if port not in (80, 443) else "ALLOW",
        })

    # 3. Injected Malicious Port Scan #2: External Reconnaissance
    # Attacker IP: 203.0.113.77 scanning Target 192.168.1.10
    # Touches 15 distinct ports within 25 seconds at Minute 6
    scan_start_2 = base_time + timedelta(minutes=6, seconds=30)
    attacker_2 = "203.0.113.77"
    scan_ports_2 = [21, 22, 80, 443, 445, 3389, 8080, 8443, 8000, 8888, 9000, 9090, 10000, 3128, 8081]

    for idx, port in enumerate(scan_ports_2):
        ts = scan_start_2 + timedelta(seconds=idx * 1.2)
        events.append({
            "timestamp": ts.isoformat(),
            "src_ip": attacker_2,
            "dest_ip": web_server,
            "dest_port": port,
            "proto": "TCP",
            "action": "DROP",
        })

    # Sort all events chronologically by timestamp
    events.sort(key=lambda e: e["timestamp"])

    # Ensure parent directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    return len(events)


def main() -> int:
    """CLI generator script."""
    parser = argparse.ArgumentParser(description="Generate synthetic network logs with port scans.")
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="samples/network_traffic.log",
        help="Output log file path (default: samples/network_traffic.log).",
    )
    args = parser.parse_args()

    count = generate_logs(args.output)
    print(f"[+] Successfully generated {count} network log events in '{args.output}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
