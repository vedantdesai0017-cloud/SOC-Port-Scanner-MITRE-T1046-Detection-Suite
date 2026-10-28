"""Command-Line Interface (CLI) for the SOC Port Scanner.

Provides argument parsing, target safety validation, formatted terminal output,
and export to JSON/CSV formats.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import List, Optional

from scanner.core import PortResult, PortScanner
from scanner.syn_scan import run_syn_scan
from scanner.utils import (
    DEFAULT_COMMON_PORTS,
    expand_targets,
    parse_port_range,
    verify_target_authorization,
)
from scanner.version_parser import parse_banner
from scanner.cve_lookup import lookup_cves, format_cve_summary


def format_table(results: List[PortResult], show_cves: bool = False) -> str:
    """Format a list of PortResult objects into an aligned ASCII table."""
    if not results:
        return "No open ports discovered."

    headers = ["PORT", "STATE", "SERVICE", "BANNER", "CVEs"] if show_cves else ["PORT", "STATE", "SERVICE", "BANNER"]
    rows = []
    for r in results:
        port_str = f"{r.port}/tcp"
        banner_clean = r.banner if r.banner else "-"
        row = [port_str, r.state, r.service, banner_clean]
        if show_cves:
            cve_str = f"{len(r.cves)} found" if r.cves else "-"
            row.append(cve_str)
        rows.append(row)

    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, val in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(str(val)))

    header_line = "  ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    separator = "  ".join("-" * col_widths[i] for i in range(len(headers)))
    row_lines = [
        "  ".join(str(val).ljust(col_widths[i]) for i, val in enumerate(row))
        for row in rows
    ]

    return f"{header_line}\n{separator}\n" + "\n".join(row_lines)


def export_results(
    results: List[PortResult],
    output_path: str,
    target: str,
    duration: float,
) -> None:
    """Export scan results to a JSON or CSV file based on file extension.

    Args:
        results: List of open PortResult objects.
        output_path: Filepath to write results.
        target: Target address or range.
        duration: Scan elapsed time in seconds.
    """
    ext = os.path.splitext(output_path)[1].lower()

    if ext == ".csv" or output_path.lower() == "csv":
        file_to_write = output_path if ext else f"{output_path}.csv"
        with open(file_to_write, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["target_ip", "port", "protocol", "state", "service", "banner"])
            for r in results:
                writer.writerow([r.ip, r.port, "tcp", r.state, r.service, r.banner])
        print(f"[+] Scan results exported to CSV: {file_to_write}")

    else:
        # Default to JSON
        file_to_write = output_path if ext else f"{output_path}.json"
        data = {
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": round(duration, 3),
            "open_ports_count": len(results),
            "results": [r.to_dict() for r in results],
        }
        with open(file_to_write, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Scan results exported to JSON: {file_to_write}")


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="soc-port-scanner",
        description=(
            "SOC Port Scanner - Multithreaded TCP Connect & SYN Port Scanner "
            "with Banner Grabbing and MITRE ATT&CK T1046 Detection."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m scanner.cli 127.0.0.1 --ports 22,80,443\n"
            "  python -m scanner.cli 192.168.1.1 --ports 1-1024 --threads 100\n"
            "  python -m scanner.cli 192.168.1.0/30 --ports 80,443,8080 --output results.json\n"
            "  python -m scanner.cli scanme.nmap.org --ports 22,80 --randomize-ports --rate-limit 0.05\n"
        ),
    )

    parser.add_argument(
        "target",
        type=str,
        help="Target IP address, hostname (e.g. scanme.nmap.org), or CIDR block (e.g. 192.168.1.0/30).",
    )

    parser.add_argument(
        "-p",
        "--ports",
        type=str,
        default=None,
        help="Port(s) to scan: comma-separated list, range, or combination (e.g. 22,80,100-200). Default: Top 20 common ports.",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=50,
        help="Number of concurrent worker threads (default: 50).",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds per probe (default: 1.0).",
    )

    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        help="Minimum delay in seconds between port probes to throttle traffic (default: 0.0).",
    )

    parser.add_argument(
        "--randomize-ports",
        action="store_true",
        help="Randomize the scanning order of destination ports to evade sequential detection.",
    )

    parser.add_argument(
        "--syn-scan",
        action="store_true",
        help="Use TCP SYN (half-open stealth) scan via Scapy (requires root / administrator privileges).",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Export results to a file (formats: .json or .csv).",
    )

    parser.add_argument(
        "-y",
        "--force-yes",
        action="store_true",
        help="Bypass authorization prompt when scanning public IP addresses (for scripted lab runs).",
    )

    parser.add_argument(
        "--cve-check",
        action="store_true",
        help="After banner grabbing, query the NVD API for known CVEs matching the detected service version (requires internet).",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # 1. Parse port range
    try:
        ports = parse_port_range(args.ports)
    except ValueError as exc:
        print(f"[-] Port Error: {exc}", file=sys.stderr)
        return 1

    # 2. Expand targets (IP, hostname, CIDR)
    try:
        target_ips = expand_targets(args.target)
    except ValueError as exc:
        print(f"[-] Target Error: {exc}", file=sys.stderr)
        return 1

    # 3. Check safety / authorization rules
    if not verify_target_authorization(target_ips, force=args.force_yes):
        print("[-] Target authorization denied. Scan terminated.", file=sys.stderr)
        return 1

    print("\n" + "=" * 60)
    print(" SOC Port Scanner (T1046 - Network Service Discovery)")
    print("=" * 60)
    print(f" Target               : {args.target}")
    print(f" Resolved Hosts ({len(target_ips)}): {', '.join(target_ips[:5])}{' ...' if len(target_ips) > 5 else ''}")
    print(f" Total Ports per Host : {len(ports)}")
    print(f" Scan Technique       : {'TCP SYN (Half-Open)' if args.syn_scan else 'TCP Connect (Full 3-Way)'}")
    print(f" Worker Threads       : {args.threads}")
    print(f" Socket Timeout       : {args.timeout}s")
    if args.rate_limit > 0:
        print(f" Rate Limit Delay     : {args.rate_limit}s/probe")
    if args.randomize_ports:
        print(" Port Randomization   : Enabled")
    if args.cve_check:
        print(" CVE Lookup           : Enabled (NVD API)")
    print("=" * 60 + "\n")

    start_time = time.time()
    all_results: List[PortResult] = []

    try:
        for idx, target_ip in enumerate(target_ips, start=1):
            if len(target_ips) > 1:
                print(f"[*] Scanning host {idx}/{len(target_ips)}: {target_ip}...")

            if args.syn_scan:
                try:
                    host_results = run_syn_scan(target_ip, ports, timeout=args.timeout)
                except (ImportError, PermissionError) as exc:
                    print(f"[-] SYN Scan Failed: {exc}", file=sys.stderr)
                    return 2
            else:
                scanner = PortScanner(
                    timeout=args.timeout,
                    threads=args.threads,
                    rate_limit=args.rate_limit,
                    randomize_ports=args.randomize_ports,
                )
                host_results = scanner.scan(target_ip, ports)

            all_results.extend(host_results)

    except KeyboardInterrupt:
        print("\n[!] User interrupted the scan (Ctrl+C). Showing partial results below.", file=sys.stderr)

    duration = time.time() - start_time

    # Display results table
    print(f"\n--- Scan Report ({len(all_results)} open ports found in {duration:.2f}s) ---")
    print(format_table(all_results, show_cves=args.cve_check))

    # CVE Lookup section
    if args.cve_check and all_results:
        print("\n--- CVE Analysis (via NVD API) ---")
        any_cves = False
        for result in all_results:
            parsed = parse_banner(result.banner) if result.banner else None
            if parsed:
                print(f"\n[*] {result.port}/tcp ({result.service}) — Detected: {parsed.product} {parsed.version}")
                cves = lookup_cves(parsed.product, parsed.version)
                result.cves = [c.to_dict() for c in cves]
                if cves:
                    any_cves = True
                    print(format_cve_summary(cves))
                else:
                    print("  No matching CVEs found in NVD.")
            else:
                result.cves = []
        if not any_cves:
            print("[*] No parseable service versions detected in banners for CVE correlation.")

    # Export if requested
    if args.output:
        export_results(all_results, args.output, args.target, duration)

    return 0


if __name__ == "__main__":
    sys.exit(main())
