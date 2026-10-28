"""Network port scan detector and alert generator.

Parses network connection logs (JSON, CSV, Syslog/Firewall text) or PCAP files,
identifying horizontal and vertical port scans using a sliding time-window algorithm.
Maps all detections to MITRE ATT&CK Technique T1046 (Network Service Discovery).

Features:
  - Multi-format log ingestion: JSON lines, iptables/ufw KV, CSV, PCAP
  - Sliding time-window deque engine with configurable threshold and cooldown
  - --watch mode: real-time live log tail monitoring
  - --geoip flag: enriches alerts with country, city, ISP via ip-api.com
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Iterator, List, Optional, Set, Tuple


@dataclass
class ConnectionEvent:
    """Normalized network connection event."""

    timestamp: float  # Epoch seconds
    src_ip: str
    dest_ip: str
    dest_port: int
    protocol: str = "TCP"
    raw_event: Optional[str] = None


@dataclass
class ScanAlert:
    """Structured security alert for detected port scanning activity."""

    alert_id: str
    alert_timestamp: str
    event_timestamp: str
    source_ip: str
    target_ip: str
    distinct_ports_count: int
    ports_hit: List[int]
    window_seconds: float
    threshold: int
    mitre_attack: Dict[str, str]
    geoip: Optional[Dict[str, Any]] = None  # Populated if --geoip flag is set

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert dataclass to dictionary."""
        return asdict(self)


def parse_timestamp(val: Any) -> float:
    """Parse various timestamp representations into epoch seconds float."""
    if isinstance(val, (int, float)):
        return float(val)

    if not isinstance(val, str):
        return datetime.now(timezone.utc).timestamp()

    val_str = val.strip()

    # Try direct numeric string
    try:
        return float(val_str)
    except ValueError:
        pass

    # Try ISO-8601 formats
    try:
        # Python 3.11+ datetime.fromisoformat handles most ISO 8601 strings
        dt = datetime.fromisoformat(val_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        pass

    # Try standard syslog/apache formats
    current_year = datetime.now(timezone.utc).year
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.strptime(val_str, fmt)
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue

    # Syslog format without year (e.g. "Oct 28 12:00:01")
    try:
        dt = datetime.strptime(f"{current_year} {val_str}", f"%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        pass

    return datetime.now(timezone.utc).timestamp()


# Regex patterns for iptables / syslog / firewall logs
KV_SRC_RE = re.compile(r"(?:SRC=|src=|source_ip=)([\d\.:a-fA-F]+)")
KV_DST_RE = re.compile(r"(?:DST=|dst=|dest_ip=)([\d\.:a-fA-F]+)")
KV_DPT_RE = re.compile(r"(?:DPT=|dpt=|dest_port=|dport=)(\d+)")
KV_PROTO_RE = re.compile(r"(?:PROTO=|proto=)([a-zA-Z]+)")


def parse_log_line(line: str) -> Optional[ConnectionEvent]:
    """Parse a single raw log line (JSON, CSV, or Firewall key-value) into a ConnectionEvent."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    # 1. Try parsing JSON format
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            data = json.loads(stripped)
            ts = parse_timestamp(data.get("timestamp") or data.get("time") or data.get("@timestamp") or time_now_epoch())
            src = data.get("src_ip") or data.get("source_ip") or data.get("id.orig_h") or data.get("src")
            dst = data.get("dest_ip") or data.get("destination_ip") or data.get("id.resp_h") or data.get("dst")
            port_val = data.get("dest_port") or data.get("dport") or data.get("id.resp_p") or data.get("port")
            proto = data.get("proto") or data.get("protocol") or "TCP"

            if src and dst and port_val is not None:
                return ConnectionEvent(
                    timestamp=ts,
                    src_ip=str(src),
                    dest_ip=str(dst),
                    dest_port=int(port_val),
                    protocol=str(proto).upper(),
                    raw_event=stripped,
                )
        except Exception:
            pass

    # 2. Try parsing Firewall key-value pairs (iptables, ufw, cisco)
    src_match = KV_SRC_RE.search(stripped)
    dst_match = KV_DST_RE.search(stripped)
    dpt_match = KV_DPT_RE.search(stripped)

    if src_match and dst_match and dpt_match:
        proto_match = KV_PROTO_RE.search(stripped)
        proto = proto_match.group(1).upper() if proto_match else "TCP"
        # Extract leading timestamp if present
        time_part = stripped[:24]
        ts = parse_timestamp(time_part)
        return ConnectionEvent(
            timestamp=ts,
            src_ip=src_match.group(1),
            dest_ip=dst_match.group(1),
            dest_port=int(dpt_match.group(1)),
            protocol=proto,
            raw_event=stripped,
        )

    # 3. Try parsing CSV line: timestamp,src_ip,dest_ip,dest_port,proto
    parts = [p.strip() for p in stripped.split(",")]
    if len(parts) >= 4:
        try:
            ts = parse_timestamp(parts[0])
            src = parts[1]
            dst = parts[2]
            port = int(parts[3])
            proto = parts[4].upper() if len(parts) >= 5 else "TCP"
            return ConnectionEvent(
                timestamp=ts,
                src_ip=src,
                dest_ip=dst,
                dest_port=port,
                protocol=proto,
                raw_event=stripped,
            )
        except (ValueError, IndexError):
            pass

    return None


def time_now_epoch() -> float:
    """Return current UTC epoch seconds."""
    return datetime.now(timezone.utc).timestamp()


def parse_pcap_file(filepath: str) -> Iterator[ConnectionEvent]:
    """Extract TCP connection attempts from a PCAP file using Scapy.

    Args:
        filepath: Path to .pcap or .pcapng file.

    Yields:
        ConnectionEvent objects for TCP packets.

    Raises:
        ImportError: If scapy is not installed.
    """
    try:
        from scapy.all import IP, TCP, PcapReader
    except ImportError as exc:
        raise ImportError(
            "Scapy is required to parse PCAP files. Install via 'pip install scapy'."
        ) from exc

    with PcapReader(filepath) as reader:
        for pkt in reader:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                ip_layer = pkt.getlayer(IP)
                tcp_layer = pkt.getlayer(TCP)
                # We are primarily interested in SYN packets initiating connection attempts
                yield ConnectionEvent(
                    timestamp=float(pkt.time),
                    src_ip=ip_layer.src,
                    dest_ip=ip_layer.dst,
                    dest_port=int(tcp_layer.dport),
                    protocol="TCP",
                    raw_event=f"PCAP TCP {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}",
                )


class PortScanDetector:
    """Sliding time-window port scan detection engine.

    Tracks connection attempts per source IP. Triggers an alert when any single source IP
    touches more than N distinct destination ports within a sliding window of T seconds.
    """

    def __init__(
        self,
        threshold: int = 10,
        window_seconds: float = 60.0,
        cooldown_seconds: float = 30.0,
    ) -> None:
        """Initialize the detector.

        Args:
            threshold: Number of distinct destination ports required to trigger an alert (> N).
            window_seconds: Duration of the sliding time window in seconds (T).
            cooldown_seconds: Cooldown period after an alert before triggering another for the same src_ip.
        """
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds

        # Per source IP sliding window: Deque of (timestamp, dest_port, dest_ip)
        self.history: Dict[str, Deque[Tuple[float, int, str]]] = {}
        # Tracking last alert timestamp per source IP to prevent alert storming
        self.last_alert_time: Dict[str, float] = {}

    def process_event(self, event: ConnectionEvent) -> Optional[ScanAlert]:
        """Ingest a connection event, update sliding window, and evaluate alert criteria.

        Args:
            event: ConnectionEvent to evaluate.

        Returns:
            ScanAlert if threshold is exceeded and cooldown has passed, otherwise None.
        """
        src = event.src_ip
        if src not in self.history:
            self.history[src] = deque()

        window = self.history[src]
        window.append((event.timestamp, event.dest_port, event.dest_ip))

        # Evict all entries outside the sliding window (t < current_t - window_seconds)
        cutoff = event.timestamp - self.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()

        # Count distinct destination ports touched within this active window
        distinct_ports: Set[int] = {entry[1] for entry in window}

        if len(distinct_ports) > self.threshold:
            # Check cooldown suppression
            last_alert = self.last_alert_time.get(src, 0.0)
            if (event.timestamp - last_alert) >= self.cooldown_seconds:
                self.last_alert_time[src] = event.timestamp

                sorted_ports = sorted(distinct_ports)
                target_ip = event.dest_ip

                dt_event = datetime.fromtimestamp(event.timestamp, tz=timezone.utc)
                dt_now = datetime.now(timezone.utc)

                alert = ScanAlert(
                    alert_id=str(uuid.uuid4()),
                    alert_timestamp=dt_now.isoformat(),
                    event_timestamp=dt_event.isoformat(),
                    source_ip=src,
                    target_ip=target_ip,
                    distinct_ports_count=len(sorted_ports),
                    ports_hit=sorted_ports,
                    window_seconds=self.window_seconds,
                    threshold=self.threshold,
                    mitre_attack={
                        "tactic": "Discovery (TA0007)",
                        "technique_id": "T1046",
                        "technique_name": "Network Service Discovery",
                        "reference": "https://attack.mitre.org/techniques/T1046/",
                        "severity": "HIGH" if len(sorted_ports) > 25 else "MEDIUM",
                        "description": (
                            f"Source IP {src} probed {len(sorted_ports)} distinct ports on {target_ip} "
                            f"within {self.window_seconds}s (Threshold > {self.threshold})."
                        ),
                    },
                )
                return alert

        return None

    def analyze_stream(
        self,
        events: Iterator[ConnectionEvent],
    ) -> List[ScanAlert]:
        """Analyze an iterable stream of connection events and return all generated alerts.

        Args:
            events: Iterator of ConnectionEvent objects.

        Returns:
            List of generated ScanAlert objects.
        """
        alerts: List[ScanAlert] = []
        for event in events:
            alert = self.process_event(event)
            if alert:
                alerts.append(alert)
        return alerts


def load_events_from_file(filepath: str) -> Iterator[ConnectionEvent]:
    """Load normalized connection events from a log file or PCAP."""
    ext = os.path.splitext(filepath)[1].lower()

    if ext in (".pcap", ".pcapng"):
        yield from parse_pcap_file(filepath)
    else:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                event = parse_log_line(line)
                if event:
                    yield event


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line arguments for the scan detector."""
    parser = argparse.ArgumentParser(
        prog="detect_scan",
        description="Defensive Port Scan Detection Engine (MITRE ATT&CK T1046).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m detection.detect_scan samples/network_traffic.log\n"
            "  python -m detection.detect_scan firewall.log --threshold 15 --window 30\n"
            "  python -m detection.detect_scan capture.pcap --output alerts.json\n"
        ),
    )

    parser.add_argument(
        "logfile",
        type=str,
        help="Path to network log file (JSON lines, CSV, Syslog) or PCAP file.",
    )

    parser.add_argument(
        "-n",
        "--threshold",
        type=int,
        default=10,
        help="Alert threshold: maximum distinct ports touched before triggering an alert (default: 10).",
    )

    parser.add_argument(
        "-w",
        "--window",
        type=float,
        default=60.0,
        help="Sliding time-window in seconds (default: 60.0s).",
    )

    parser.add_argument(
        "-c",
        "--cooldown",
        type=float,
        default=30.0,
        help="Cooldown period in seconds between successive alerts for the same source IP (default: 30.0s).",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Filepath to write generated JSON alerts.",
    )

    parser.add_argument(
        "--geoip",
        action="store_true",
        help="Enrich alerts with GeoIP data (country, city, ISP) via ip-api.com (requires internet).",
    )

    parser.add_argument(
        "--watch",
        action="store_true",
        help="Watch mode: continuously tail the log file for new events in real time (like tail -f).",
    )

    parser.add_argument(
        "--watch-interval",
        type=float,
        default=0.5,
        help="Polling interval in seconds for --watch mode (default: 0.5s).",
    )

    return parser


def _print_alert(alert: ScanAlert, idx: int) -> None:
    """Print a single alert to stdout in a standardized format."""
    print(f"\n--- [INCIDENT #{idx}] ----------------------------------------------")
    print(f"  Alert ID        : {alert.alert_id}")
    print(f"  Event Timestamp : {alert.event_timestamp}")
    print(f"  Attacker IP     : {alert.source_ip}")
    if alert.geoip and not alert.geoip.get("is_private"):
        geo = alert.geoip
        print(f"  GeoIP Location  : {geo.get('city')}, {geo.get('region')}, {geo.get('country')} ({geo.get('country_code')})")
        print(f"  ISP / ASN       : {geo.get('org') or geo.get('isp')} | {geo.get('asn')}")
        print(f"  Coordinates     : lat={geo.get('lat')}, lon={geo.get('lon')}")
    elif alert.geoip:
        print(f"  GeoIP Location  : Private / Local Network")
    print(f"  Target IP       : {alert.target_ip}")
    print(f"  Distinct Ports  : {alert.distinct_ports_count}")
    print(f"  Probed Ports    : {alert.ports_hit}")
    print(f"  MITRE ATT&CK    : {alert.mitre_attack['technique_id']} - {alert.mitre_attack['technique_name']}")
    print(f"  Severity        : {alert.mitre_attack['severity']}")
    print(f"  Summary         : {alert.mitre_attack['description']}")
    print("------------------------------------------------------------------")


def main(argv: Optional[List[str]] = None) -> int:
    """Detector CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not os.path.exists(args.logfile):
        print(f"[-] Error: File not found: '{args.logfile}'", file=sys.stderr)
        return 1

    detector = PortScanDetector(
        threshold=args.threshold,
        window_seconds=args.window,
        cooldown_seconds=args.cooldown,
    )

    # Conditionally import GeoIP module
    geoip_lookup = None
    if args.geoip:
        try:
            from detection.geoip import lookup_geoip
            geoip_lookup = lookup_geoip
        except ImportError:
            print("[!] GeoIP module not found. Proceeding without geolocation.", file=sys.stderr)

    print("=" * 65)
    print(" SOC Detection Engine - MITRE ATT&CK T1046 Port Scan Detector")
    print("=" * 65)
    print(f" Log/Capture File : {args.logfile}")
    print(f" Port Threshold   : > {args.threshold} distinct ports")
    print(f" Sliding Window   : {args.window} seconds")
    print(f" Alert Cooldown   : {args.cooldown} seconds")
    print(f" GeoIP Enrichment : {'Enabled (ip-api.com)' if args.geoip else 'Disabled'}")
    print(f" Mode             : {'LIVE WATCH (Ctrl+C to stop)' if args.watch else 'File Analysis'}")
    print("=" * 65 + "\n")

    all_alerts: List[ScanAlert] = []
    alert_counter = [0]

    def _process_alert(alert: ScanAlert) -> None:
        """Enrich with GeoIP and print an alert."""
        if geoip_lookup:
            geo = geoip_lookup(alert.source_ip)
            alert.geoip = geo.to_dict() if geo else None
        alert_counter[0] += 1
        all_alerts.append(alert)
        _print_alert(alert, alert_counter[0])

    if args.watch:
        # ── WATCH MODE: tail the log file for new lines in real time ──
        print(f"[*] Entering watch mode on '{args.logfile}'. Waiting for new events... (Ctrl+C to stop)\n")
        try:
            with open(args.logfile, "r", encoding="utf-8", errors="replace") as f:
                # Seek to end of file so we only process new events
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if line:
                        event = parse_log_line(line)
                        if event:
                            alert = detector.process_event(event)
                            if alert:
                                _process_alert(alert)
                    else:
                        import time as _time
                        _time.sleep(args.watch_interval)
        except KeyboardInterrupt:
            print("\n\n[*] Watch mode stopped by user (Ctrl+C).")

    else:
        # ── BATCH FILE MODE: analyse entire file ──
        events = load_events_from_file(args.logfile)
        for event in events:
            alert = detector.process_event(event)
            if alert:
                _process_alert(alert)

    if not all_alerts:
        print("[*] Analysis complete. No port scanning activity detected exceeding threshold.")
        return 0

    print(f"\n[+] Total incidents detected: {len(all_alerts)}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump([a.to_dict() for a in all_alerts], f, indent=2, default=str)
        print(f"[+] Alerts written to: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
