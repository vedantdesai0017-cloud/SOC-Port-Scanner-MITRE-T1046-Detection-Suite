"""Unit tests for the port scan detection engine (MITRE ATT&CK T1046)."""

from datetime import datetime, timezone
import json
import pytest

from detection.detect_scan import (
    ConnectionEvent,
    PortScanDetector,
    parse_log_line,
    parse_timestamp,
)


def test_parse_timestamp_numeric():
    """Verify parsing numeric epoch timestamps."""
    assert parse_timestamp(1700000000) == 1700000000.0
    assert parse_timestamp("1700000000.5") == 1700000000.5


def test_parse_timestamp_iso8601():
    """Verify parsing ISO-8601 timestamps."""
    ts = parse_timestamp("2026-10-28T12:00:00Z")
    assert ts > 0
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    assert dt.year == 2026
    assert dt.month == 10
    assert dt.day == 28


def test_parse_log_line_json():
    """Verify parsing JSON log format."""
    line = json.dumps({
        "timestamp": "2026-10-28T12:00:00Z",
        "src_ip": "192.168.1.50",
        "dest_ip": "192.168.1.10",
        "dest_port": 80,
        "proto": "tcp",
    })
    event = parse_log_line(line)
    assert event is not None
    assert event.src_ip == "192.168.1.50"
    assert event.dest_ip == "192.168.1.10"
    assert event.dest_port == 80
    assert event.protocol == "TCP"


def test_parse_log_line_firewall_kv():
    """Verify parsing iptables/firewall key-value line."""
    line = "Oct 28 12:00:01 fw kernel: [100.1] IN=eth0 SRC=10.0.0.99 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=443"
    event = parse_log_line(line)
    assert event is not None
    assert event.src_ip == "10.0.0.99"
    assert event.dest_ip == "10.0.0.1"
    assert event.dest_port == 443
    assert event.protocol == "TCP"


def test_parse_log_line_csv():
    """Verify parsing CSV formatted log line."""
    line = "2026-10-28T12:00:00Z, 172.16.1.5, 172.16.1.1, 22, TCP"
    event = parse_log_line(line)
    assert event is not None
    assert event.src_ip == "172.16.1.5"
    assert event.dest_ip == "172.16.1.1"
    assert event.dest_port == 22


def test_parse_log_line_invalid():
    """Verify comments and empty lines return None."""
    assert parse_log_line("") is None
    assert parse_log_line("   ") is None
    assert parse_log_line("# This is a comment") is None


def test_detector_no_alert_for_repeated_same_port():
    """Ensure normal traffic hitting the same port repeatedly does not trigger alert."""
    detector = PortScanDetector(threshold=5, window_seconds=60)
    base_t = 1000.0

    # Send 20 requests all to port 80 (e.g. web browsing)
    for i in range(20):
        ev = ConnectionEvent(
            timestamp=base_t + i,
            src_ip="192.168.1.100",
            dest_ip="192.168.1.10",
            dest_port=80,
        )
        alert = detector.process_event(ev)
        assert alert is None, "Repeated connections to same port must not trigger port scan alert."


def test_detector_threshold_trigger():
    """Ensure touching more than N distinct ports within window triggers an alert."""
    detector = PortScanDetector(threshold=5, window_seconds=60, cooldown_seconds=0)
    base_t = 1000.0
    src = "192.168.1.200"
    target = "192.168.1.10"

    # Send probes to 5 distinct ports (threshold is 5, so <= 5 does NOT trigger)
    for p in [21, 22, 23, 25, 53]:
        ev = ConnectionEvent(timestamp=base_t, src_ip=src, dest_ip=target, dest_port=p)
        assert detector.process_event(ev) is None

    # Probe 6th distinct port (> threshold)
    ev6 = ConnectionEvent(timestamp=base_t + 5, src_ip=src, dest_ip=target, dest_port=80)
    alert = detector.process_event(ev6)

    assert alert is not None
    assert alert.source_ip == src
    assert alert.target_ip == target
    assert alert.distinct_ports_count == 6
    assert alert.ports_hit == [21, 22, 23, 25, 53, 80]
    assert alert.mitre_attack["technique_id"] == "T1046"
    assert alert.mitre_attack["technique_name"] == "Network Service Discovery"


def test_detector_window_eviction():
    """Ensure events outside the time window expire and do not contribute to threshold."""
    detector = PortScanDetector(threshold=3, window_seconds=10)
    base_t = 1000.0
    src = "192.168.1.55"
    target = "192.168.1.1"

    # Event 1: Port 21 at t=1000
    detector.process_event(ConnectionEvent(timestamp=base_t, src_ip=src, dest_ip=target, dest_port=21))
    # Event 2: Port 22 at t=1002
    detector.process_event(ConnectionEvent(timestamp=base_t + 2, src_ip=src, dest_ip=target, dest_port=22))

    # Event 3: Port 80 at t=1020 (window of 10s has passed, ports 21 and 22 are evicted!)
    detector.process_event(ConnectionEvent(timestamp=base_t + 20, src_ip=src, dest_ip=target, dest_port=80))
    # Event 4: Port 443 at t=1022
    alert = detector.process_event(ConnectionEvent(timestamp=base_t + 22, src_ip=src, dest_ip=target, dest_port=443))

    # At t=1022, only ports 80 and 443 are in the active window (count = 2 <= 3), so no alert
    assert alert is None


def test_detector_cooldown_suppression():
    """Ensure consecutive alerts are throttled by the cooldown parameter."""
    detector = PortScanDetector(threshold=2, window_seconds=60, cooldown_seconds=30)
    base_t = 1000.0
    src = "192.168.1.99"
    target = "192.168.1.1"

    detector.process_event(ConnectionEvent(timestamp=base_t, src_ip=src, dest_ip=target, dest_port=1))
    detector.process_event(ConnectionEvent(timestamp=base_t, src_ip=src, dest_ip=target, dest_port=2))
    alert1 = detector.process_event(ConnectionEvent(timestamp=base_t, src_ip=src, dest_ip=target, dest_port=3))
    assert alert1 is not None

    # Probe 4th port 5 seconds later (within 30s cooldown)
    alert2 = detector.process_event(ConnectionEvent(timestamp=base_t + 5, src_ip=src, dest_ip=target, dest_port=4))
    assert alert2 is None, "Alert should be suppressed during cooldown window."

    # Probe 5th port 35 seconds later (cooldown elapsed)
    alert3 = detector.process_event(ConnectionEvent(timestamp=base_t + 35, src_ip=src, dest_ip=target, dest_port=5))
    assert alert3 is not None, "Alert should fire once cooldown has passed."
