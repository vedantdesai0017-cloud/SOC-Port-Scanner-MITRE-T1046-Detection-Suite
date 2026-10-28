"""SOC Analyst Dashboard — Streamlit Application.

Real-time interactive dashboard for the SOC Port Scanner project.
Displays scan alerts, attack geolocation, port frequency analysis,
and MITRE ATT&CK T1046 threat intelligence enrichment.

Run with:
    cd soc-port-scanner
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

import streamlit as st
import pandas as pd
import pydeck as pdk

# Add project root so we can import scanner/detection modules
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from detection.detect_scan import (
    PortScanDetector,
    ScanAlert,
    load_events_from_file,
)

# ─── Page Configuration ───────────────────────────────────────────────────────
st.set_page_config(
    page_title="SOC Port Scanner Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ───────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    .metric-card {
        background: #1e1e2e;
        border-radius: 12px;
        padding: 18px 24px;
        border-left: 4px solid;
        margin-bottom: 10px;
    }
    .card-critical { border-color: #ff4757; }
    .card-high     { border-color: #ff6348; }
    .card-medium   { border-color: #ffa502; }
    .card-info     { border-color: #1e90ff; }
    .alert-box {
        background: #2d1b1b;
        border: 1px solid #ff4757;
        border-radius: 8px;
        padding: 12px;
        margin: 6px 0;
        font-family: monospace;
        font-size: 13px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ─── Sidebar Controls ─────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/9/9e/MITRE_ATT%26CK_logo.png/320px-MITRE_ATT%26CK_logo.png", width=180)
    st.title("🛡️ SOC Dashboard")
    st.caption("Network Service Discovery · T1046")
    st.divider()

    st.subheader("📁 Log Source")
    source_mode = st.radio("Input Method", ["Use Sample File", "Enter File Path"])

    sample_log = str(PROJECT_ROOT / "samples" / "network_traffic.log")
    if source_mode == "Use Sample File":
        log_path = sample_log
        st.info(f"Using: `samples/network_traffic.log`")
    else:
        log_path = st.text_input("Log file path", value=sample_log)

    st.divider()
    st.subheader("⚙️ Detection Settings")
    threshold = st.slider("Port Threshold (N)", min_value=2, max_value=50, value=10,
                          help="Alert when a source IP touches more than N distinct ports")
    window_sec = st.slider("Time Window (seconds)", min_value=10, max_value=300, value=60,
                           help="Sliding time window for port counting")
    cooldown_sec = st.slider("Alert Cooldown (seconds)", min_value=0, max_value=120, value=30,
                             help="Minimum time between alerts for the same source IP")

    st.divider()
    st.subheader("🌍 Enrichment")
    enable_geoip = st.toggle("GeoIP Enrichment", value=True,
                             help="Enrich attacker IPs with country/city/ISP via ip-api.com")

    st.divider()
    run_btn = st.button("▶  Run Detection", type="primary", use_container_width=True)

    st.divider()
    st.caption("MITRE ATT&CK T1046 · Network Service Discovery")
    st.caption("[View Technique →](https://attack.mitre.org/techniques/T1046/)")


# ─── Main Header ──────────────────────────────────────────────────────────────
st.title("🛡️ SOC Port Scanner — Detection Dashboard")
st.markdown(
    "**MITRE ATT&CK T1046 · Network Service Discovery** — Sliding time-window anomaly detection "
    "with GeoIP enrichment, attack telemetry, and Blue Team intelligence."
)

# ─── Session State ────────────────────────────────────────────────────────────
if "alerts" not in st.session_state:
    st.session_state.alerts: List[ScanAlert] = []
if "events_count" not in st.session_state:
    st.session_state.events_count = 0
if "last_run" not in st.session_state:
    st.session_state.last_run = None


# ─── Detection Runner ─────────────────────────────────────────────────────────
def run_detection(log_path: str, threshold: int, window: float, cooldown: float, geoip: bool) -> List[ScanAlert]:
    """Run the detector and optionally enrich alerts with GeoIP."""
    if not os.path.exists(log_path):
        st.error(f"Log file not found: `{log_path}`")
        return []

    detector = PortScanDetector(threshold=threshold, window_seconds=window, cooldown_seconds=cooldown)
    events = list(load_events_from_file(log_path))
    st.session_state.events_count = len(events)

    alerts = detector.analyze_stream(iter(events))

    if geoip and alerts:
        try:
            from detection.geoip import lookup_geoip
            for alert in alerts:
                geo = lookup_geoip(alert.source_ip)
                if geo:
                    alert.geoip = geo.to_dict()
        except Exception:
            pass  # GeoIP is optional enrichment, never block alerts

    return alerts


# ─── Trigger Detection ────────────────────────────────────────────────────────
if run_btn:
    with st.spinner("🔍 Analysing network logs..."):
        alerts = run_detection(log_path, threshold, window_sec, cooldown_sec, enable_geoip)
    st.session_state.alerts = alerts
    st.session_state.last_run = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

alerts: List[ScanAlert] = st.session_state.alerts

# ─── Empty State ──────────────────────────────────────────────────────────────
if not alerts and not run_btn:
    st.info("👈 Configure settings in the sidebar and click **Run Detection** to analyse logs.")
    st.stop()


# ─── KPI Metrics Row ──────────────────────────────────────────────────────────
def severity_count(alerts: List[ScanAlert], level: str) -> int:
    return sum(1 for a in alerts if a.mitre_attack.get("severity") == level)

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("📊 Log Events", st.session_state.events_count or "—")
col2.metric("🚨 Total Incidents", len(alerts))
col3.metric("🔴 Critical Alerts", severity_count(alerts, "HIGH"))
col4.metric("🟠 Medium Alerts", severity_count(alerts, "MEDIUM"))
col5.metric("🌐 Unique Attackers", len({a.source_ip for a in alerts}))

if st.session_state.last_run:
    st.caption(f"Last run: {st.session_state.last_run} · Threshold: >{threshold} ports / {window_sec}s window")

st.divider()

# ─── No Alerts Result ─────────────────────────────────────────────────────────
if not alerts:
    st.success("✅ No port scanning activity detected above the configured threshold.")
    st.stop()

# ─── Tabs ─────────────────────────────────────────────────────────────────────
tab_map, tab_alerts, tab_ports, tab_timeline, tab_raw = st.tabs([
    "🌍 Attack Map", "🚨 Incidents", "📊 Port Analysis", "⏱️ Timeline", "📄 Raw JSON"
])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 · WORLD MAP
# ══════════════════════════════════════════════════════════════════════════════
with tab_map:
    st.subheader("🌍 Attacker Geolocation Map")

    geo_data = []
    for alert in alerts:
        geo = alert.geoip
        if geo and geo.get("lat") and geo.get("lon") and not geo.get("is_private"):
            geo_data.append({
                "lat": float(geo["lat"]),
                "lon": float(geo["lon"]),
                "source_ip": alert.source_ip,
                "country": geo.get("country", "Unknown"),
                "city": geo.get("city", "Unknown"),
                "isp": geo.get("isp", geo.get("org", "Unknown")),
                "ports": alert.distinct_ports_count,
                "severity": alert.mitre_attack.get("severity", "MEDIUM"),
            })

    if not geo_data:
        st.warning(
            "No geolocation data available. "
            "Enable **GeoIP Enrichment** in the sidebar, or all detected attackers may be on private IP ranges."
        )
    else:
        df_geo = pd.DataFrame(geo_data)

        # Color by severity: CRITICAL→red, HIGH→orange, MEDIUM→yellow
        def severity_color(s: str) -> list:
            return {
                "HIGH": [255, 71, 87, 220],
                "MEDIUM": [255, 165, 2, 200],
                "LOW": [46, 213, 115, 200],
            }.get(s, [30, 144, 255, 200])

        df_geo["color"] = df_geo["severity"].apply(severity_color)
        df_geo["radius"] = df_geo["ports"] * 8000 + 30000

        scatter_layer = pdk.Layer(
            "ScatterplotLayer",
            data=df_geo,
            get_position="[lon, lat]",
            get_color="color",
            get_radius="radius",
            pickable=True,
            opacity=0.7,
            stroked=True,
            filled=True,
            radius_min_pixels=6,
            radius_max_pixels=60,
        )

        view_state = pdk.ViewState(latitude=20, longitude=0, zoom=1.5, pitch=0)
        tooltip = {
            "html": (
                "<b>Attacker:</b> {source_ip}<br/>"
                "<b>Location:</b> {city}, {country}<br/>"
                "<b>ISP:</b> {isp}<br/>"
                "<b>Distinct Ports:</b> {ports}<br/>"
                "<b>Severity:</b> {severity}"
            ),
            "style": {"background": "#1a1a2e", "color": "white", "padding": "8px", "borderRadius": "6px"},
        }

        st.pydeck_chart(pdk.Deck(
            layers=[scatter_layer],
            initial_view_state=view_state,
            tooltip=tooltip,
            map_style="mapbox://styles/mapbox/dark-v11",
        ))

        st.caption("Bubble size = number of distinct ports probed · Color: 🔴 High / 🟠 Medium")

        st.subheader("🗺️ Attacker Summary")
        display_cols = ["source_ip", "country", "city", "isp", "ports", "severity"]
        existing_cols = [c for c in display_cols if c in df_geo.columns]
        st.dataframe(df_geo[existing_cols], use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 · INCIDENTS
# ══════════════════════════════════════════════════════════════════════════════
with tab_alerts:
    st.subheader(f"🚨 Detected Incidents ({len(alerts)})")

    for idx, alert in enumerate(alerts, start=1):
        severity = alert.mitre_attack.get("severity", "MEDIUM")
        icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟢"}.get(severity, "🔵")
        geo = alert.geoip

        with st.expander(
            f"{icon} Incident #{idx} — {alert.source_ip} → {alert.distinct_ports_count} ports "
            f"| {severity} | {alert.event_timestamp[:19]}",
            expanded=(idx == 1),
        ):
            cols = st.columns([1, 1])
            with cols[0]:
                st.markdown("**🔍 Attack Details**")
                st.write(f"**Alert ID:** `{alert.alert_id}`")
                st.write(f"**Attacker IP:** `{alert.source_ip}`")
                st.write(f"**Target IP:** `{alert.target_ip}`")
                st.write(f"**Event Time:** {alert.event_timestamp}")
                st.write(f"**Distinct Ports:** {alert.distinct_ports_count} (threshold was >{alert.threshold})")
                st.write(f"**Time Window:** {alert.window_seconds}s")

            with cols[1]:
                st.markdown("**🌍 GeoIP Enrichment**")
                if geo and not geo.get("is_private"):
                    st.write(f"**Country:** {geo.get('country')} ({geo.get('country_code')})")
                    st.write(f"**City:** {geo.get('city')}, {geo.get('region')}")
                    st.write(f"**ISP:** {geo.get('isp')}")
                    st.write(f"**ASN:** {geo.get('asn')}")
                elif geo:
                    st.info("Private / Internal Network (RFC 1918)")
                else:
                    st.caption("GeoIP not available (enable in sidebar)")

            st.markdown("**🛡️ MITRE ATT&CK Mapping**")
            mitre = alert.mitre_attack
            att_cols = st.columns(3)
            att_cols[0].metric("Tactic", mitre.get("tactic", "—").split("(")[0].strip())
            att_cols[1].metric("Technique ID", mitre.get("technique_id", "—"))
            att_cols[2].metric("Severity", severity)
            st.link_button("📎 View T1046 on MITRE ATT&CK", mitre.get("reference", "https://attack.mitre.org/techniques/T1046/"))

            st.markdown("**🔌 Ports Probed**")
            ports_str = "  ".join(f"`{p}`" for p in alert.ports_hit)
            st.markdown(ports_str)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 · PORT ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
with tab_ports:
    st.subheader("📊 Port Frequency Analysis")

    from collections import Counter
    import socket as _socket

    all_ports = []
    for alert in alerts:
        all_ports.extend(alert.ports_hit)

    if all_ports:
        port_counts = Counter(all_ports)

        def _svc(p: int) -> str:
            try:
                return _socket.getservbyport(p, "tcp")
            except Exception:
                return "unknown"

        df_ports = pd.DataFrame([
            {"Port": p, "Service": _svc(p), "Hit Count": c}
            for p, c in sorted(port_counts.items(), key=lambda x: -x[1])
        ])

        chart_cols = st.columns([3, 2])

        with chart_cols[0]:
            st.markdown("**Top Probed Ports (Bar Chart)**")
            top_ports = df_ports.head(20)
            st.bar_chart(
                top_ports.set_index("Port")["Hit Count"],
                color="#ff4757",
                use_container_width=True,
                height=350,
            )

        with chart_cols[1]:
            st.markdown("**Port → Service Mapping**")
            st.dataframe(df_ports, use_container_width=True, hide_index=True, height=350)

        # Severity distribution
        st.subheader("Severity Distribution")
        sev_data = {
            "HIGH": severity_count(alerts, "HIGH"),
            "MEDIUM": severity_count(alerts, "MEDIUM"),
            "LOW": severity_count(alerts, "LOW"),
        }
        sev_df = pd.DataFrame(list(sev_data.items()), columns=["Severity", "Count"])
        sev_df = sev_df[sev_df["Count"] > 0]

        if not sev_df.empty:
            st.bar_chart(
                sev_df.set_index("Severity")["Count"],
                color="#ffa502",
                use_container_width=True,
                height=200,
            )


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 · TIMELINE
# ══════════════════════════════════════════════════════════════════════════════
with tab_timeline:
    st.subheader("⏱️ Alert Timeline")

    if alerts:
        timeline_rows = []
        for alert in alerts:
            try:
                ts = datetime.fromisoformat(alert.event_timestamp.replace("Z", "+00:00"))
            except ValueError:
                ts = datetime.now(timezone.utc)

            timeline_rows.append({
                "Timestamp": ts,
                "Source IP": alert.source_ip,
                "Target IP": alert.target_ip,
                "Distinct Ports": alert.distinct_ports_count,
                "Severity": alert.mitre_attack.get("severity", "MEDIUM"),
                "Technique": alert.mitre_attack.get("technique_id", "T1046"),
            })

        df_timeline = pd.DataFrame(timeline_rows).sort_values("Timestamp")
        st.dataframe(df_timeline, use_container_width=True, hide_index=True)

        st.subheader("Ports Probed Over Time")
        st.line_chart(
            df_timeline.set_index("Timestamp")["Distinct Ports"],
            color="#1e90ff",
            use_container_width=True,
            height=250,
        )

        # Top attackers table
        st.subheader("🏴 Top Attackers")
        from collections import defaultdict
        attacker_stats: Dict[str, Any] = defaultdict(lambda: {"incidents": 0, "max_ports": 0, "target_ips": set()})
        for alert in alerts:
            src = alert.source_ip
            attacker_stats[src]["incidents"] += 1
            attacker_stats[src]["max_ports"] = max(attacker_stats[src]["max_ports"], alert.distinct_ports_count)
            attacker_stats[src]["target_ips"].add(alert.target_ip)

        top_data = [
            {
                "Attacker IP": ip,
                "Total Incidents": v["incidents"],
                "Max Distinct Ports": v["max_ports"],
                "Targets": ", ".join(v["target_ips"]),
            }
            for ip, v in sorted(attacker_stats.items(), key=lambda x: -x[1]["incidents"])
        ]
        st.dataframe(pd.DataFrame(top_data), use_container_width=True, hide_index=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 5 · RAW JSON
# ══════════════════════════════════════════════════════════════════════════════
with tab_raw:
    st.subheader("📄 Raw Alert JSON")
    st.caption("Full structured alert output — copy this to integrate with your SIEM or ticketing system.")

    json_output = json.dumps([a.to_dict() for a in alerts], indent=2, default=str)
    st.code(json_output, language="json")

    st.download_button(
        label="⬇️ Download Alerts (JSON)",
        data=json_output,
        file_name=f"soc_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
        type="primary",
    )
