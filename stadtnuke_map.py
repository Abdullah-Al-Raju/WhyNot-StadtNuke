"""WhyNot-StadtNuke Map Generation Engine.

Produces interactive Folium/Leaflet attack-surface maps with marker clustering,
color-coded risk levels, CVE links, micro-jittering, and tactical HUD summaries.
Authored by: Abduallah Al Raju
"""

import html
import json
import os
import random
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import folium
from folium.plugins import MarkerCluster

RISK_COLORS = {
    "Critical": "darkred",
    "High": "red",
    "Medium": "orange",
    "Low": "green",
}


def _create_popup_html(dev: Dict[str, Any]) -> str:
    ip = html.escape(str(dev.get("ip", "0.0.0.0")))
    ports = dev.get("ports", [])
    ports_str = ", ".join(str(p) for p in ports[:8])
    if len(ports) > 8:
        ports_str += f" (+{len(ports) - 8} more)"
    if not ports_str:
        ports_str = "None"

    vulns = dev.get("vulns", [])
    hostnames = dev.get("hostnames", [])
    host_str = html.escape(hostnames[0]) if hostnames else "unresolved"
    city = html.escape(dev.get("city", "Unknown"))
    country = html.escape(dev.get("country", "Unknown"))
    isp = html.escape(dev.get("isp", "Transit Provider"))
    risk_score = dev.get("risk_score", 0)
    risk_level = dev.get("risk_level", "Low")
    roast = html.escape(dev.get("roast", "Standard endpoint."))

    # Risk badge color
    badge_bg = "#22c55e"
    if risk_level == "Critical":
        badge_bg = "#ef4444"
    elif risk_level == "High":
        badge_bg = "#f97316"
    elif risk_level == "Medium":
        badge_bg = "#eab308"

    # CVE links
    cve_html = ""
    if vulns:
        cve_items = []
        for cve in vulns[:5]:
            cve_clean = html.escape(cve)
            cve_items.append(
                f'<a href="https://nvd.nist.gov/vuln/detail/{cve_clean}" target="_blank" style="color: #ef4444; text-decoration: underline; font-weight: 600;">{cve_clean}</a>'
            )
        if len(vulns) > 5:
            cve_items.append(f'<span style="color: #94a3b8;">+{len(vulns) - 5} more</span>')
        cve_html = f'<div style="margin-top: 6px;"><b>Vulnerabilities:</b><br>{" &bull; ".join(cve_items)}</div>'
    else:
        cve_html = '<div style="margin-top: 6px; color: #22c55e;"><b>Vulnerabilities:</b> None cataloged</div>'

    popup_body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 13px; line-height: 1.4; color: #0f172a; min-width: 240px; max-width: 320px;">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; margin-bottom: 8px;">
            <span style="font-weight: 700; font-size: 14px; font-family: monospace;">{ip}</span>
            <span style="background-color: {badge_bg}; color: white; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase;">{risk_level} ({risk_score})</span>
        </div>
        <div><b>Host:</b> {host_str}</div>
        <div><b>Location:</b> {city}, {country}</div>
        <div><b>ISP:</b> {isp}</div>
        <div style="margin-top: 4px;"><b>Open Ports:</b> <span style="font-family: monospace; background: #f1f5f9; padding: 1px 4px; border-radius: 4px;">{ports_str}</span></div>
        {cve_html}
        <div style="margin-top: 8px; padding-top: 6px; border-top: 1px dashed #cbd5e1; font-style: italic; color: #475569; font-size: 12px;">
            &ldquo;{roast}&rdquo;
        </div>
    </div>
    """
    return popup_body


def render_map(
    devices: List[Dict[str, Any]],
    title: str = "WhyNot-StadtNuke Attack Surface Map",
    center_coords: Optional[Tuple[float, float]] = None,
    output_file: str = "stadtnuke_map.html",
    zoom_start: int = 12,
) -> str:
    """Generate interactive Folium map with clustered markers and tactical HUD."""
    if not center_coords:
        if devices and devices[0].get("lat") and devices[0].get("lon"):
            center_coords = (float(devices[0]["lat"]), float(devices[0]["lon"]))
        else:
            center_coords = (48.1351, 11.5820)

    # Base Folium Map using OpenStreetMap to avoid API key deprecations
    m = folium.Map(
        location=center_coords,
        zoom_start=zoom_start,
        tiles="OpenStreetMap",
        control_scale=True,
    )

    # Use MarkerCluster plugin for smooth rendering of hundreds/thousands of devices
    cluster = MarkerCluster(name="Endpoints Cluster").add_to(m)

    # Track coordinate overlaps for micro-jittering (under 200m)
    coord_counts = defaultdict(int)

    for dev in devices:
        lat = dev.get("lat")
        lon = dev.get("lon")
        if lat is None or lon is None:
            lat, lon = center_coords

        key = (round(lat, 4), round(lon, 4))
        coord_counts[key] += 1
        count = coord_counts[key]

        if count > 1:
            # Deterministic micro-jitter: max +/- 0.0015 deg (~150m)
            rng = random.Random(f"{dev.get('ip')}-{count}")
            lat += rng.uniform(-0.0015, 0.0015)
            lon += rng.uniform(-0.0015, 0.0015)

        risk_level = dev.get("risk_level", "Low")
        color = RISK_COLORS.get(risk_level, "green")
        popup_html = _create_popup_html(dev)

        icon = folium.Icon(color=color, icon="crosshairs", prefix="fa") if "fa" in dir(folium) else folium.Icon(color=color)

        folium.Marker(
            location=[lat, lon],
            popup=folium.Popup(popup_html, max_width=340),
            tooltip=f"{dev.get('ip')} - {risk_level} ({len(dev.get('ports', []))} ports)",
            icon=icon,
        ).add_to(cluster)

    # Floating Tactical HUD Legend
    total_devs = len(devices)
    critical_count = sum(1 for d in devices if d.get("risk_level") == "Critical")
    high_count = sum(1 for d in devices if d.get("risk_level") == "High")
    med_count = sum(1 for d in devices if d.get("risk_level") == "Medium")
    low_count = sum(1 for d in devices if d.get("risk_level") == "Low")
    vuln_count = sum(1 for d in devices if d.get("vulns"))

    hud_html = f"""
    <div style="position: fixed; bottom: 24px; left: 24px; z-index: 1000; background: rgba(15, 23, 42, 0.92); backdrop-filter: blur(8px); color: #f8fafc; padding: 16px; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.15); box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 13px; max-width: 320px;">
        <div style="font-weight: 800; font-size: 15px; letter-spacing: 0.05em; color: #38bdf8; margin-bottom: 8px; border-bottom: 1px solid rgba(255, 255, 255, 0.1); padding-bottom: 4px;">
            {html.escape(title)}
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 10px;">
            <div>Total Devices: <b>{total_devs}</b></div>
            <div>Vulnerable: <b style="color: #ef4444;">{vuln_count}</b></div>
        </div>
        <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; margin-bottom: 6px;">Severity Breakdown</div>
        <div style="display: flex; gap: 6px; font-weight: 700; font-size: 11px;">
            <span style="background: #ef4444; color: white; padding: 2px 6px; border-radius: 4px;">CRIT: {critical_count}</span>
            <span style="background: #f97316; color: white; padding: 2px 6px; border-radius: 4px;">HIGH: {high_count}</span>
            <span style="background: #eab308; color: black; padding: 2px 6px; border-radius: 4px;">MED: {med_count}</span>
            <span style="background: #22c55e; color: white; padding: 2px 6px; border-radius: 4px;">LOW: {low_count}</span>
        </div>
        <div style="margin-top: 10px; font-size: 11px; color: #64748b; border-top: 1px dashed rgba(255, 255, 255, 0.1); padding-top: 6px;">
            Engine by Abduallah Al Raju &bull; WhyNot-StadtNuke v2.0
        </div>
    </div>
    """
    m.get_root().html.add_child(folium.Element(hud_html))

    m.save(output_file)
    return output_file


def merge_json_scans(file_paths: List[str]) -> List[Dict[str, Any]]:
    """Load and merge multiple StadtNuke JSON files with deduplication."""
    seen_ips = set()
    merged: List[Dict[str, Any]] = []

    for path in file_paths:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        ip = item.get("ip")
                        if ip and ip not in seen_ips:
                            seen_ips.add(ip)
                            merged.append(item)
        except Exception:
            pass

    return merged
