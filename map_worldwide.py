#!/usr/bin/env python3
"""
Worldwide Map Generator for WhyNot-StadtNuke
Usage: python map_worldwide.py --json Bangladesh_worldwide.json --country "Bangladesh"
"""

import json
import folium
import argparse
import random
import requests

def get_country_coords(country_name):
    """Get center coordinates for any country using free Nominatim API"""
    try:
        url = f"https://nominatim.openstreetmap.org/search?q={country_name}&format=json&limit=1"
        resp = requests.get(url, headers={'User-Agent': 'WhyNot-StadtNuke/1.0'}, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data:
                return float(data[0]['lat']), float(data[0]['lon'])
    except:
        pass
    # Fallback coordinates for common countries
    fallback = {
        "bangladesh": [23.685, 90.3563],
        "japan": [36.2048, 138.2529],
        "germany": [51.1657, 10.4515],
        "india": [20.5937, 78.9629],
        "usa": [37.0902, -95.7129],
        "uk": [55.3781, -3.4360]
    }
    return fallback.get(country_name.lower(), [20, 0])

parser = argparse.ArgumentParser(description='Generate worldwide map from scan results')
parser.add_argument('--json', required=True, help='JSON file from stadtnuke_worldwide.py')
parser.add_argument('--country', required=True, help='Country name (e.g., "Bangladesh", "Japan")')
args = parser.parse_args()

# Load devices
with open(args.json, 'r') as f:
    devices = json.load(f)

# Get center of the country
center = get_country_coords(args.country)
print(f"[*] Centering map on {args.country}: {center[0]}, {center[1]}")
print(f"[*] Plotting {min(len(devices), 100)} devices...")

# Create map centered on the country
m = folium.Map(location=center, zoom_start=7, tiles='CartoDB positron')

# Plot devices (spread randomly within the country for privacy)
for idx, dev in enumerate(devices[:100]):
    # Random offset within ~50km range
    lat = center[0] + random.uniform(-0.5, 0.5)
    lon = center[1] + random.uniform(-0.5, 0.5)
    
    color = 'red' if dev.get('vulns') and len(dev['vulns']) > 0 else 'green'
    popup_text = f"<b>IP:</b> {dev['ip']}<br><b>Ports:</b> {dev['ports'][:4]}<br><b>Vulns:</b> {len(dev.get('vulns', []))}"
    
    folium.Marker(
        [lat, lon], 
        popup=folium.Popup(popup_text, max_width=300),
        icon=folium.Icon(color=color)
    ).add_to(m)

# Save map
map_file = f"{args.country.lower()}_worldwide_map.html"
m.save(map_file)
print(f"\n🗺️ Map saved: {map_file}")
print(f"   Open with: firefox {map_file}")
