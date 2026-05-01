#!/usr/bin/env python3
import json
import folium
import requests
import time
import random
from collections import defaultdict

CITY_NAME = "Munich"

CITY_CENTERS = {
    "Munich": [48.1351, 11.5820],
    "Berlin": [52.5200, 13.4050],
    "Mumbai": [19.0760, 72.8777]
}
center = CITY_CENTERS.get(CITY_NAME, [48.1351, 11.5820])

def get_coords(ip):
    """Get real GPS coordinates for an IP. Returns (lat, lon) or (None, None)."""
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=lat,lon,status", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                return data.get('lat'), data.get('lon')
    except Exception as e:
        print(f"  [!] Error: {e}")
    return None, None

def main():
    json_file = f"{CITY_NAME}_stadtnuke.json"
    try:
        with open(json_file, "r") as f:
            devices = json.load(f)
    except FileNotFoundError:
        print(f"Error: {json_file} not found. Run 'python stadtnuke.py' first.")
        return
    
    if not devices:
        print("No devices found.")
        return
    
    print(f"[*] Loading {len(devices)} devices from {json_file}")
    m = folium.Map(location=center, zoom_start=14, tiles='CartoDB positron')
    
    # Track used coordinates to detect stacks
    coord_counter = defaultdict(int)
    coords_list = []
    
    # First pass: get all coordinates
    for dev in devices:
        lat, lon = get_coords(dev['ip'])
        if lat and lon:
            coords_list.append((lat, lon, dev))
        else:
            # Fallback to city center with random offset
            lat = center[0] + random.uniform(-0.01, 0.01)
            lon = center[1] + random.uniform(-0.01, 0.01)
            coords_list.append((lat, lon, dev))
    
    # Count duplicates
    for lat, lon, _ in coords_list:
        coord_counter[(round(lat, 4), round(lon, 4))] += 1
    
    # Second pass: add markers with jitter for duplicates
    for lat, lon, dev in coords_list:
        key = (round(lat, 4), round(lon, 4))
        total_at_location = coord_counter[key]
        
        if total_at_location > 1:
            # Add small random jitter to spread stacked markers
            jitter_lat = random.uniform(-0.0008, 0.0008)
            jitter_lon = random.uniform(-0.0008, 0.0008)
            final_lat = lat + jitter_lat
            final_lon = lon + jitter_lon
            color = 'red' if dev.get('vulns') and len(dev['vulns']) > 0 else 'green'
            popup_text = f"<b>IP:</b> {dev['ip']}<br><b>Ports:</b> {dev['ports'][:5]}<br><b>📍 Stacked device</b>"
        else:
            final_lat, final_lon = lat, lon
            color = 'red' if dev.get('vulns') and len(dev['vulns']) > 0 else 'green'
            popup_text = f"<b>IP:</b> {dev['ip']}<br><b>Ports:</b> {dev['ports'][:5]}<br><b>📍 Real location</b>"
        
        popup = folium.Popup(popup_text, max_width=300)
        folium.Marker([final_lat, final_lon], popup=popup, icon=folium.Icon(color=color)).add_to(m)
    
    map_file = f"{CITY_NAME}_stadtnuke_map.html"
    m.save(map_file)
    
    print("\n" + "="*50)
    print(f"✅ Map saved: {map_file}")
    print(f"   Total devices plotted: {len(devices)}")
    print(f"   Devices with same coordinates were spread with jitter")
    print(f"   Zoom in to see individual markers")
    print(f"   Open with: firefox {map_file}")
    print("="*50)

if __name__ == "__main__":
    main()
