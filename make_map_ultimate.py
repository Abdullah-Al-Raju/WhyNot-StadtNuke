#!/usr/bin/env python3
import json
import folium
import requests
import time
import random
import argparse

def get_city_coords(city_name):
    """Get lat/lon for a city using Nominatim API"""
    try:
        url = f"https://nominatim.openstreetmap.org/search?q={city_name}&format=json&limit=1"
        resp = requests.get(url, headers={'User-Agent': 'WhyNot-StadtNuke/1.0'}, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data:
                return float(data[0]['lat']), float(data[0]['lon'])
    except:
        pass
    return 48.1351, 11.5820

def main():
    parser = argparse.ArgumentParser(description='Generate map from WhyNot-StadtNuke Ultimate scan')
    parser.add_argument('--json', required=True, help='JSON file from stadtnuke_ultimate.py')
    parser.add_argument('--city', required=True, help='City name')
    args = parser.parse_args()
    
    try:
        with open(args.json, "r") as f:
            devices = json.load(f)
    except FileNotFoundError:
        print(f"Error: {args.json} not found. Run stadtnuke_ultimate.py first.")
        return
    
    if not devices:
        print("No devices found.")
        return
    
    center = get_city_coords(args.city)
    print(f"[*] Mapping {len(devices)} devices for {args.city}...")
    
    m = folium.Map(location=center, zoom_start=12, tiles='CartoDB positron')
    
    def get_coords(ip):
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=lat,lon,status", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    return data.get('lat'), data.get('lon')
        except:
            pass
        return None, None
    
    count = 0
    for dev in devices:
        lat, lon = get_coords(dev['ip'])
        if not lat or not lon:
            offset_lat = random.uniform(-0.03, 0.03)
            offset_lon = random.uniform(-0.03, 0.03)
            lat, lon = center[0] + offset_lat, center[1] + offset_lon
            color = 'purple'
        else:
            color = 'red' if dev.get('vulns') and len(dev['vulns']) > 0 else 'green'
        
        popup = folium.Popup(f"<b>IP:</b> {dev['ip']}<br><b>Ports:</b> {dev['ports'][:4]}", max_width=300)
        folium.Marker([lat, lon], popup=popup, icon=folium.Icon(color=color)).add_to(m)
        count += 1
        time.sleep(0.3)
        if count >= 50:
            break
    
    map_file = f"{args.city.replace(' ', '_')}_stadtnuke_ultimate_map.html"
    m.save(map_file)
    print(f"\n🗺️ Map saved: {map_file}")
    print(f"   Open with: firefox {map_file}")

if __name__ == "__main__":
    main()
