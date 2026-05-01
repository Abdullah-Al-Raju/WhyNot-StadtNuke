#!/usr/bin/env python3
"""
WhyNot-StadtNuke ULTIMATE - Worldwide City Network Census
Usage: python stadtnuke_ultimate.py --city "Tokyo"
       python stadtnuke_ultimate.py --city "Mumbai" --max-ips 100
"""

import requests
import json
import time
import argparse
import sys
from ipaddress import ip_network

# ---------------- CONFIG ----------------
MAX_IPS_PER_RANGE = 50
REQUEST_DELAY = 0.1

# ---------------- Fallback coordinates ----------------
CITY_COORDS = {
    "munich": [48.1351, 11.5820],
    "berlin": [52.5200, 13.4050],
    "mumbai": [19.0760, 72.8777],
    "tokyo": [35.6895, 139.6917],
    "london": [51.5074, -0.1278],
    "new york": [40.7128, -74.0060],
    "paris": [48.8566, 2.3522],
    "dubai": [25.2048, 55.2708],
    "singapore": [1.3521, 103.8198],
    "sydney": [-33.8688, 151.2093]
}

# ---------------- FUNCTION: Get city coordinates ----------------
def get_city_coords(city_name):
    """Get lat/lon for a city using free Nominatim API (OpenStreetMap)"""
    try:
        url = f"https://nominatim.openstreetmap.org/search?q={city_name}&format=json&limit=1"
        resp = requests.get(url, headers={'User-Agent': 'WhyNot-StadtNuke/1.0'}, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data:
                return float(data[0]['lat']), float(data[0]['lon'])
    except:
        pass
    # Fallback to hardcoded
    result = CITY_COORDS.get(city_name.lower(), [48.1351, 11.5820])
    if isinstance(result, list):
        return result[0], result[1]
    return 48.1351, 11.5820

# ---------------- FUNCTION: Get IP ranges for a city ----------------
def get_ip_ranges_for_city(city_name):
    """
    Query RIPE Stat API for IP ranges belonging to organizations in this city.
    """
    print(f"[*] Looking up IP ranges for {city_name}...")
    ranges = []
    
    try:
        url = f"https://stat.ripe.net/data/geoloc/data.json?resource={city_name}&types=ipv4"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if 'data' in data and 'located_resources' in data['data']:
                for item in data['data']['located_resources']:
                    if 'prefix' in item:
                        ranges.append(item['prefix'])
                        print(f"    Found range: {item['prefix']}")
    except Exception as e:
        print(f"    [!] RIPE API error: {e}")
    
    # If RIPE gives nothing, use some common test ranges
    if not ranges:
        print(f"    [!] No ranges found via RIPE. Using fallback test ranges.")
        ranges = ["8.8.8.0/24", "1.1.1.0/24"]
    
    return ranges[:5]

# ---------------- FUNCTION: Query InternetDB ----------------
def query_internetdb(ip):
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return None

# ---------------- FUNCTION: Scan a single IP range ----------------
def scan_range(cidr, max_ips=MAX_IPS_PER_RANGE):
    print(f"[*] Scanning {cidr} (max {max_ips} IPs)...")
    net = ip_network(cidr, strict=False)
    found = []
    count = 0
    for ip in net.hosts():
        if count >= max_ips:
            break
        data = query_internetdb(str(ip))
        if data and data.get('ports'):
            found.append({
                'ip': str(ip),
                'ports': data['ports'],
                'hostnames': data.get('hostnames', []),
                'vulns': data.get('vulns', [])
            })
        count += 1
        time.sleep(REQUEST_DELAY)
    return found

# ---------------- FUNCTION: Sarcastic Report ----------------
def sarcastic_report(devices, city):
    total = len(devices)
    if total == 0:
        print("\n" + "="*50)
        print(f"💀 SARCASM REPORT for {city}: Zero devices found.")
        print("   Either the city is a digital ghost town, or the IP ranges are wrong.")
        print("="*50)
        return
    vuln_count = sum(1 for d in devices if d['vulns'])
    print("\n" + "="*50)
    print(f"📢 WhyNot-StadtNuke REPORT for {city}")
    print(f"   Devices found: {total}")
    print(f"   Vulnerable devices: {vuln_count}")
    if vuln_count > total/2:
        print("   ⚠️  More than half are vulnerable. Yikes.")
    elif vuln_count > 0:
        print("   🔓 Somebody forgot to patch. Happens to the best of us.")
    else:
        print("   ✅ No known vulns? Either very secure or very boring.")
    print("="*50)

# ---------------- MAIN ----------------
def main():
    parser = argparse.ArgumentParser(description='WhyNot-StadtNuke - Ultimate Worldwide City Scanner')
    parser.add_argument('--city', required=True, help='City name (e.g., "Tokyo", "Mumbai", "Berlin")')
    parser.add_argument('--max-ips', type=int, default=50, help='Max IPs to scan per range (default: 50)')
    args = parser.parse_args()
    
    city = args.city
    max_ips = args.max_ips
    
    print(f"\n💥 WhyNot-StadtNuke ULTIMATE – nuking {city}...")
    
    # Get coordinates (for future map)
    lat, lon = get_city_coords(city)
    print(f"[*] City center: {lat}, {lon}")
    
    # Get IP ranges for this city
    ranges = get_ip_ranges_for_city(city)
    
    if not ranges:
        print("[!] No IP ranges found. Cannot scan.")
        sys.exit(1)
    
    # Scan each range
    all_devices = []
    for cidr in ranges:
        devices = scan_range(cidr, max_ips)
        all_devices.extend(devices)
        print(f"   → Found {len(devices)} devices in {cidr}")
    
    # Save results
    output_file = f"{city.replace(' ', '_')}_stadtnuke_ultimate.json"
    with open(output_file, "w") as f:
        json.dump(all_devices, f, indent=2)
    
    print(f"\n✅ Scan complete. Saved {len(all_devices)} devices to {output_file}")
    
    # Sarcastic report
    sarcastic_report(all_devices, city)

if __name__ == "__main__":
    main()
