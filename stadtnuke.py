#!/usr/bin/env python3
import requests
import json
import time
from ipaddress import ip_network

CITY_NAME = "Munich"

CITY_RANGES = {
    "Munich": ["129.187.0.0/16", "141.91.0.0/16"],
    "Berlin": ["193.175.0.0/16", "130.149.0.0/16"],
    "Mumbai": ["103.27.8.0/22", "49.44.0.0/15"]
}

def query_internetdb(ip):
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return None

def scan_range(cidr, max_ips=50):
    print(f"[*] Scanning {cidr}...")
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
        time.sleep(0.1)
    return found

def main():
    print(f"\n💥 WhyNot-StadtNuke – nuking {CITY_NAME}...")
    ranges = CITY_RANGES.get(CITY_NAME, ["8.8.8.0/24"])
    all_devices = []
    for cidr in ranges:
        devices = scan_range(cidr)
        all_devices.extend(devices)
        print(f"   Found {len(devices)} devices")
    
    with open(f"{CITY_NAME}_stadtnuke.json", "w") as f:
        json.dump(all_devices, f, indent=2)
    
    print(f"\n✅ Saved {len(all_devices)} devices to {CITY_NAME}_stadtnuke.json")

if __name__ == "__main__":
    main()
