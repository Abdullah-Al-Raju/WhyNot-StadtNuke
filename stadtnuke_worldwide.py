#!/usr/bin/env python3
"""
WhyNot-StadtNuke WORLDWIDE - Scan any country or ISP
Usage: 
  python stadtnuke_worldwide.py --country "Bangladesh"
  python stadtnuke_worldwide.py --country "Japan"
  python stadtnuke_worldwide.py --asn "AS45609"
"""

import requests
import json
import time
import argparse
import sys
from ipaddress import ip_network

# ---------------- CONFIG ----------------
MAX_IPS_PER_RANGE = 30
REQUEST_DELAY = 0.1

# ---------------- FUNCTION: Get IP ranges for a COUNTRY (worldwide) ----------------
def get_ranges_for_country(country_name):
    """
    Use RIPE Stat API to get all IPv4 ranges for a country.
    Works for EVERY country on Earth.
    """
    print(f"[*] Looking up IP ranges for country: {country_name}...")
    ranges = []
    
    # Convert country name to country code (simple mapping for common ones)
    country_codes = {
        "bangladesh": "BD", "india": "IN", "japan": "JP", "germany": "DE",
        "usa": "US", "uk": "GB", "france": "FR", "canada": "CA",
        "australia": "AU", "brazil": "BR", "china": "CN", "russia": "RU"
    }
    country_code = country_codes.get(country_name.lower(), country_name.upper())
    
    try:
        # Query RIPE Stat for all ranges in this country
        url = f"https://stat.ripe.net/data/country-resource-list/data.json?resource={country_code}"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if 'data' in data and 'resources' in data['data']:
                ipv4 = data['data']['resources'].get('ipv4', [])
                for cidr in ipv4[:10]:  # Limit to 10 ranges for speed
                    ranges.append(cidr)
                    print(f"    Found range: {cidr}")
    except Exception as e:
        print(f"    [!] API error: {e}")
    
    if not ranges:
        print(f"    [!] No ranges found. Using fallback.")
        ranges = ["8.8.8.0/24"]
    
    return ranges

# ---------------- FUNCTION: Get IP ranges for an ASN ----------------
def get_ranges_for_asn(asn):
    """
    Get all IP ranges belonging to an ASN (ISP).
    """
    print(f"[*] Looking up IP ranges for ASN: {asn}...")
    ranges = []
    
    # Clean ASN format
    asn_clean = asn.upper().replace('AS', '')
    
    try:
        url = f"https://stat.ripe.net/data/asn-geo/data.json?resource=AS{asn_clean}"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            if 'data' in data and 'prefixes' in data['data']:
                for item in data['data']['prefixes']:
                    if 'prefix' in item:
                        ranges.append(item['prefix'])
                        print(f"    Found range: {item['prefix']}")
    except Exception as e:
        print(f"    [!] API error: {e}")
    
    if not ranges:
        print(f"    [!] No ranges found for {asn}")
        ranges = ["8.8.8.0/24"]
    
    return ranges

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

# ---------------- FUNCTION: Scan a range ----------------
def scan_range(cidr, max_ips=MAX_IPS_PER_RANGE):
    print(f"[*] Scanning {cidr}...")
    try:
        net = ip_network(cidr, strict=False)
    except:
        return []
    
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
                'vulns': data.get('vulns', [])
            })
        count += 1
        time.sleep(REQUEST_DELAY)
    return found

# ---------------- FUNCTION: Sarcastic Report ----------------
def sarcastic_report(devices, target):
    total = len(devices)
    if total == 0:
        print("\n" + "="*50)
        print(f"💀 No devices found for {target}")
        print("="*50)
        return
    vuln_count = sum(1 for d in devices if d['vulns'])
    print("\n" + "="*50)
    print(f"📢 WhyNot-StadtNuke REPORT for {target}")
    print(f"   Devices found: {total}")
    print(f"   Vulnerable devices: {vuln_count}")
    if vuln_count > total/2:
        print("   ⚠️  More than half are vulnerable. Yikes.")
    else:
        print("   ✅ Scan complete. Not terrible.")
    print("="*50)

# ---------------- MAIN ----------------
def main():
    parser = argparse.ArgumentParser(description='WhyNot-StadtNuke - Worldwide Country/ASN Scanner')
    parser.add_argument('--country', help='Country name (e.g., "Bangladesh", "Japan")')
    parser.add_argument('--asn', help='ASN number (e.g., "AS45609")')
    parser.add_argument('--max-ips', type=int, default=30)
    args = parser.parse_args()
    
    if not args.country and not args.asn:
        print("Error: Specify --country OR --asn")
        print("Examples:")
        print("  python stadtnuke_worldwide.py --country Bangladesh")
        print("  python stadtnuke_worldwide.py --country Japan")
        print("  python stadtnuke_worldwide.py --asn AS45609")
        sys.exit(1)
    
    if args.country:
        target = f"Country: {args.country}"
        ranges = get_ranges_for_country(args.country)
    else:
        target = f"ASN: {args.asn}"
        ranges = get_ranges_for_asn(args.asn)
    
    print(f"\n💥 WhyNot-StadtNuke WORLDWIDE – scanning {target}...")
    
    all_devices = []
    for cidr in ranges:
        devices = scan_range(cidr, args.max_ips)
        all_devices.extend(devices)
        print(f"   Found {len(devices)} devices")
        if len(all_devices) >= 100:  # Limit total for performance
            print("   Reached device limit (100). Stopping.")
            break
    
    output_file = f"{target.replace(' ', '_').replace(':', '')}_worldwide.json"
    with open(output_file, "w") as f:
        json.dump(all_devices, f, indent=2)
    
    print(f"\n✅ Saved {len(all_devices)} devices to {output_file}")
    sarcastic_report(all_devices, target)

if __name__ == "__main__":
    main()
