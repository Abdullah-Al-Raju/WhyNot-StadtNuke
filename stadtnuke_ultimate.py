#!/usr/bin/env python3
"""WhyNot-StadtNuke Ultimate (Legacy Compatibility Wrapper).

Routes directly to the robust core engine.
"""

import argparse
import json
import stadtnuke_core as core
import stadtnuke_map as smap


def main():
    parser = argparse.ArgumentParser(description="WhyNot-StadtNuke Ultimate City Scanner")
    parser.add_argument("--city", required=True, help='City name (e.g., "Munich", "Berlin", "Tokyo")')
    parser.add_argument("--max-ips", type=int, default=50, help="Max IPs to sample per range")
    args = parser.parse_args()

    city = args.city
    resolver = core.TargetResolver()
    target = resolver.resolve(city=city)

    print(f"\n[*] WhyNot-StadtNuke ULTIMATE - Surveying {city}...")
    print(f"[*] City Coordinates: {target.coords[0]:.4f}, {target.coords[1]:.4f}")
    print(f"[*] Allocated Prefixes: {', '.join(target.prefixes[:5])}")

    engine = core.CensusEngine()
    devices = engine.scan_target(target, max_ips_per_prefix=args.max_ips)

    dict_devices = [d.to_dict() for d in devices]
    out_file = f"{city.replace(' ', '_')}_stadtnuke_ultimate.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(dict_devices, f, indent=2)

    print(f"\n[+] Scan complete. Saved {len(devices)} devices to {out_file}")

    vuln_c = sum(1 for d in dict_devices if d.get("vulns"))
    crit_c = sum(1 for d in dict_devices if d.get("risk_level") == "Critical")
    roast = engine.scorer.generate_overall_roast(len(dict_devices), vuln_c, crit_c)

    print("\n" + "=" * 50)
    print(f"WhyNot-StadtNuke REPORT for {city}")
    print(f"   Devices found: {len(devices)}")
    print(f"   Vulnerable devices: {vuln_c}")
    print(f"   Roast: \"{roast}\"")
    print("=" * 50)


if __name__ == "__main__":
    main()
