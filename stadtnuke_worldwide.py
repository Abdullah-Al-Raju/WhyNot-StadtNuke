#!/usr/bin/env python3
"""WhyNot-StadtNuke Worldwide (Legacy Compatibility Wrapper).

Routes directly to the robust core engine.
"""

import argparse
import json
import sys
import stadtnuke_core as core


def main():
    parser = argparse.ArgumentParser(description="WhyNot-StadtNuke Worldwide Country/ASN Scanner")
    parser.add_argument("--country", help='Country name (e.g., "Bangladesh", "Japan", "Germany")')
    parser.add_argument("--asn", help='ASN number (e.g., "AS45609")')
    parser.add_argument("--max-ips", type=int, default=30)
    args = parser.parse_args()

    if not args.country and not args.asn:
        print("Error: Specify --country OR --asn")
        sys.exit(1)

    resolver = core.TargetResolver()
    if args.country:
        target = resolver.resolve(country=args.country)
        label = f"Country_{target.name.replace(' ', '_')}"
    else:
        target = resolver.resolve(asn=args.asn)
        label = f"ASN_{target.name.replace(' ', '_')}"

    print(f"\n[*] WhyNot-StadtNuke WORLDWIDE - Surveying {target.name}...")
    print(f"[*] Prefixes: {', '.join(target.prefixes[:5])}")

    engine = core.CensusEngine()
    devices = engine.scan_target(target, max_ips_per_prefix=args.max_ips)

    dict_devices = [d.to_dict() for d in devices]
    out_file = f"{label}_worldwide.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(dict_devices, f, indent=2)

    print(f"\n[+] Saved {len(devices)} devices to {out_file}")

    vuln_c = sum(1 for d in dict_devices if d.get("vulns"))
    crit_c = sum(1 for d in dict_devices if d.get("risk_level") == "Critical")
    roast = engine.scorer.generate_overall_roast(len(dict_devices), vuln_c, crit_c)

    print("\n" + "=" * 50)
    print(f"WhyNot-StadtNuke REPORT for {target.name}")
    print(f"   Devices found: {len(devices)}")
    print(f"   Vulnerable devices: {vuln_c}")
    print(f"   Roast: \"{roast}\"")
    print("=" * 50)


if __name__ == "__main__":
    main()
