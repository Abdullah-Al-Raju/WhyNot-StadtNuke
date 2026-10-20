#!/usr/bin/env python3
"""WhyNot-StadtNuke Worldwide Map Generator (Legacy Compatibility Wrapper)."""

import argparse
import json
import os
import stadtnuke_core as core
import stadtnuke_map as smap


def main():
    parser = argparse.ArgumentParser(description="Generate worldwide map from scan results")
    parser.add_argument("--json", required=True, help="JSON file from stadtnuke_worldwide.py")
    parser.add_argument("--country", required=True, help='Country name (e.g., "Bangladesh", "Japan")')
    args = parser.parse_args()

    if not os.path.exists(args.json):
        print(f"Error: {args.json} not found.")
        return

    with open(args.json, "r", encoding="utf-8") as f:
        devices = json.load(f)

    resolver = core.TargetResolver()
    target = resolver.resolve(country=args.country)

    map_file = f"{args.country.lower().replace(' ', '_')}_worldwide_map.html"
    smap.render_map(
        devices,
        title=f"WhyNot-StadtNuke Worldwide - {target.name}",
        center_coords=target.coords,
        output_file=map_file,
    )

    print(f"\n[+] Map saved: {map_file}")
    print(f"    Open with: firefox {map_file}")


if __name__ == "__main__":
    main()
