#!/usr/bin/env python3
"""WhyNot-StadtNuke Ultimate Map Generator (Legacy Compatibility Wrapper)."""

import argparse
import json
import os
import stadtnuke_core as core
import stadtnuke_map as smap


def main():
    parser = argparse.ArgumentParser(description="Generate map from WhyNot-StadtNuke Ultimate scan")
    parser.add_argument("--json", required=True, help="JSON file from stadtnuke_ultimate.py")
    parser.add_argument("--city", required=True, help="City name")
    args = parser.parse_args()

    if not os.path.exists(args.json):
        print(f"Error: {args.json} not found.")
        return

    with open(args.json, "r", encoding="utf-8") as f:
        devices = json.load(f)

    resolver = core.TargetResolver()
    target = resolver.resolve(city=args.city)

    map_file = f"{args.city.replace(' ', '_')}_stadtnuke_ultimate_map.html"
    smap.render_map(
        devices,
        title=f"WhyNot-StadtNuke Ultimate - {target.name}",
        center_coords=target.coords,
        output_file=map_file,
    )

    print(f"\n[+] Map saved: {map_file}")
    print(f"    Open with: firefox {map_file}")


if __name__ == "__main__":
    main()
