#!/usr/bin/env python3
"""WhyNot-StadtNuke Munich Map Generator (Legacy Compatibility Wrapper)."""

import json
import os
import sys
import stadtnuke_map as smap

CITY_NAME = "Munich"


def main():
    json_file = f"{CITY_NAME}_stadtnuke.json"
    if not os.path.exists(json_file):
        print(f"Error: {json_file} not found. Run 'python stadtnuke.py scan --city Munich' or 'python stadtnuke.py demo' first.")
        return

    with open(json_file, "r", encoding="utf-8") as f:
        devices = json.load(f)

    if not devices:
        print("No devices found in JSON file.")
        return

    map_file = f"{CITY_NAME}_stadtnuke_map.html"
    smap.render_map(
        devices,
        title=f"WhyNot-StadtNuke - {CITY_NAME}",
        center_coords=(48.1351, 11.5820),
        output_file=map_file,
    )

    print("\n" + "=" * 50)
    print(f"[+] Map saved: {map_file}")
    print(f"    Total devices plotted: {len(devices)}")
    print(f"    Open with: firefox {map_file}")
    print("=" * 50)


if __name__ == "__main__":
    main()
