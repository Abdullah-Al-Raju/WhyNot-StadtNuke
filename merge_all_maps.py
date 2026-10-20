#!/usr/bin/env python3
"""WhyNot-StadtNuke Global Merger (Legacy Compatibility Wrapper).

Merges all scan results into one unified interactive world map.
"""

import glob
import stadtnuke_map as smap


def main():
    print("WhyNot-StadtNuke GLOBAL MERGER")
    print("=" * 40)

    json_files = glob.glob("*_worldwide.json") + glob.glob("*_stadtnuke*.json") + glob.glob("*_devices.json")
    # Remove duplicates in list
    json_files = list(set(json_files))

    if not json_files:
        print("[!] No scan JSON files found. Run scans first or run demo:")
        print("    python stadtnuke.py demo --city Munich")
        print("    python stadtnuke.py demo --city Tokyo")
        return

    print(f"[*] Found {len(json_files)} scan files to merge:")
    for f in json_files:
        print(f"    - {f}")

    merged = smap.merge_json_scans(json_files)
    map_file = "GLOBAL_STADTNUKE_MAP.html"

    smap.render_map(
        merged,
        title="WhyNot-StadtNuke Global Attack Surface",
        center_coords=(20.0, 10.0),
        output_file=map_file,
        zoom_start=2,
    )

    print("\n" + "=" * 50)
    print(f"[+] GLOBAL MAP SAVED: {map_file}")
    print(f"    Total unique devices plotted: {len(merged)}")
    print(f"    Open with: firefox {map_file}")
    print("=" * 50)


if __name__ == "__main__":
    main()
