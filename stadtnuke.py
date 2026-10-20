#!/usr/bin/env python3
"""WhyNot-StadtNuke Unified CLI.

Worldwide network census, attack-surface intelligence, interactive mapping,
and sarcastic defense audit engine.
Authored by: Abduallah Al Raju
"""

import argparse
import json
import os
import sys
from typing import List

import stadtnuke_core as core
import stadtnuke_map as smap


def print_banner():
    print("=" * 64)
    print("  WhyNot-StadtNuke // Worldwide Network Census & Attack Radar")
    print("  Engine by Abduallah Al Raju | v2.0 Tactical Edition")
    print("=" * 64 + "\n")


def cmd_scan(args):
    print_banner()
    resolver = core.TargetResolver()
    try:
        target = resolver.resolve(
            city=args.city,
            country=args.country,
            asn=args.asn,
            cidr=args.cidr,
        )
    except Exception as exc:
        print(f"[!] Target resolution failed: {exc}")
        sys.exit(1)

    print(f"[*] Target Identity: {target.name} ({target.country})")
    print(f"[*] Target Coordinates: {target.coords[0]:.4f}, {target.coords[1]:.4f}")
    print(f"[*] Allocated Prefixes: {', '.join(target.prefixes[:5])}")
    if len(target.prefixes) > 5:
        print(f"    (+{len(target.prefixes) - 5} additional prefixes)")

    engine = core.CensusEngine(concurrency=args.concurrency, delay=args.delay)

    def on_prog(done, total, ip):
        if not args.quiet:
            pct = (done / total) * 100
            print(f"\r[*] Surveying hosts: {done}/{total} ({pct:.1f}%) | Probing {ip:<16}", end="", flush=True)

    print("\n[*] Initializing concurrent Shodan InternetDB inspection...")
    devices = engine.scan_target(
        target,
        max_ips_per_prefix=args.max_ips,
        max_total_devices=args.max_devices,
        on_progress=on_prog,
    )
    print("\n[+] Survey complete.")

    # Save JSON output
    out_json = args.output or f"{target.name.lower().replace(' ', '_')}_stadtnuke.json"
    dict_devices = [d.to_dict() for d in devices]
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(dict_devices, f, indent=2)

    print(f"[+] Discovered {len(devices)} active endpoints -> {out_json}")

    # Generate Map if requested
    if args.map or args.map_output:
        map_file = args.map_output or f"{target.name.lower().replace(' ', '_')}_map.html"
        smap.render_map(
            dict_devices,
            title=f"WhyNot-StadtNuke - {target.name}",
            center_coords=target.coords,
            output_file=map_file,
        )
        print(f"[+] Tactical Map generated -> {map_file}")

    # Display sarcastic report
    _display_report(target.name, dict_devices, engine.scorer)


def cmd_demo(args):
    print_banner()
    print("[*] Running zero-network simulated census demo...")
    resolver = core.TargetResolver()
    target = resolver.resolve(city=args.city)
    engine = core.CensusEngine()

    devices = engine.run_simulation(
        target,
        count=args.count,
        vuln_ratio=args.vuln_ratio,
    )
    dict_devices = [d.to_dict() for d in devices]

    out_json = args.output or f"{args.city.lower()}_stadtnuke_demo.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(dict_devices, f, indent=2)

    print(f"[+] Simulated census generated: {len(devices)} endpoints -> {out_json}")

    map_file = args.map_output or f"{args.city.lower()}_demo_map.html"
    smap.render_map(
        dict_devices,
        title=f"WhyNot-StadtNuke Demo - {target.name}",
        center_coords=target.coords,
        output_file=map_file,
    )
    print(f"[+] Interactive Map generated -> {map_file}")

    _display_report(target.name, dict_devices, engine.scorer)


def cmd_map(args):
    print_banner()
    if not os.path.exists(args.input):
        print(f"[!] Input file '{args.input}' not found.")
        sys.exit(1)

    with open(args.input, "r", encoding="utf-8") as f:
        devices = json.load(f)

    out_file = args.output or f"{os.path.splitext(args.input)[0]}_map.html"
    smap.render_map(
        devices,
        title=args.title or "WhyNot-StadtNuke Attack Surface Map",
        output_file=out_file,
    )
    print(f"[+] Map rendered successfully: {len(devices)} devices plotted -> {out_file}")


def cmd_merge(args):
    print_banner()
    merged = smap.merge_json_scans(args.files)
    if not merged:
        print("[!] No valid devices found across provided files.")
        sys.exit(1)

    out_json = args.json_output or "GLOBAL_STADTNUKE_MERGED.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)
    print(f"[+] Merged {len(merged)} unique endpoints into {out_json}")

    map_file = args.output or "GLOBAL_STADTNUKE_MAP.html"
    smap.render_map(
        merged,
        title="WhyNot-StadtNuke Global Attack Surface",
        center_coords=(20.0, 10.0),
        output_file=map_file,
        zoom_start=2,
    )
    print(f"[+] Global World Map generated -> {map_file}")


def cmd_report(args):
    print_banner()
    if not os.path.exists(args.file):
        print(f"[!] File '{args.file}' not found.")
        sys.exit(1)

    with open(args.file, "r", encoding="utf-8") as f:
        devices = json.load(f)

    target_name = os.path.splitext(os.path.basename(args.file))[0]
    scorer = core.RiskScorer()
    _display_report(target_name, devices, scorer)


def _display_report(target_name: str, devices: List[dict], scorer: core.RiskScorer):
    total = len(devices)
    vuln_devs = sum(1 for d in devices if d.get("vulns"))
    crit_devs = sum(1 for d in devices if d.get("risk_level") == "Critical")
    high_devs = sum(1 for d in devices if d.get("risk_level") == "High")
    med_devs = sum(1 for d in devices if d.get("risk_level") == "Medium")
    low_devs = sum(1 for d in devices if d.get("risk_level") == "Low")

    threat_score = round(sum(d.get("risk_score", 0) for d in devices) / total) if total > 0 else 0
    roast = scorer.generate_overall_roast(total, vuln_devs, crit_devs)

    print("\n" + "=" * 64)
    print(f"  ATTACK SURFACE & DEFENSE AUDIT: {target_name.upper()}")
    print("=" * 64)
    print(f"  Total Surveyed Endpoints: {total}")
    print(f"  Vulnerable Systems:       {vuln_devs} ({(vuln_devs/total*100):.1f}%)" if total else "0")
    print(f"  Critical Risk Nodes:      {crit_devs}")
    print(f"  High Risk Nodes:          {high_devs}")
    print(f"  Medium Risk Nodes:        {med_devs}")
    print(f"  Hardened / Low Risk:      {low_devs}")
    print(f"  Overall Threat Score:     {threat_score}/100")
    print("-" * 64)
    print(f"  SARCASTIC AUDIT ROAST:\n  \"{roast}\"")
    print("=" * 64 + "\n")


def cmd_web(args):
    try:
        import uvicorn
    except ImportError:
        print("[!] uvicorn is required for web mode: pip install uvicorn fastapi")
        sys.exit(1)

    print_banner()
    print(f"[+] Starting WhyNot-StadtNuke Tactical Web Radar on http://{args.host}:{args.port}")
    uvicorn.run("web_app:app", host=args.host, port=args.port, log_level="info")


def main():
    parser = argparse.ArgumentParser(
        description="WhyNot-StadtNuke: Worldwide Network Census & Attack Surface Radar by Abduallah Al Raju",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Operational mode")

    # scan subcommand
    sp_scan = subparsers.add_parser("scan", help="Conduct live network census across city, country, or subnet")
    grp_target = sp_scan.add_mutually_exclusive_group(required=True)
    grp_target.add_argument("--city", help="Target city name (e.g. 'Munich', 'Berlin', 'Tokyo')")
    grp_target.add_argument("--country", help="Target country code or name (e.g. 'BD', 'Germany', 'JP')")
    grp_target.add_argument("--asn", help="Target Autonomous System Number (e.g. 'AS45609')")
    grp_target.add_argument("--cidr", help="Target direct CIDR prefix (e.g. '129.187.0.0/16')")
    sp_scan.add_argument("--max-ips", type=int, default=30, help="Max IPs to sample per prefix (default: 30)")
    sp_scan.add_argument("--max-devices", type=int, default=100, help="Max total discovered devices (default: 100)")
    sp_scan.add_argument("--concurrency", type=int, default=15, help="Concurrent worker threads (default: 15)")
    sp_scan.add_argument("--delay", type=float, default=0.04, help="Inter-request delay in seconds (default: 0.04)")
    sp_scan.add_argument("-o", "--output", help="Output JSON results path")
    sp_scan.add_argument("--map", action="store_true", help="Generate interactive Folium map automatically")
    sp_scan.add_argument("--map-output", help="Custom output path for generated map HTML")
    sp_scan.add_argument("-q", "--quiet", action="store_true", help="Suppress progress ticker")

    # demo subcommand
    sp_demo = subparsers.add_parser("demo", help="Run simulated offline attack surface census without internet API dependency")
    sp_demo.add_argument("--city", default="Munich", help="City profile to simulate (default: Munich)")
    sp_demo.add_argument("--count", type=int, default=35, help="Number of simulated endpoints (default: 35)")
    sp_demo.add_argument("--vuln-ratio", type=float, default=0.35, help="Fraction of vulnerable endpoints (default: 0.35)")
    sp_demo.add_argument("-o", "--output", help="Output JSON results path")
    sp_demo.add_argument("--map-output", help="Output HTML map path")

    # map subcommand
    sp_map = subparsers.add_parser("map", help="Render interactive HTML map from existing scan JSON")
    sp_map.add_argument("-i", "--input", required=True, help="Input scan JSON file")
    sp_map.add_argument("-o", "--output", help="Output HTML map file")
    sp_map.add_argument("--title", help="Map HUD custom title")

    # merge subcommand
    sp_merge = subparsers.add_parser("merge", help="Merge multiple scan JSON files into one global world map")
    sp_merge.add_argument("files", nargs="+", help="JSON scan files to merge")
    sp_merge.add_argument("-o", "--output", default="GLOBAL_STADTNUKE_MAP.html", help="Output global map HTML")
    sp_merge.add_argument("--json-output", help="Output merged JSON file path")

    # report subcommand
    sp_report = subparsers.add_parser("report", help="Display sarcastic defense audit report for a scan file")
    sp_report.add_argument("file", help="Input scan JSON file")

    # web subcommand
    sp_web = subparsers.add_parser("web", help="Launch interactive tactical web radar interface")
    sp_web.add_argument("--host", default="127.0.0.1", help="Server bind host (default: 127.0.0.1)")
    sp_web.add_argument("--port", type=int, default=8080, help="Server bind port (default: 8080)")

    args = parser.parse_args()

    if args.subcommand == "scan":
        cmd_scan(args)
    elif args.subcommand == "demo":
        cmd_demo(args)
    elif args.subcommand == "map":
        cmd_map(args)
    elif args.subcommand == "merge":
        cmd_merge(args)
    elif args.subcommand == "report":
        cmd_report(args)
    elif args.subcommand == "web":
        cmd_web(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
