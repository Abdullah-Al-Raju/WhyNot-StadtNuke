#!/usr/bin/env python3
"""
WhyNot-StadtNuke Global Merger
Combines all scan results into ONE single world map.
Usage: python merge_all_maps.py
"""

import json
import folium
import random
import os
import glob

# Colors for different countries
COLORS = {
    "bangladesh": "red",
    "japan": "blue", 
    "germany": "green",
    "munich": "green",
    "dhaka": "red",
    "default": "purple"
}

# Center coordinates for different regions
CENTER_COORDS = {
    "bangladesh": [23.685, 90.3563],
    "japan": [36.2048, 138.2529],
    "germany": [51.1657, 10.4515],
    "munich": [48.1351, 11.5820],
    "dhaka": [23.8103, 90.4125]
}

def get_country_from_filename(filename):
    """Extract country name from filename"""
    filename_lower = filename.lower()
    if "bangladesh" in filename_lower:
        return "bangladesh"
    elif "japan" in filename_lower:
        return "japan"
    elif "germany" in filename_lower or "munich" in filename_lower:
        return "germany"
    elif "dhaka" in filename_lower:
        return "bangladesh"
    else:
        return "unknown"

def load_all_json_files():
    """Load all JSON files from scans"""
    all_devices = []
    json_files = glob.glob("*_worldwide.json") + glob.glob("*_stadtnuke*.json")
    
    print(f"[*] Found {len(json_files)} JSON files:")
    for f in json_files:
        size = os.path.getsize(f)
        print(f"    - {f} ({size} bytes)")
    
    for json_file in json_files:
        try:
            with open(json_file, 'r') as f:
                devices = json.load(f)
                country = get_country_from_filename(json_file)
                for dev in devices:
                    dev['source_country'] = country
                    dev['source_file'] = json_file
                all_devices.extend(devices)
                print(f"    Loaded {len(devices)} devices from {json_file} -> {country}")
        except Exception as e:
            print(f"    Error loading {json_file}: {e}")
    
    return all_devices

def generate_global_map(devices):
    """Generate a single world map with all devices"""
    # Center of the world (Greenwich)
    world_center = [20, 10]
    
    print(f"\n[*] Generating GLOBAL MAP with {len(devices)} total devices...")
    
    m = folium.Map(location=world_center, zoom_start=2, tiles='CartoDB positron')
    
    plotted = 0
    for idx, dev in enumerate(devices[:200]):  # Limit to 200 for performance
        country = dev.get('source_country', 'unknown')
        
        # Get center for this country
        if country in CENTER_COORDS:
            base_lat, base_lon = CENTER_COORDS[country]
        else:
            base_lat, base_lon = 20, 10
        
        # Add random spread within country (so they don't all stack)
        lat = base_lat + random.uniform(-0.8, 0.8)
        lon = base_lon + random.uniform(-0.8, 0.8)
        
        # Choose color based on country
        color = COLORS.get(country, COLORS['default'])
        
        # Determine if device has vulnerabilities
        has_vulns = dev.get('vulns') and len(dev.get('vulns', [])) > 0
        if has_vulns:
            color = 'darkred'
        
        # Create popup text
        popup_text = f"""
        <b>IP:</b> {dev['ip']}<br>
        <b>Ports:</b> {dev['ports'][:4]}<br>
        <b>Country:</b> {country.upper()}<br>
        <b>Vulns:</b> {len(dev.get('vulns', []))}<br>
        <b>Source:</b> {dev.get('source_file', 'unknown')}
        """
        
        folium.Marker(
            [lat, lon],
            popup=folium.Popup(popup_text, max_width=300),
            icon=folium.Icon(color=color, icon='info-sign')
        ).add_to(m)
        plotted += 1
    
    # Add a legend
    legend_html = '''
    <div style="position: fixed; bottom: 50px; left: 50px; z-index: 1000; background-color: white; padding: 10px; border-radius: 5px; border: 2px solid grey;">
    <b>🌍 Legend</b><br>
    🔴 Red: Bangladesh<br>
    🔵 Blue: Japan<br>
    🟢 Green: Germany/Munich<br>
    🟣 Purple: Unknown<br>
    ⚫ Dark Red: Has Vulnerabilities
    </div>
    '''
    m.get_root().html.add_child(folium.Element(legend_html))
    
    map_file = "GLOBAL_STADTNUKE_MAP.html"
    m.save(map_file)
    
    print(f"\n✅ GLOBAL MAP SAVED: {map_file}")
    print(f"   Total devices plotted: {plotted}")
    print(f"   Open with: firefox {map_file}")
    print("\n📊 Summary by country:")
    
    # Count by country
    country_counts = {}
    for dev in devices:
        country = dev.get('source_country', 'unknown')
        country_counts[country] = country_counts.get(country, 0) + 1
    
    for country, count in country_counts.items():
        print(f"      {country.upper()}: {count} devices")

def main():
    print("💥 WhyNot-StadtNuke GLOBAL MERGER")
    print("="*40)
    
    # Load all JSON files
    devices = load_all_json_files()
    
    if not devices:
        print("\n[!] No devices found. Run scans first:")
        print("    python stadtnuke_worldwide.py --country Bangladesh")
        print("    python stadtnuke_worldwide.py --country Japan")
        print("    python stadtnuke.py")  # For Munich
        return
    
    # Generate global map
    generate_global_map(devices)

if __name__ == "__main__":
    main()
