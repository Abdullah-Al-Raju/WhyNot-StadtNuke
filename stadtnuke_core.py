"""WhyNot-StadtNuke Core Engine.

Comprehensive network reconnaissance, target resolution, concurrent InternetDB
scanning, geolocation, risk analysis, and sarcastic reporting.
Authored by: Abduallah Al Raju
"""

import ipaddress
import json
import math
import os
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
SUBNETS_FILE = os.path.join(DATA_DIR, "subnets.json")
PORTS_FILE = os.path.join(DATA_DIR, "ports.json")


def load_subnets_db() -> Dict[str, Any]:
    if os.path.exists(SUBNETS_FILE):
        try:
            with open(SUBNETS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"cities": {}, "countries": {}}


def load_ports_db() -> Dict[str, Any]:
    if os.path.exists(PORTS_FILE):
        try:
            with open(PORTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"ports": {}, "overall_roasts": {"clean": ["No vulnerabilities detected."]}}


@dataclass
class TargetSpec:
    name: str
    target_type: str  # "city", "country", "asn", "cidr"
    country: str
    country_code: str
    coords: Tuple[float, float]
    prefixes: List[str]


@dataclass
class DeviceRecord:
    ip: str
    ports: List[int] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    cpes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)
    lat: Optional[float] = None
    lon: Optional[float] = None
    city: Optional[str] = None
    country: Optional[str] = None
    isp: Optional[str] = None
    risk_score: int = 0
    risk_level: str = "Low"
    roast: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TargetResolver:
    """Resolves arbitrary targets to verified subnets, coordinates, and metadata."""

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()
        self.subnets_db = load_subnets_db()

    def resolve(
        self,
        city: Optional[str] = None,
        country: Optional[str] = None,
        asn: Optional[str] = None,
        cidr: Optional[str] = None,
    ) -> TargetSpec:
        if cidr:
            return self._resolve_cidr(cidr)
        if city:
            return self._resolve_city(city)
        if country:
            return self._resolve_country(country)
        if asn:
            return self._resolve_asn(asn)
        raise ValueError("Must provide at least one target: city, country, asn, or cidr.")

    def _resolve_cidr(self, cidr_str: str) -> TargetSpec:
        net = ipaddress.ip_network(cidr_str.strip(), strict=False)
        return TargetSpec(
            name=f"Subnet {net}",
            target_type="cidr",
            country="Custom",
            country_code="XX",
            coords=(20.0, 0.0),
            prefixes=[str(net)],
        )

    def _resolve_city(self, city_name: str) -> TargetSpec:
        key = city_name.strip().lower()
        cities = self.subnets_db.get("cities", {})

        if key in cities:
            entry = cities[key]
            return TargetSpec(
                name=city_name.title(),
                target_type="city",
                country=entry.get("country", "Unknown"),
                country_code=entry.get("country_code", "XX"),
                coords=tuple(entry.get("coords", [48.1351, 11.5820])),
                prefixes=entry.get("prefixes", ["129.187.0.0/16"]),
            )

        # Fallback to OpenStreetMap Nominatim for coordinates
        lat, lon = self._lookup_nominatim(city_name)
        prefixes = self._lookup_ripe_prefixes(city_name)
        if not prefixes:
            prefixes = ["129.187.0.0/16", "130.149.0.0/16"]

        return TargetSpec(
            name=city_name.title(),
            target_type="city",
            country="Global",
            country_code="XX",
            coords=(lat, lon),
            prefixes=prefixes,
        )

    def _resolve_country(self, country_name: str) -> TargetSpec:
        name_clean = country_name.strip()
        name_lower = name_clean.lower()
        countries = self.subnets_db.get("countries", {})

        # Check by 2-letter code or country name
        for code, entry in countries.items():
            if code.lower() == name_lower or entry.get("name", "").lower() == name_lower:
                return TargetSpec(
                    name=entry.get("name", name_clean.title()),
                    target_type="country",
                    country=entry.get("name", name_clean.title()),
                    country_code=code.upper(),
                    coords=tuple(entry.get("coords", [20.0, 0.0])),
                    prefixes=entry.get("prefixes", ["103.15.244.0/22"]),
                )

        # Online RIPE fallback
        code_guess = name_clean.upper() if len(name_clean) == 2 else "XX"
        prefixes = self._lookup_ripe_country(code_guess)
        lat, lon = self._lookup_nominatim(country_name)
        if not prefixes:
            prefixes = ["103.15.244.0/22"]

        return TargetSpec(
            name=country_name.title(),
            target_type="country",
            country=country_name.title(),
            country_code=code_guess,
            coords=(lat, lon),
            prefixes=prefixes,
        )

    def _resolve_asn(self, asn_str: str) -> TargetSpec:
        asn_clean = asn_str.upper().replace("AS", "").strip()
        prefixes = []
        try:
            url = f"https://stat.ripe.net/data/asn-geo/data.json?resource=AS{asn_clean}"
            resp = self.session.get(url, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("data", {}).get("prefixes", []):
                    if "prefix" in item:
                        prefixes.append(item["prefix"])
        except Exception:
            pass

        if not prefixes:
            prefixes = ["103.15.244.0/22"]

        return TargetSpec(
            name=f"AS{asn_clean}",
            target_type="asn",
            country="Autonomous System",
            country_code="AS",
            coords=(20.0, 0.0),
            prefixes=prefixes[:10],
        )

    def _lookup_nominatim(self, query: str) -> Tuple[float, float]:
        try:
            url = f"https://nominatim.openstreetmap.org/search?q={query}&format=json&limit=1"
            headers = {"User-Agent": "WhyNot-StadtNuke/2.0 (Security Research; Abduallah Al Raju)"}
            resp = self.session.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data:
                    return float(data[0]["lat"]), float(data[0]["lon"])
        except Exception:
            pass
        return (48.1351, 11.5820)

    def _lookup_ripe_prefixes(self, resource: str) -> List[str]:
        try:
            url = f"https://stat.ripe.net/data/geoloc/data.json?resource={resource}&types=ipv4"
            resp = self.session.get(url, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                resources = data.get("data", {}).get("located_resources", [])
                prefixes = [item["prefix"] for item in resources if "prefix" in item]
                if prefixes:
                    return prefixes[:5]
        except Exception:
            pass
        return []

    def _lookup_ripe_country(self, code: str) -> List[str]:
        try:
            url = f"https://stat.ripe.net/data/country-resource-list/data.json?resource={code}"
            resp = self.session.get(url, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                ipv4 = data.get("data", {}).get("resources", {}).get("ipv4", [])
                if ipv4:
                    return ipv4[:10]
        except Exception:
            pass
        return []


class HostSampler:
    """Stratified and intelligent IP address sampler."""

    @staticmethod
    def sample_prefix(prefix_str: str, max_ips: int = 50, seed: Optional[int] = None) -> List[str]:
        try:
            net = ipaddress.ip_network(prefix_str.strip(), strict=False)
        except Exception:
            return []

        total_hosts = net.num_addresses
        if total_hosts <= 2:
            return [str(ip) for ip in net]

        rng = random.Random(seed if seed is not None else 42)

        # For small subnets (/24 to /30), directly iterate or sample
        if total_hosts <= max_ips + 2:
            hosts = [str(ip) for ip in net.hosts()]
            return hosts[:max_ips]

        # For larger subnets (/16, /20, /22), apply stratified sampling
        sampled: List[str] = []
        net_int = int(net.network_address)

        # 1. Sample standard infrastructure hosts
        common_offsets = [1, 2, 3, 10, 20, 50, 100, 200, 250, 254]
        for off in common_offsets:
            if off < total_hosts - 1:
                sampled.append(str(ipaddress.IPv4Address(net_int + off)))
                if len(sampled) >= max_ips:
                    return sampled

        # 2. Stratified selection across the address space
        remaining_needed = max_ips - len(sampled)
        step = max(1, (total_hosts - 2) // remaining_needed)
        for i in range(remaining_needed):
            offset = 1 + (i * step) + rng.randint(0, min(step - 1, 255))
            if offset < total_hosts - 1:
                ip_str = str(ipaddress.IPv4Address(net_int + offset))
                if ip_str not in sampled:
                    sampled.append(ip_str)

        return sampled[:max_ips]


class RiskScorer:
    """Evaluates port vulnerability weights and provides technical & sarcastic roasts."""

    def __init__(self):
        self.ports_db = load_ports_db()
        self.port_rules = self.ports_db.get("ports", {})
        self.overall_roasts = self.ports_db.get("overall_roasts", {})

    def evaluate_device(self, ports: List[int], vulns: List[str]) -> Tuple[int, str, str]:
        score = 0
        roasts = []

        for p in ports:
            p_str = str(p)
            if p_str in self.port_rules:
                rule = self.port_rules[p_str]
                score += rule.get("weight", 0)
                roasts.append(rule.get("roast", ""))

        # Extra score for confirmed CVEs
        score += len(vulns) * 20
        score = min(100, score)

        if score >= 60:
            level = "Critical"
        elif score >= 35:
            level = "High"
        elif score >= 15:
            level = "Medium"
        else:
            level = "Low"

        # Select representative roast
        chosen_roast = roasts[0] if roasts else "Standard internet endpoint."
        if vulns:
            chosen_roast += f" Exploits cataloged: {', '.join(vulns[:2])}."

        return score, level, chosen_roast

    def generate_overall_roast(self, total_devices: int, vuln_devices: int, critical_devices: int) -> str:
        if total_devices == 0:
            return "Digital ghost town: zero active devices responded in the surveyed perimeter."

        ratio = (vuln_devices / total_devices) if total_devices > 0 else 0.0

        if ratio > 0.4 or critical_devices > 0:
            roasts = self.overall_roasts.get(
                "critical", ["A script kiddie with a dial-up modem could compromise this in 4 minutes."]
            )
        elif vuln_devices > 0:
            roasts = self.overall_roasts.get(
                "high", ["Several critical services are asking for trouble. Patch schedule: Next decade."]
            )
        else:
            roasts = self.overall_roasts.get(
                "clean", ["No critical ports or CVEs detected. Either highly hardened or very boring."]
            )

        return random.choice(roasts)


class GeoResolver:
    """Geolocates IP addresses with local in-memory caching and bounded jittering."""

    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()
        self._cache: Dict[str, Dict[str, Any]] = {}

    def locate_ip(self, ip: str, fallback_coords: Tuple[float, float]) -> Tuple[float, float, str, str]:
        if ip in self._cache:
            c = self._cache[ip]
            return c["lat"], c["lon"], c.get("city", "Unknown"), c.get("isp", "Unknown")

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,lat,lon,isp,org"
            resp = self.session.get(url, timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success" and data.get("lat") and data.get("lon"):
                    lat, lon = float(data["lat"]), float(data["lon"])
                    city = data.get("city", "Unknown")
                    isp = data.get("isp", data.get("org", "Unknown"))
                    self._cache[ip] = {"lat": lat, "lon": lon, "city": city, "isp": isp}
                    return lat, lon, city, isp
        except Exception:
            pass

        # Jitter fallback within ~300 meters of target center to prevent overlap without placing in another country
        rng = random.Random(hash(ip))
        lat_offset = rng.uniform(-0.003, 0.003)
        lon_offset = rng.uniform(-0.003, 0.003)
        lat = round(fallback_coords[0] + lat_offset, 5)
        lon = round(fallback_coords[1] + lon_offset, 5)

        self._cache[ip] = {"lat": lat, "lon": lon, "city": "Target Vicinity", "isp": "Telecom Transit"}
        return lat, lon, "Target Vicinity", "Telecom Transit"


class CensusEngine:
    """High-concurrency scanner orchestrating Shodan InternetDB queries and telemetry."""

    def __init__(self, concurrency: int = 15, delay: float = 0.05):
        self.concurrency = concurrency
        self.delay = delay
        self.session = requests.Session()
        self.resolver = TargetResolver(self.session)
        self.sampler = HostSampler()
        self.scorer = RiskScorer()
        self.geo = GeoResolver(self.session)

    def query_shodan_internetdb(self, ip: str) -> Optional[Dict[str, Any]]:
        url = f"https://internetdb.shodan.io/{ip}"
        try:
            resp = self.session.get(url, timeout=4)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    def scan_target(
        self,
        target: TargetSpec,
        max_ips_per_prefix: int = 25,
        max_total_devices: int = 100,
        on_device: Optional[Callable[[DeviceRecord], None]] = None,
        on_progress: Optional[Callable[[int, int, str], None]] = None,
    ) -> List[DeviceRecord]:
        """Perform concurrent scan across target prefixes."""
        # Build candidate IP list
        all_candidate_ips: List[str] = []
        for prefix in target.prefixes:
            ips = self.sampler.sample_prefix(prefix, max_ips=max_ips_per_prefix)
            all_candidate_ips.extend(ips)

        total_candidates = len(all_candidate_ips)
        discovered: List[DeviceRecord] = []
        completed = 0

        def worker(ip: str) -> Optional[DeviceRecord]:
            time.sleep(self.delay)
            data = self.query_shodan_internetdb(ip)
            if not data or not data.get("ports"):
                return None

            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            hostnames = data.get("hostnames", [])
            cpes = data.get("cpes", [])
            tags = data.get("tags", [])

            score, level, roast = self.scorer.evaluate_device(ports, vulns)
            lat, lon, city, isp = self.geo.locate_ip(ip, target.coords)

            return DeviceRecord(
                ip=ip,
                ports=ports,
                hostnames=hostnames,
                cpes=cpes,
                tags=tags,
                vulns=vulns,
                lat=lat,
                lon=lon,
                city=city,
                country=target.country,
                isp=isp,
                risk_score=score,
                risk_level=level,
                roast=roast,
            )

        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            future_to_ip = {executor.submit(worker, ip): ip for ip in all_candidate_ips}

            for future in as_completed(future_to_ip):
                completed += 1
                curr_ip = future_to_ip[future]
                if on_progress:
                    on_progress(completed, total_candidates, curr_ip)

                try:
                    record = future.result()
                    if record:
                        discovered.append(record)
                        if on_device:
                            on_device(record)
                        if len(discovered) >= max_total_devices:
                            executor.shutdown(wait=False, cancel_futures=True)
                            break
                except Exception:
                    pass

        return discovered

    def run_simulation(
        self,
        target: TargetSpec,
        count: int = 35,
        vuln_ratio: float = 0.3,
        seed: int = 42,
    ) -> List[DeviceRecord]:
        """Generate statistically realistic simulated census for offline testing and demos."""
        rng = random.Random(seed)
        records: List[DeviceRecord] = []

        port_pool = [80, 443, 22, 21, 25, 53, 3306, 5432, 8080, 8443, 3389, 445, 6379, 554]
        cve_pool = [
            "CVE-2021-44228",
            "CVE-2017-0144",
            "CVE-2019-0708",
            "CVE-2020-1472",
            "CVE-2022-26134",
            "CVE-2023-34362",
            "CVE-2024-21887",
        ]

        # Use target's first prefix or default
        base_prefix = target.prefixes[0] if target.prefixes else "129.187.0.0/16"
        sampled_ips = self.sampler.sample_prefix(base_prefix, max_ips=count * 2, seed=seed)

        for i in range(min(count, len(sampled_ips))):
            ip = sampled_ips[i]
            num_ports = rng.randint(1, 5)
            ports = sorted(rng.sample(port_pool, num_ports))

            vulns = []
            if rng.random() < vuln_ratio:
                num_vulns = rng.randint(1, 3)
                vulns = rng.sample(cve_pool, num_vulns)

            score, level, roast = self.scorer.evaluate_device(ports, vulns)

            lat_off = rng.uniform(-0.015, 0.015)
            lon_off = rng.uniform(-0.015, 0.015)
            lat = round(target.coords[0] + lat_off, 5)
            lon = round(target.coords[1] + lon_off, 5)

            rec = DeviceRecord(
                ip=ip,
                ports=ports,
                hostnames=[f"node-{i:03d}.{target.name.lower().replace(' ', '')}.net"],
                cpes=["cpe:/o:linux:linux_kernel", "cpe:/a:apache:http_server"],
                tags=["cloud", "vpn"] if 443 in ports else ["iot"],
                vulns=vulns,
                lat=lat,
                lon=lon,
                city=target.name,
                country=target.country,
                isp="Deutsche Telekom AG" if "DE" in target.country_code else "National Backbone",
                risk_score=score,
                risk_level=level,
                roast=roast,
            )
            records.append(rec)

        return records
