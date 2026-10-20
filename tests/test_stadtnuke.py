"""Comprehensive test suite for WhyNot-StadtNuke.

Verifies target resolution, stratified host sampling, risk assessment,
offline simulation, map rendering, and FastAPI web endpoints.
Authored by: Abduallah Al Raju
"""

import json
import os
import tempfile
import pytest
from fastapi.testclient import TestClient

import stadtnuke_core as core
import stadtnuke_map as smap
from web_app import app


class TestTargetResolution:
    def test_resolve_builtin_city(self):
        resolver = core.TargetResolver()
        target = resolver.resolve(city="Munich")
        assert target.name == "Munich"
        assert target.target_type == "city"
        assert target.country_code == "DE"
        assert len(target.prefixes) > 0
        assert target.coords[0] == pytest.approx(48.1351, abs=0.01)

    def test_resolve_builtin_country_code(self):
        resolver = core.TargetResolver()
        target = resolver.resolve(country="BD")
        assert target.country_code == "BD"
        assert target.target_type == "country"
        assert "Bangladesh" in target.name
        assert len(target.prefixes) > 0

    def test_resolve_builtin_country_name(self):
        resolver = core.TargetResolver()
        target = resolver.resolve(country="Germany")
        assert target.country_code == "DE"
        assert len(target.prefixes) > 0

    def test_resolve_direct_cidr(self):
        resolver = core.TargetResolver()
        target = resolver.resolve(cidr="192.168.1.0/24")
        assert target.target_type == "cidr"
        assert target.prefixes == ["192.168.1.0/24"]

    def test_resolve_empty_raises(self):
        resolver = core.TargetResolver()
        with pytest.raises(ValueError):
            resolver.resolve()


class TestHostSampling:
    def test_sample_small_subnet(self):
        sampler = core.HostSampler()
        ips = sampler.sample_prefix("192.168.1.0/28", max_ips=10)
        assert len(ips) <= 10
        assert "192.168.1.1" in ips

    def test_sample_large_subnet_stratified(self):
        sampler = core.HostSampler()
        ips = sampler.sample_prefix("129.187.0.0/16", max_ips=30)
        assert len(ips) == 30
        assert len(set(ips)) == 30
        # Check boundary integrity
        for ip in ips:
            octets = [int(o) for o in ip.split(".")]
            assert octets[0] == 129
            assert octets[1] == 187


class TestRiskAndSarcasmScoring:
    def test_clean_device_scoring(self):
        scorer = core.RiskScorer()
        score, level, roast = scorer.evaluate_device(ports=[443, 80], vulns=[])
        assert score < 20
        assert level == "Low"

    def test_critical_ports_scoring(self):
        scorer = core.RiskScorer()
        score, level, roast = scorer.evaluate_device(ports=[445, 23, 6379], vulns=["CVE-2021-44228"])
        assert score >= 60
        assert level == "Critical"
        assert len(roast) > 0

    def test_overall_roast_generation(self):
        scorer = core.RiskScorer()
        # Empty devices
        assert "zero active devices" in scorer.generate_overall_roast(0, 0, 0)
        # Critical network
        crit_roast = scorer.generate_overall_roast(10, 8, 5)
        assert len(crit_roast) > 0


class TestSimulationEngine:
    def test_run_simulation(self):
        resolver = core.TargetResolver()
        target = resolver.resolve(city="Tokyo")
        engine = core.CensusEngine()

        records = engine.run_simulation(target, count=20, vuln_ratio=0.5, seed=123)
        assert len(records) == 20
        assert all(r.country == "Japan" for r in records)
        assert all(len(r.ports) > 0 for r in records)
        assert any(len(r.vulns) > 0 for r in records)


class TestMapRendering:
    def test_render_map_html(self):
        resolver = core.TargetResolver()
        target = resolver.resolve(city="Munich")
        engine = core.CensusEngine()
        records = engine.run_simulation(target, count=10)
        dict_records = [r.to_dict() for r in records]

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            temp_path = f.name

        try:
            smap.render_map(dict_records, title="Test Map", output_file=temp_path)
            assert os.path.exists(temp_path)
            with open(temp_path, "r", encoding="utf-8") as f:
                content = f.read()
            assert "leaflet" in content.lower()
            assert "Test Map" in content
            assert "Abduallah Al Raju" in content
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_merge_json_scans(self):
        dev1 = [{"ip": "1.1.1.1", "ports": [53]}]
        dev2 = [{"ip": "1.1.1.1", "ports": [53]}, {"ip": "8.8.8.8", "ports": [53]}]

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f1, \
             tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f2:
            json.dump(dev1, f1)
            f1.flush()
            json.dump(dev2, f2)
            f2.flush()
            p1, p2 = f1.name, f2.name

        try:
            merged = smap.merge_json_scans([p1, p2])
            assert len(merged) == 2
            ips = [d["ip"] for d in merged]
            assert "1.1.1.1" in ips and "8.8.8.8" in ips
        finally:
            os.remove(p1)
            os.remove(p2)


class TestWebAPI:
    def test_api_status(self):
        client = TestClient(app)
        res = client.get("/api/status")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "online"
        assert data["author"] == "Abduallah Al Raju"
        assert "Munich".lower() in data["available_cities"]

    def test_api_demo_and_devices(self):
        client = TestClient(app)
        res = client.post("/api/demo", json={"city": "Munich", "count": 15, "vuln_ratio": 0.5})
        assert res.status_code == 200
        demo_data = res.json()
        assert demo_data["count"] == 15

        # Get devices
        dev_res = client.get("/api/devices")
        assert dev_res.status_code == 200
        assert len(dev_res.json()["devices"]) == 15

        # Filter vulnerable
        vuln_res = client.get("/api/devices?vulnerable_only=true")
        assert vuln_res.status_code == 200
        for dev in vuln_res.json()["devices"]:
            assert len(dev["vulns"]) > 0

    def test_api_export_json(self):
        client = TestClient(app)
        # Ensure devices exist
        client.post("/api/demo", json={"city": "Munich", "count": 5})
        res = client.get("/api/export/json")
        assert res.status_code == 200
        assert "application/json" in res.headers["content-type"]
