# WhyNot-StadtNuke Verification and Empirical Audit Report

An end-to-end verification and performance audit was executed across the rebuilt **WhyNot-StadtNuke** framework, validating target resolution, stratified host sampling, concurrent Shodan InternetDB querying, geospatial map rendering, and the interactive web radar.

Conducted and authored by: **Abduallah Al Raju**

---

## 1. Automated Test Suite Execution

The automated test suite in `tests/test_stadtnuke.py` was executed using pytest, verifying all functional subsystems:

```
============================= test session starts ==============================
platform linux -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0 -- /usr/bin/python3
cachedir: .pytest_cache
rootdir: /home/raju/Downloads/git-optimization/WhyNot-StadtNuke
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.12.1, typeguard-4.4.4
collected 16 items

tests/test_stadtnuke.py::TestTargetResolution::test_resolve_builtin_city PASSED [  6%]
tests/test_stadtnuke.py::TestTargetResolution::test_resolve_builtin_country_code PASSED [ 12%]
tests/test_stadtnuke.py::TestTargetResolution::test_resolve_builtin_country_name PASSED [ 18%]
tests/test_stadtnuke.py::TestTargetResolution::test_resolve_direct_cidr PASSED [ 25%]
tests/test_stadtnuke.py::TestTargetResolution::test_resolve_empty_raises PASSED [ 31%]
tests/test_stadtnuke.py::TestHostSampling::test_sample_small_subnet PASSED [ 37%]
tests/test_stadtnuke.py::TestHostSampling::test_sample_large_subnet_stratified PASSED [ 43%]
tests/test_stadtnuke.py::TestRiskAndSarcasmScoring::test_clean_device_scoring PASSED [ 50%]
tests/test_stadtnuke.py::TestRiskAndSarcasmScoring::test_critical_ports_scoring PASSED [ 56%]
tests/test_stadtnuke.py::TestRiskAndSarcasmScoring::test_overall_roast_generation PASSED [ 62%]
tests/test_stadtnuke.py::TestSimulationEngine::test_run_simulation PASSED [ 68%]
tests/test_stadtnuke.py::TestMapRendering::test_render_map_html PASSED   [ 75%]
tests/test_stadtnuke.py::TestMapRendering::test_merge_json_scans PASSED  [ 81%]
tests/test_stadtnuke.py::TestWebAPI::test_api_status PASSED              [ 87%]
tests/test_stadtnuke.py::TestWebAPI::test_api_demo_and_devices PASSED    [ 93%]
tests/test_stadtnuke.py::TestWebAPI::test_api_export_json PASSED         [100%]

============================== 16 passed in 4.08s ==============================
```

- **Pass Rate**: 100% (16 of 16 tests passing).
- **Subsystem Coverage**: Target Resolution, Subnet Sampling, Risk Calculation, Simulation Engine, Folium Map Generation, JSON Deduplication, FastAPI REST Endpoints.

---

## 2. CLI Offline Simulation and Map Audit

The offline simulation demo was executed via the unified CLI:

```bash
python3 stadtnuke.py demo --city "Munich" --output Munich_stadtnuke.json --map-output Munich_stadtnuke_map.html
```

### Execution Telemetry

```
================================================================
  WhyNot-StadtNuke // Worldwide Network Census & Attack Radar
  Engine by Abduallah Al Raju | v2.0 Tactical Edition
================================================================

[*] Running zero-network simulated census demo...
[+] Simulated census generated: 35 endpoints -> Munich_stadtnuke.json
[+] Interactive Map generated -> Munich_stadtnuke_map.html

================================================================
  ATTACK SURFACE & DEFENSE AUDIT: MUNICH
================================================================
  Total Surveyed Endpoints: 35
  Vulnerable Systems:       14 (40.0%)
  Critical Risk Nodes:      24
  High Risk Nodes:          3
  Medium Risk Nodes:        2
  Hardened / Low Risk:      6
  Overall Threat Score:     69/100
----------------------------------------------------------------
  SARCASTIC AUDIT ROAST:
  "A script kiddie with a dial-up modem could compromise this in 4 minutes."
================================================================
```

- **Output Artifacts**: Validated that `Munich_stadtnuke.json` contains structured endpoints and `Munich_stadtnuke_map.html` correctly embeds Leaflet clusters, HUD elements, and OpenStreetMap tiles.

---

## 3. Web Radar Dashboard Live Verification

The tactical web radar was launched on `http://127.0.0.1:8081`, populated via the census engine, and rendered in headless Chromium.

### Browser Dashboard Capture

![WhyNot-StadtNuke Web Radar Dashboard](web-radar.png)

### Live Telemetry Metrics

| Metric | Measured Value | Notes |
|---|---|---|
| **Surveyed Endpoints** | 42 | Sampled across target subnets |
| **Vulnerable Targets** | 19 | Confirmed active CVEs cataloged |
| **Critical Risk Nodes** | 28 | Exposed high-risk ports (SMB 445, Telnet 23, Redis 6379) |
| **High Risk Nodes** | 8 | Remote desktop/database interfaces (RDP 3389, MySQL 3306) |
| **Medium Risk Nodes** | 3 | Legacy protocols (SMTP 25, FTP 21) |
| **Low / Hardened Nodes**| 3 | Standard encrypted endpoints (HTTPS 443, SSH 22) |
| **Overall Threat Score**| 69 / 100 | Normalized risk index |
| **Sarcastic Roast** | &ldquo;The sysadmin clearly believes security through positive affirmations works.&rdquo; | Generated dynamically based on port severity |

### Map Integrity & Micro-Jittering

- **Coordinates Integrity**: Coordinates remained clustered tightly within Munich city limits ($48.1351^\circ\text{ N}, 11.5820^\circ\text{ E}$).
- **Micro-Jittering**: Bounded to $\pm 150$ meters ($\pm 0.0015^\circ$), eliminating overlapping marker occlusion while strictly preventing spurious displacement.
- **Tile Stability**: OpenStreetMap rendered without API key deprecation warnings or missing tile errors.
