"""WhyNot-StadtNuke Web Application Backend.

Provides a FastAPI server with REST endpoints and WebSockets for real-time
cybersecurity attack surface discovery, interactive Leaflet mapping, and telemetry.
Authored by: Abduallah Al Raju
"""

import asyncio
from contextlib import asynccontextmanager
import json
import os
import threading
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import stadtnuke_core as core
import stadtnuke_map as smap

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")

# Global in-memory scan state
scan_lock = threading.Lock()
current_devices: List[Dict[str, Any]] = []
active_scan_job: Optional[threading.Thread] = None
is_scanning: bool = False
last_target_name: str = "Munich"
last_roast: str = "Ready to inspect attack surface."
engine = core.CensusEngine()

# WebSockets registry
active_connections: List[WebSocket] = []
event_loop: Optional[asyncio.AbstractEventLoop] = None


def broadcast_event(event: Dict[str, Any]) -> None:
    global event_loop
    if event_loop and event_loop.is_running():
        asyncio.run_coroutine_threadsafe(_async_broadcast(event), event_loop)


async def _async_broadcast(event: Dict[str, Any]) -> None:
    for ws in list(active_connections):
        try:
            await ws.send_json(event)
        except Exception:
            if ws in active_connections:
                active_connections.remove(ws)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global event_loop
    event_loop = asyncio.get_running_loop()
    yield


app = FastAPI(
    title="WhyNot-StadtNuke Visual Census & Attack Surface Radar",
    description="Worldwide Network Census & Sarcastic Vulnerability Radar by Abduallah Al Raju",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target_type: str = "city"  # "city", "country", "asn", "cidr"
    target: str = "Munich"
    max_ips: int = 50
    concurrency: int = 15


class DemoRequest(BaseModel):
    city: str = "Munich"
    count: int = 35
    vuln_ratio: float = 0.35


def compute_telemetry_summary() -> Dict[str, Any]:
    with scan_lock:
        devs = list(current_devices)

    total = len(devs)
    vuln_count = sum(1 for d in devs if d.get("vulns"))
    crit_count = sum(1 for d in devs if d.get("risk_level") == "Critical")
    high_count = sum(1 for d in devs if d.get("risk_level") == "High")
    med_count = sum(1 for d in devs if d.get("risk_level") == "Medium")
    low_count = sum(1 for d in devs if d.get("risk_level") == "Low")

    # Threat score calculation
    if total > 0:
        avg_score = round(sum(d.get("risk_score", 0) for d in devs) / total)
    else:
        avg_score = 0

    # Top exposed ports
    port_freq: Dict[int, int] = {}
    for d in devs:
        for p in d.get("ports", []):
            port_freq[p] = port_freq.get(p, 0) + 1

    sorted_ports = sorted(port_freq.items(), key=lambda x: x[1], reverse=True)[:8]

    return {
        "total_devices": total,
        "vulnerable_count": vuln_count,
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "threat_score": avg_score,
        "top_ports": [{"port": p, "count": c} for p, c in sorted_ports],
        "last_roast": last_roast,
        "target": last_target_name,
        "is_scanning": is_scanning,
    }


# REST Endpoints
@app.get("/api/status")
def get_status():
    subnets_db = core.load_subnets_db()
    available_cities = list(subnets_db.get("cities", {}).keys())
    available_countries = [c.get("name") for c in subnets_db.get("countries", {}).values()]

    return {
        "status": "online",
        "engine_version": "2.0.0",
        "author": "Abduallah Al Raju",
        "is_scanning": is_scanning,
        "available_cities": available_cities,
        "available_countries": available_countries,
        "telemetry": compute_telemetry_summary(),
    }


@app.get("/api/devices")
def get_devices(
    vulnerable_only: bool = Query(False),
    min_risk: int = Query(0),
    port: Optional[int] = Query(None),
):
    with scan_lock:
        results = list(current_devices)

    if vulnerable_only:
        results = [d for d in results if d.get("vulns")]
    if min_risk > 0:
        results = [d for d in results if d.get("risk_score", 0) >= min_risk]
    if port is not None:
        results = [d for d in results if port in d.get("ports", [])]

    return {"devices": results, "count": len(results)}


@app.post("/api/scan")
def trigger_scan(req: ScanRequest):
    global is_scanning, active_scan_job, last_target_name, last_roast

    with scan_lock:
        if is_scanning:
            return JSONResponse(status_code=409, content={"error": "A scan is already in progress."})
        is_scanning = True
        current_devices.clear()
        last_target_name = req.target

    broadcast_event({"type": "scan_started", "data": {"target": req.target, "type": req.target_type}})

    def run_scan_thread():
        global is_scanning, last_roast
        try:
            resolver = core.TargetResolver()
            target_spec = resolver.resolve(
                city=req.target if req.target_type == "city" else None,
                country=req.target if req.target_type == "country" else None,
                asn=req.target if req.target_type == "asn" else None,
                cidr=req.target if req.target_type == "cidr" else None,
            )

            def on_dev(record: core.DeviceRecord):
                with scan_lock:
                    current_devices.append(record.to_dict())
                broadcast_event({"type": "device_found", "data": record.to_dict()})

            def on_prog(done: int, total: int, ip: str):
                broadcast_event({"type": "scan_progress", "data": {"completed": done, "total": total, "ip": ip}})

            engine.scan_target(
                target_spec,
                max_ips_per_prefix=req.max_ips,
                on_device=on_dev,
                on_progress=on_prog,
            )

            # Generate roast
            with scan_lock:
                devs = list(current_devices)
            vuln_c = sum(1 for d in devs if d.get("vulns"))
            crit_c = sum(1 for d in devs if d.get("risk_level") == "Critical")
            last_roast = engine.scorer.generate_overall_roast(len(devs), vuln_c, crit_c)

        except Exception as exc:
            last_roast = f"Scan execution error: {exc}"
        finally:
            is_scanning = False
            broadcast_event({"type": "scan_finished", "data": compute_telemetry_summary()})

    active_scan_job = threading.Thread(target=run_scan_thread, daemon=True)
    active_scan_job.start()

    return {"status": "started", "target": req.target}


@app.post("/api/demo")
def trigger_demo(req: DemoRequest):
    global is_scanning, last_target_name, last_roast

    with scan_lock:
        if is_scanning:
            return JSONResponse(status_code=409, content={"error": "A scan is currently running."})
        current_devices.clear()
        last_target_name = req.city

    resolver = core.TargetResolver()
    target_spec = resolver.resolve(city=req.city)
    simulated = engine.run_simulation(target_spec, count=req.count, vuln_ratio=req.vuln_ratio)

    with scan_lock:
        for rec in simulated:
            current_devices.append(rec.to_dict())
        devs = list(current_devices)

    vuln_c = sum(1 for d in devs if d.get("vulns"))
    crit_c = sum(1 for d in devs if d.get("risk_level") == "Critical")
    last_roast = engine.scorer.generate_overall_roast(len(devs), vuln_c, crit_c)

    summary = compute_telemetry_summary()
    broadcast_event({"type": "demo_completed", "data": {"devices": current_devices, "summary": summary}})

    return {"status": "demo_completed", "summary": summary, "count": len(current_devices)}


@app.get("/api/map")
def export_map():
    with scan_lock:
        devs = list(current_devices)

    if not devs:
        return JSONResponse(status_code=400, content={"error": "No devices available to map. Run a scan first."})

    out_file = os.path.join(BASE_DIR, f"{last_target_name.replace(' ', '_')}_map.html")
    smap.render_map(devs, title=f"StadtNuke Attack Surface - {last_target_name}", output_file=out_file)
    return FileResponse(out_file, media_type="text/html", filename=os.path.basename(out_file))


@app.get("/api/export/json")
def export_json():
    with scan_lock:
        devs = list(current_devices)

    out_file = os.path.join(BASE_DIR, f"{last_target_name.replace(' ', '_')}_devices.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(devs, f, indent=2)

    return FileResponse(out_file, media_type="application/json", filename=os.path.basename(out_file))


# WebSocket Endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        # Send initial snapshot
        with scan_lock:
            snapshot = list(current_devices)
        await websocket.send_json(
            {
                "type": "init",
                "devices": snapshot,
                "summary": compute_telemetry_summary(),
            }
        )

        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)
    except Exception:
        if websocket in active_connections:
            active_connections.remove(websocket)


# Static File Serving
if os.path.exists(WEB_DIR):
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/")
    def index():
        return FileResponse(os.path.join(WEB_DIR, "index.html"))
