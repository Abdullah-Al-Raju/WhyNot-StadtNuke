/* WhyNot-StadtNuke Tactical Frontend Controller
   Authored by: Abduallah Al Raju */

let map = null;
let markersGroup = null;
let currentDevices = [];
let ws = null;
let isScanning = false;

document.addEventListener("DOMContentLoaded", () => {
    initMap();
    initWebSocket();
    initUIEvents();
    fetchInitialStatus();
});

// Initialize Leaflet Map
function initMap() {
    // Default to Munich coordinates
    map = L.map("map", {
        zoomControl: true,
        attributionControl: false
    }).setView([48.1351, 11.5820], 12);

    // OpenStreetMap base layer
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        maxZoom: 19
    }).addTo(map);

    markersGroup = L.layerGroup().addTo(map);
}

// WebSocket Connection
function initWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        updateStatusPill(false);
    };

    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleWsMessage(msg);
        } catch (e) {
            console.error("WS Parse error", e);
        }
    };

    ws.onclose = () => {
        setTimeout(initWebSocket, 2000);
    };

    // Heartbeat ping
    setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send("ping");
        }
    }, 15000);
}

function handleWsMessage(msg) {
    if (msg.type === "init") {
        currentDevices = msg.devices || [];
        updateMetrics(msg.summary || {});
        renderDevices(currentDevices);
    } else if (msg.type === "scan_started") {
        isScanning = true;
        updateStatusPill(true);
        currentDevices = [];
        clearMap();
        document.getElementById("scan-progress-bar-container").classList.remove("hidden");
        document.getElementById("current-target-title").innerText = `${msg.data.target.toUpperCase()} CYBERSPACE RADAR`;
    } else if (msg.type === "scan_progress") {
        const pct = Math.round((msg.data.completed / msg.data.total) * 100);
        document.getElementById("scan-progress-fill").style.width = `${pct}%`;
        document.getElementById("progress-pct").innerText = `${pct}%`;
        document.getElementById("progress-ip-label").innerText = `Scanning: ${msg.data.ip}`;
    } else if (msg.type === "device_found") {
        currentDevices.unshift(msg.data);
        addDeviceToMap(msg.data);
        renderDevices(currentDevices);
    } else if (msg.type === "scan_finished" || msg.type === "demo_completed") {
        isScanning = false;
        updateStatusPill(false);
        document.getElementById("scan-progress-bar-container").classList.add("hidden");
        if (msg.type === "demo_completed") {
            currentDevices = msg.data.devices || [];
            updateMetrics(msg.data.summary || {});
            renderDevices(currentDevices);
            centerMapOnDevices(currentDevices);
        } else {
            updateMetrics(msg.data || {});
        }
    }
}

function updateStatusPill(scanning) {
    const pill = document.getElementById("engine-status");
    const label = document.getElementById("status-label");
    if (scanning) {
        pill.className = "status-pill status-scanning";
        label.innerText = "SURVEYING SUBNETS...";
    } else {
        pill.className = "status-pill status-online";
        label.innerText = "RADAR ONLINE";
    }
}

function initUIEvents() {
    // Quick chips
    document.querySelectorAll(".chip").forEach(chip => {
        chip.addEventListener("click", () => {
            const type = chip.getAttribute("data-type");
            const val = chip.getAttribute("data-val");
            document.getElementById("target-type").value = type;
            document.getElementById("target-input").value = val;
        });
    });

    // Start Live Scan
    document.getElementById("btn-start-scan").addEventListener("click", () => {
        if (isScanning) return;
        const targetType = document.getElementById("target-type").value;
        const target = document.getElementById("target-input").value.trim();
        const maxIps = parseInt(document.getElementById("sample-depth").value, 10);

        if (!target) return alert("Please specify a target.");

        fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target_type: targetType, target: target, max_ips: maxIps })
        }).catch(err => alert("Scan error: " + err));
    });

    // Start Demo Scan
    document.getElementById("btn-demo-scan").addEventListener("click", () => {
        if (isScanning) return;
        const target = document.getElementById("target-input").value.trim() || "Munich";
        fetch("/api/demo", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ city: target, count: 35, vuln_ratio: 0.35 })
        }).catch(err => alert("Demo error: " + err));
    });

    // Vulnerable filter
    document.getElementById("filter-vuln").addEventListener("change", () => {
        renderDevices(currentDevices);
    });

    // Export buttons
    document.getElementById("btn-export-json").addEventListener("click", () => {
        window.open("/api/export/json", "_blank");
    });
    document.getElementById("btn-export-map").addEventListener("click", () => {
        window.open("/api/map", "_blank");
    });
}

function fetchInitialStatus() {
    fetch("/api/status")
        .then(res => res.json())
        .then(data => {
            if (data.telemetry) {
                updateMetrics(data.telemetry);
            }
        });
}

function updateMetrics(summary) {
    document.getElementById("stat-total").innerText = summary.total_devices || 0;
    document.getElementById("stat-vuln").innerText = summary.vulnerable_count || 0;
    document.getElementById("stat-crit").innerText = summary.critical_count || 0;
    document.getElementById("stat-threat").innerText = `${summary.threat_score || 0}/100`;

    if (summary.last_roast) {
        document.getElementById("roast-text").innerHTML = `&ldquo;${summary.last_roast}&rdquo;`;
    }

    // Update severity bar
    const total = summary.total_devices || 1;
    const critPct = ((summary.critical_count || 0) / total) * 100;
    const highPct = ((summary.high_count || 0) / total) * 100;
    const medPct = ((summary.medium_count || 0) / total) * 100;
    const lowPct = ((summary.low_count || 0) / total) * 100;

    document.getElementById("bar-crit").style.width = `${critPct}%`;
    document.getElementById("bar-high").style.width = `${highPct}%`;
    document.getElementById("bar-med").style.width = `${medPct}%`;
    document.getElementById("bar-low").style.width = `${lowPct}%`;
}

function clearMap() {
    if (markersGroup) {
        markersGroup.clearLayers();
    }
}

function addDeviceToMap(dev) {
    if (!map || dev.lat == null || dev.lon == null) return;

    let color = "#10b981"; // green
    if (dev.risk_level === "Critical") color = "#b91c1c";
    else if (dev.risk_level === "High") color = "#ef4444";
    else if (dev.risk_level === "Medium") color = "#f59e0b";

    const circle = L.circleMarker([dev.lat, dev.lon], {
        radius: dev.vulns && dev.vulns.length > 0 ? 8 : 6,
        fillColor: color,
        color: "#ffffff",
        weight: 1.5,
        opacity: 0.9,
        fillOpacity: 0.8
    });

    const popupHtml = `
        <div style="font-family: sans-serif; font-size: 12px; line-height: 1.4;">
            <b>IP:</b> ${dev.ip}<br>
            <b>Risk:</b> <span style="color:${color}; font-weight:bold;">${dev.risk_level} (${dev.risk_score})</span><br>
            <b>Location:</b> ${dev.city || "Unknown"}, ${dev.country || ""}<br>
            <b>Ports:</b> ${(dev.ports || []).slice(0, 5).join(", ")}<br>
            <b>Exploits:</b> ${(dev.vulns && dev.vulns.length > 0) ? dev.vulns.join(", ") : "None"}<br>
            <i>${dev.roast || ""}</i>
        </div>
    `;

    circle.bindPopup(popupHtml);
    markersGroup.addLayer(circle);
}

function centerMapOnDevices(devices) {
    if (!map || devices.length === 0) return;
    const validCoords = devices.filter(d => d.lat != null && d.lon != null).map(d => [d.lat, d.lon]);
    if (validCoords.length > 0) {
        map.fitBounds(L.latLngBounds(validCoords), { padding: [40, 40], maxZoom: 13 });
    }
}

function renderDevices(devices) {
    const tbody = document.getElementById("devices-tbody");
    const vulnOnly = document.getElementById("filter-vuln").checked;

    clearMap();

    const filtered = vulnOnly ? devices.filter(d => d.vulns && d.vulns.length > 0) : devices;

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No matching endpoints found.</td></tr>`;
        return;
    }

    let rowsHtml = "";
    filtered.forEach(dev => {
        addDeviceToMap(dev);

        const portsHtml = (dev.ports || []).slice(0, 5).map(p => `<span class="port-pill">${p}</span>`).join("");
        const vulnsHtml = (dev.vulns && dev.vulns.length > 0)
            ? dev.vulns.slice(0, 3).map(v => `<span style="color:#ef4444; font-weight:600;">${v}</span>`).join(", ")
            : `<span style="color:#10b981;">Clean</span>`;

        let badgeClass = "badge-low";
        if (dev.risk_level === "Critical") badgeClass = "badge-critical";
        else if (dev.risk_level === "High") badgeClass = "badge-high";
        else if (dev.risk_level === "Medium") badgeClass = "badge-medium";

        rowsHtml += `
            <tr>
                <td style="font-family: monospace; font-weight: 700;">${dev.ip}</td>
                <td style="color: #94a3b8;">${(dev.hostnames && dev.hostnames[0]) || "unresolved"}</td>
                <td>${portsHtml}</td>
                <td><span class="badge-risk ${badgeClass}">${dev.risk_level}</span></td>
                <td>${vulnsHtml}</td>
                <td style="font-style: italic; color: #94a3b8; font-size: 11px;">${dev.roast || ""}</td>
            </tr>
        `;
    });

    tbody.innerHTML = rowsHtml;
}
