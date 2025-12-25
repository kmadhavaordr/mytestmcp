"""
Ordr MCP Server - With Auth Wrapper

Architecture:
1. FastAPI receives request on main port
2. Extracts JWT token from Authorization header
3. Calls Auth service to validate token
4. If valid, forwards request to internal FastMCP with customer context
5. Returns response to client

Environment Variables:
- PORT: External port (default: 8000)
- AUTH_SERVICE_URL: Auth validator URL
- TEST_MODE: "true" to allow requests without valid token
"""

import os
import asyncio
import logging
from datetime import datetime
from typing import Optional
from threading import Thread

import httpx
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ordr-mcp")

# =============================================================================
# CONFIGURATION
# =============================================================================

EXTERNAL_PORT = int(os.environ.get("PORT", 8000))
INTERNAL_MCP_PORT = 8001  # FastMCP runs here internally
AUTH_SERVICE_URL = os.environ.get("AUTH_SERVICE_URL", "https://mytestauth.onrender.com")
TEST_MODE = os.environ.get("TEST_MODE", "false").lower() == "true"

# Customer context - set by auth, read by tools
_customer_context = {}

def set_customer_context(ctx: dict):
    global _customer_context
    _customer_context = ctx
    logger.info(f"Customer context set: {ctx.get('customer_name')} / {ctx.get('user_email')}")

def get_customer_context() -> dict:
    if _customer_context:
        return _customer_context
    return {
        "customer_name": "Healthcare Corp (Default)",
        "data_set": "tenant-a",
        "user_email": "default@example.com",
        "customer_id": "default"
    }

# =============================================================================
# MOCK DATA
# =============================================================================

MOCK_DEVICES = {
    "tenant-a": [
        {
            "id": "dev-001",
            "hostname": "MRI-SCANNER-01",
            "ip_address": "192.168.1.50",
            "mac_address": "00:1A:2B:3C:4D:5E",
            "device_type": "Medical Device",
            "manufacturer": "GE Healthcare",
            "model": "SIGNA Premier",
            "os": "Linux 4.14",
            "risk_score": 85,
            "vulnerabilities": ["CVE-2024-1234", "CVE-2024-5678"],
            "last_seen": "2024-01-15T10:30:00Z",
            "location": "Building A - Radiology"
        },
        {
            "id": "dev-002",
            "hostname": "INFUSION-PUMP-12",
            "ip_address": "192.168.1.67",
            "mac_address": "00:1A:2B:3C:4D:6F",
            "device_type": "Medical Device",
            "manufacturer": "BD",
            "model": "Alaris 8015",
            "os": "Embedded",
            "risk_score": 72,
            "vulnerabilities": ["CVE-2024-9012"],
            "last_seen": "2024-01-15T10:28:00Z",
            "location": "Building B - ICU"
        },
        {
            "id": "dev-003",
            "hostname": "WORKSTATION-IT-05",
            "ip_address": "192.168.2.100",
            "mac_address": "00:1A:2B:3C:4D:7A",
            "device_type": "Workstation",
            "manufacturer": "Dell",
            "model": "OptiPlex 7090",
            "os": "Windows 11 Pro",
            "risk_score": 25,
            "vulnerabilities": [],
            "last_seen": "2024-01-15T10:35:00Z",
            "location": "Building A - IT Department"
        }
    ],
    "tenant-b": [
        {
            "id": "dev-101",
            "hostname": "PLC-ASSEMBLY-01",
            "ip_address": "10.0.1.50",
            "mac_address": "00:2B:3C:4D:5E:6F",
            "device_type": "Industrial Controller",
            "manufacturer": "Siemens",
            "model": "S7-1500",
            "os": "Firmware 2.9",
            "risk_score": 65,
            "vulnerabilities": ["CVE-2024-3333"],
            "last_seen": "2024-01-15T10:30:00Z",
            "location": "Factory Floor - Line 1"
        },
        {
            "id": "dev-102",
            "hostname": "HMI-PANEL-03",
            "ip_address": "10.0.1.55",
            "mac_address": "00:2B:3C:4D:5E:7A",
            "device_type": "HMI",
            "manufacturer": "Rockwell",
            "model": "PanelView Plus 7",
            "os": "Windows CE",
            "risk_score": 78,
            "vulnerabilities": ["CVE-2024-4444", "CVE-2024-5555"],
            "last_seen": "2024-01-15T10:32:00Z",
            "location": "Factory Floor - Line 1"
        }
    ]
}

MOCK_ALERTS = {
    "tenant-a": [
        {
            "id": "alert-001",
            "severity": "critical",
            "title": "Unpatched vulnerability detected",
            "description": "MRI-SCANNER-01 has critical vulnerability CVE-2024-1234",
            "device_id": "dev-001",
            "device_hostname": "MRI-SCANNER-01",
            "created_at": "2024-01-15T08:00:00Z",
            "status": "open"
        },
        {
            "id": "alert-002",
            "severity": "high",
            "title": "Anomalous network traffic",
            "description": "INFUSION-PUMP-12 communicating with unusual external IP",
            "device_id": "dev-002",
            "device_hostname": "INFUSION-PUMP-12",
            "created_at": "2024-01-15T09:15:00Z",
            "status": "investigating"
        },
        {
            "id": "alert-003",
            "severity": "medium",
            "title": "Outdated firmware",
            "description": "INFUSION-PUMP-12 running outdated firmware version",
            "device_id": "dev-002",
            "device_hostname": "INFUSION-PUMP-12",
            "created_at": "2024-01-14T14:00:00Z",
            "status": "open"
        }
    ],
    "tenant-b": [
        {
            "id": "alert-101",
            "severity": "high",
            "title": "PLC firmware vulnerability",
            "description": "PLC-ASSEMBLY-01 affected by CVE-2024-3333",
            "device_id": "dev-101",
            "device_hostname": "PLC-ASSEMBLY-01",
            "created_at": "2024-01-15T07:30:00Z",
            "status": "open"
        },
        {
            "id": "alert-102",
            "severity": "critical",
            "title": "Unauthorized access attempt",
            "description": "HMI-PANEL-03 detected unauthorized login attempt",
            "device_id": "dev-102",
            "device_hostname": "HMI-PANEL-03",
            "created_at": "2024-01-15T11:00:00Z",
            "status": "investigating"
        }
    ]
}

def get_devices() -> list:
    ctx = get_customer_context()
    return MOCK_DEVICES.get(ctx["data_set"], [])

def get_alerts() -> list:
    ctx = get_customer_context()
    return MOCK_ALERTS.get(ctx["data_set"], [])

# =============================================================================
# FASTMCP SERVER (runs internally)
# =============================================================================

mcp = FastMCP(
    name="ordr-mcp-server",
    instructions="""
    You are the Ordr Security Assistant. You help users query their organization's
    device inventory, security alerts, and network information.
    """
)

@mcp.tool()
def list_devices(
    device_type: Optional[str] = None,
    min_risk_score: Optional[int] = None,
    location: Optional[str] = None
) -> dict:
    """
    List devices in the network inventory.
    
    Args:
        device_type: Filter by device type (e.g., "Medical Device", "Workstation")
        min_risk_score: Only show devices with risk score >= this value
        location: Filter by location (partial match)
    """
    ctx = get_customer_context()
    devices = get_devices()
    
    if device_type:
        devices = [d for d in devices if d["device_type"].lower() == device_type.lower()]
    if min_risk_score is not None:
        devices = [d for d in devices if d["risk_score"] >= min_risk_score]
    if location:
        devices = [d for d in devices if location.lower() in d["location"].lower()]
    
    return {
        "customer": ctx["customer_name"],
        "user": ctx["user_email"],
        "total_count": len(devices),
        "devices": devices
    }


@mcp.tool()
def get_device_by_ip(ip_address: str) -> dict:
    """Get device details by IP address."""
    ctx = get_customer_context()
    for device in get_devices():
        if device["ip_address"] == ip_address:
            return {"found": True, "customer": ctx["customer_name"], "device": device}
    return {"found": False, "error": f"No device with IP {ip_address}"}


@mcp.tool()
def get_device_by_hostname(hostname: str) -> dict:
    """Get device details by hostname (case-insensitive)."""
    ctx = get_customer_context()
    for device in get_devices():
        if device["hostname"].lower() == hostname.lower():
            return {"found": True, "customer": ctx["customer_name"], "device": device}
    return {"found": False, "error": f"No device with hostname {hostname}"}


@mcp.tool()
def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    device_hostname: Optional[str] = None
) -> dict:
    """
    List security alerts.
    
    Args:
        severity: Filter by severity (critical, high, medium, low)
        status: Filter by status (open, investigating, resolved)
        device_hostname: Filter by device hostname
    """
    ctx = get_customer_context()
    alerts = get_alerts()
    
    if severity:
        alerts = [a for a in alerts if a["severity"].lower() == severity.lower()]
    if status:
        alerts = [a for a in alerts if a["status"].lower() == status.lower()]
    if device_hostname:
        alerts = [a for a in alerts if device_hostname.lower() in a["device_hostname"].lower()]
    
    severity_counts = {}
    for alert in alerts:
        sev = alert["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    return {
        "customer": ctx["customer_name"],
        "user": ctx["user_email"],
        "total_count": len(alerts),
        "by_severity": severity_counts,
        "alerts": alerts
    }


@mcp.tool()
def get_high_risk_devices(threshold: int = 70) -> dict:
    """Get devices with risk score >= threshold (default 70)."""
    ctx = get_customer_context()
    devices = [d for d in get_devices() if d["risk_score"] >= threshold]
    devices.sort(key=lambda x: x["risk_score"], reverse=True)
    
    return {
        "customer": ctx["customer_name"],
        "threshold": threshold,
        "count": len(devices),
        "devices": devices
    }


@mcp.tool()
def get_network_summary() -> dict:
    """Get network inventory and security summary."""
    ctx = get_customer_context()
    devices = get_devices()
    alerts = get_alerts()
    
    device_types = {}
    for d in devices:
        dt = d["device_type"]
        device_types[dt] = device_types.get(dt, 0) + 1
    
    risk_levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for d in devices:
        score = d["risk_score"]
        if score >= 80: risk_levels["critical"] += 1
        elif score >= 60: risk_levels["high"] += 1
        elif score >= 40: risk_levels["medium"] += 1
        else: risk_levels["low"] += 1
    
    alert_severity = {}
    open_alerts = 0
    for a in alerts:
        alert_severity[a["severity"]] = alert_severity.get(a["severity"], 0) + 1
        if a["status"] != "resolved": open_alerts += 1
    
    avg_risk = sum(d["risk_score"] for d in devices) / len(devices) if devices else 0
    
    return {
        "customer": ctx["customer_name"],
        "user": ctx["user_email"],
        "summary": {
            "total_devices": len(devices),
            "device_types": device_types,
            "average_risk_score": round(avg_risk, 1),
            "risk_distribution": risk_levels,
            "total_alerts": len(alerts),
            "open_alerts": open_alerts,
            "alerts_by_severity": alert_severity
        },
        "generated_at": datetime.utcnow().isoformat() + "Z"
    }


@mcp.tool()
def whoami() -> dict:
    """Show current user and customer context."""
    ctx = get_customer_context()
    return {
        "user_email": ctx["user_email"],
        "customer_id": ctx["customer_id"],
        "customer_name": ctx["customer_name"],
        "data_set": ctx["data_set"],
        "auth_validated": ctx.get("auth_validated", False),
        "message": f"You are {ctx['user_email']} from {ctx['customer_name']}"
    }


# =============================================================================
# FASTAPI WRAPPER (handles auth, proxies to FastMCP)
# =============================================================================

app = FastAPI(title="Ordr MCP Gateway")

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "ordr-mcp-gateway",
        "auth_service": AUTH_SERVICE_URL,
        "test_mode": TEST_MODE,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


async def validate_token(authorization: str) -> dict:
    """Call auth service to validate token."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(
                f"{AUTH_SERVICE_URL}/auth",
                headers={"Authorization": authorization}
            )
            
            if response.status_code == 401:
                raise HTTPException(status_code=401, detail="Invalid or expired token")
            if response.status_code == 403:
                raise HTTPException(status_code=403, detail="User not authorized")
            if response.status_code != 200:
                raise HTTPException(status_code=502, detail=f"Auth service error: {response.status_code}")
            
            return {
                "customer_name": response.headers.get("X-Customer-Name", "Unknown"),
                "data_set": response.headers.get("X-Data-Set", "tenant-a"),
                "user_email": response.headers.get("X-User-Email", "unknown"),
                "customer_id": response.headers.get("X-Customer-Id", "unknown"),
                "auth_validated": True
            }
        except httpx.RequestError as e:
            logger.error(f"Auth service error: {e}")
            raise HTTPException(status_code=502, detail=f"Auth service unreachable")


@app.api_route("/mcp/{path:path}", methods=["GET", "POST", "DELETE"])
async def mcp_proxy(request: Request, path: str = ""):
    """
    Auth gateway for MCP requests.
    1. Validate token with auth service
    2. Set customer context
    3. Forward to internal FastMCP
    """
    # Get authorization header
    authorization = request.headers.get("Authorization", "")
    
    # Validate with auth service
    if authorization:
        try:
            customer_ctx = await validate_token(authorization)
            set_customer_context(customer_ctx)
            logger.info(f"✅ Auth OK: {customer_ctx['user_email']} → {customer_ctx['customer_name']}")
        except HTTPException as e:
            if TEST_MODE:
                logger.warning(f"⚠️ Auth failed but TEST_MODE enabled: {e.detail}")
                set_customer_context({
                    "customer_name": "Healthcare Corp (TEST_MODE)",
                    "data_set": "tenant-a",
                    "user_email": "test@example.com",
                    "customer_id": "test",
                    "auth_validated": False
                })
            else:
                raise e
    elif TEST_MODE:
        logger.warning("⚠️ No auth header, using TEST_MODE defaults")
        set_customer_context({
            "customer_name": "Healthcare Corp (TEST_MODE)",
            "data_set": "tenant-a",
            "user_email": "test@example.com",
            "customer_id": "test",
            "auth_validated": False
        })
    else:
        raise HTTPException(status_code=401, detail="No Authorization header")
    
    # Forward to internal FastMCP
    mcp_url = f"http://127.0.0.1:{INTERNAL_MCP_PORT}/mcp/{path}"
    
    body = await request.body()
    
    # Build headers (pass through most headers)
    forward_headers = {}
    for key, value in request.headers.items():
        if key.lower() not in ["host", "content-length"]:
            forward_headers[key] = value
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.request(
                method=request.method,
                url=mcp_url,
                headers=forward_headers,
                content=body,
            )
            
            # Return response
            return StreamingResponse(
                content=response.iter_bytes(),
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type")
            )
        except httpx.RequestError as e:
            logger.error(f"MCP forward error: {e}")
            raise HTTPException(status_code=502, detail="MCP service error")


# =============================================================================
# STARTUP - Run both FastMCP and FastAPI
# =============================================================================

def run_fastmcp():
    """Run FastMCP on internal port."""
    logger.info(f"Starting internal FastMCP on port {INTERNAL_MCP_PORT}")
    mcp.run(transport="streamable-http", host="127.0.0.1", port=INTERNAL_MCP_PORT)


if __name__ == "__main__":
    # Start FastMCP in background thread
    mcp_thread = Thread(target=run_fastmcp, daemon=True)
    mcp_thread.start()
    
    # Give FastMCP time to start
    import time
    time.sleep(2)
    
    # Start FastAPI on external port
    logger.info(f"Starting FastAPI gateway on port {EXTERNAL_PORT}")
    logger.info(f"Auth Service: {AUTH_SERVICE_URL}")
    logger.info(f"Test Mode: {TEST_MODE}")
    
    uvicorn.run(app, host="0.0.0.0", port=EXTERNAL_PORT)
