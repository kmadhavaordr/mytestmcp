"""
Ordr MCP Server - Streamable HTTP with Auth

Properly implements MCP streamable-http transport.
Copilot Studio sends POST requests and expects SSE responses.

Environment Variables:
- PORT: Port to run on (default: 8000)
- AUTH_SERVICE_URL: Auth validator URL  
- TEST_MODE: "true" to allow requests without valid token
"""

import os
import json
import logging
from datetime import datetime
from typing import Optional
import asyncio

import httpx
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ordr-mcp")

# =============================================================================
# CONFIGURATION
# =============================================================================

PORT = int(os.environ.get("PORT", 8000))
AUTH_SERVICE_URL = os.environ.get("AUTH_SERVICE_URL", "https://mytestauth.onrender.com")
TEST_MODE = os.environ.get("TEST_MODE", "false").lower() == "true"

# Customer context
_customer_context = {}

def set_customer_context(ctx: dict):
    global _customer_context
    _customer_context = ctx

def get_customer_context() -> dict:
    if _customer_context:
        return _customer_context
    return {
        "customer_name": "Healthcare Corp (Default)",
        "data_set": "tenant-a",
        "user_email": "default@example.com",
        "customer_id": "default",
        "auth_validated": False
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
    return MOCK_DEVICES.get(get_customer_context()["data_set"], [])

def get_alerts() -> list:
    return MOCK_ALERTS.get(get_customer_context()["data_set"], [])

# =============================================================================
# TOOLS
# =============================================================================

def tool_list_devices(args: dict) -> dict:
    ctx = get_customer_context()
    devices = get_devices()
    
    if args.get("device_type"):
        devices = [d for d in devices if d["device_type"].lower() == args["device_type"].lower()]
    if args.get("min_risk_score") is not None:
        devices = [d for d in devices if d["risk_score"] >= args["min_risk_score"]]
    if args.get("location"):
        devices = [d for d in devices if args["location"].lower() in d["location"].lower()]
    
    return {"customer": ctx["customer_name"], "user": ctx["user_email"], "total_count": len(devices), "devices": devices}

def tool_get_device_by_ip(args: dict) -> dict:
    ctx = get_customer_context()
    for device in get_devices():
        if device["ip_address"] == args.get("ip_address", ""):
            return {"found": True, "customer": ctx["customer_name"], "device": device}
    return {"found": False, "error": f"No device with IP {args.get('ip_address')}"}

def tool_get_device_by_hostname(args: dict) -> dict:
    ctx = get_customer_context()
    for device in get_devices():
        if device["hostname"].lower() == args.get("hostname", "").lower():
            return {"found": True, "customer": ctx["customer_name"], "device": device}
    return {"found": False, "error": f"No device with hostname {args.get('hostname')}"}

def tool_list_alerts(args: dict) -> dict:
    ctx = get_customer_context()
    alerts = get_alerts()
    
    if args.get("severity"):
        alerts = [a for a in alerts if a["severity"].lower() == args["severity"].lower()]
    if args.get("status"):
        alerts = [a for a in alerts if a["status"].lower() == args["status"].lower()]
    
    return {"customer": ctx["customer_name"], "user": ctx["user_email"], "total_count": len(alerts), "alerts": alerts}

def tool_get_high_risk_devices(args: dict) -> dict:
    ctx = get_customer_context()
    threshold = args.get("threshold", 70)
    devices = sorted([d for d in get_devices() if d["risk_score"] >= threshold], key=lambda x: x["risk_score"], reverse=True)
    return {"customer": ctx["customer_name"], "threshold": threshold, "count": len(devices), "devices": devices}

def tool_get_network_summary(args: dict) -> dict:
    ctx = get_customer_context()
    devices = get_devices()
    alerts = get_alerts()
    
    device_types = {}
    for d in devices:
        device_types[d["device_type"]] = device_types.get(d["device_type"], 0) + 1
    
    avg_risk = sum(d["risk_score"] for d in devices) / len(devices) if devices else 0
    
    return {
        "customer": ctx["customer_name"],
        "user": ctx["user_email"],
        "summary": {
            "total_devices": len(devices),
            "device_types": device_types,
            "average_risk_score": round(avg_risk, 1),
            "total_alerts": len(alerts),
            "open_alerts": len([a for a in alerts if a["status"] != "resolved"])
        }
    }

def tool_whoami(args: dict) -> dict:
    ctx = get_customer_context()
    return {
        "user_email": ctx["user_email"],
        "customer_id": ctx["customer_id"],
        "customer_name": ctx["customer_name"],
        "data_set": ctx["data_set"],
        "auth_validated": ctx.get("auth_validated", False),
        "message": f"You are {ctx['user_email']} from {ctx['customer_name']}"
    }

TOOLS = {
    "list_devices": {"fn": tool_list_devices, "desc": "List devices in the network inventory", "schema": {"type": "object", "properties": {"device_type": {"type": "string"}, "min_risk_score": {"type": "integer"}, "location": {"type": "string"}}}},
    "get_device_by_ip": {"fn": tool_get_device_by_ip, "desc": "Get device details by IP address", "schema": {"type": "object", "properties": {"ip_address": {"type": "string"}}, "required": ["ip_address"]}},
    "get_device_by_hostname": {"fn": tool_get_device_by_hostname, "desc": "Get device details by hostname", "schema": {"type": "object", "properties": {"hostname": {"type": "string"}}, "required": ["hostname"]}},
    "list_alerts": {"fn": tool_list_alerts, "desc": "List security alerts", "schema": {"type": "object", "properties": {"severity": {"type": "string"}, "status": {"type": "string"}}}},
    "get_high_risk_devices": {"fn": tool_get_high_risk_devices, "desc": "Get devices with high risk scores", "schema": {"type": "object", "properties": {"threshold": {"type": "integer"}}}},
    "get_network_summary": {"fn": tool_get_network_summary, "desc": "Get network inventory and security summary", "schema": {"type": "object", "properties": {}}},
    "whoami": {"fn": tool_whoami, "desc": "Show current user and customer context", "schema": {"type": "object", "properties": {}}}
}

# =============================================================================
# AUTH
# =============================================================================

async def validate_token(authorization: str) -> dict:
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(f"{AUTH_SERVICE_URL}/auth", headers={"Authorization": authorization})
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Auth failed")
            return {
                "customer_name": response.headers.get("X-Customer-Name", "Unknown"),
                "data_set": response.headers.get("X-Data-Set", "tenant-a"),
                "user_email": response.headers.get("X-User-Email", "unknown"),
                "customer_id": response.headers.get("X-Customer-Id", "unknown"),
                "auth_validated": True
            }
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Auth service error: {e}")

# =============================================================================
# MCP PROTOCOL
# =============================================================================

def handle_request(method: str, params: dict, req_id) -> dict:
    """Handle MCP JSON-RPC request."""
    
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "ordr-mcp-server", "version": "1.0.0"},
                "capabilities": {"tools": {"listChanged": False}}
            }
        }
    
    if method == "tools/list":
        tools_list = [{"name": n, "description": t["desc"], "inputSchema": t["schema"]} for n, t in TOOLS.items()]
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools_list}}
    
    if method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})
        
        if tool_name not in TOOLS:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}}
        
        try:
            result = TOOLS[tool_name]["fn"](tool_args)
            return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}}
    
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    
    if method.startswith("notifications/"):
        return None  # No response for notifications
    
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}}

# =============================================================================
# FASTAPI
# =============================================================================

app = FastAPI(title="Ordr MCP Server")

@app.get("/health")
def health():
    return {"status": "healthy", "service": "ordr-mcp", "auth_service": AUTH_SERVICE_URL, "test_mode": TEST_MODE}

@app.post("/mcp")
async def mcp_post(request: Request):
    """Handle MCP POST requests."""
    
    # Auth
    authorization = request.headers.get("Authorization", "")
    if authorization:
        try:
            ctx = await validate_token(authorization)
            set_customer_context(ctx)
            logger.info(f"✅ Auth: {ctx['user_email']} → {ctx['customer_name']}")
        except HTTPException:
            if TEST_MODE:
                set_customer_context({"customer_name": "Healthcare Corp (TEST)", "data_set": "tenant-a", "user_email": "test@test.com", "customer_id": "test", "auth_validated": False})
            else:
                raise
    elif TEST_MODE:
        set_customer_context({"customer_name": "Healthcare Corp (TEST)", "data_set": "tenant-a", "user_email": "test@test.com", "customer_id": "test", "auth_validated": False})
    else:
        raise HTTPException(status_code=401, detail="No auth")
    
    # Parse body
    try:
        body = await request.json()
    except:
        return JSONResponse({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None})
    
    # Handle request(s)
    if isinstance(body, list):
        responses = []
        for req in body:
            resp = handle_request(req.get("method", ""), req.get("params", {}), req.get("id"))
            if resp:
                responses.append(resp)
        return JSONResponse(responses)
    else:
        resp = handle_request(body.get("method", ""), body.get("params", {}), body.get("id"))
        return JSONResponse(resp if resp else {})

@app.get("/mcp")
async def mcp_get(request: Request):
    """Handle MCP GET requests (SSE endpoint)."""
    return JSONResponse({"error": "Use POST for MCP requests"})

@app.delete("/mcp")
async def mcp_delete(request: Request):
    """Handle session termination."""
    return JSONResponse({"jsonrpc": "2.0", "result": {}})

if __name__ == "__main__":
    logger.info(f"Starting Ordr MCP Server on port {PORT}")
    logger.info(f"Auth: {AUTH_SERVICE_URL}, TEST_MODE: {TEST_MODE}")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
