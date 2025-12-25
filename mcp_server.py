"""
Ordr MCP Server - With JWT Authentication

A FastMCP server that exposes device and alert tools for Copilot integration.
Includes JWT validation for Azure AD tokens.

Environment Variables:
- PORT: Port to run on (default: 8000)
- AZURE_CLIENT_ID: Your App Registration Client ID
- TEST_MODE: Set to "true" to skip auth (default: false)
"""

import os
import logging
from datetime import datetime
from typing import Optional
from functools import lru_cache
import httpx
import jwt
from jwt import PyJWKClient
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

# Azure AD Configuration
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "d63e5ccd-bd26-4b10-91b7-2dd7052577cb")
AZURE_JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
AZURE_ISSUER_PREFIX = "https://login.microsoftonline.com/"

# Test mode (skip auth for local testing)
TEST_MODE = os.environ.get("TEST_MODE", "false").lower() == "true"

# Default tenant for test mode
DEFAULT_TENANT = os.environ.get("X_TENANT_ID", "tenant-a")
DEFAULT_USER = os.environ.get("X_USER_EMAIL", "testuser@example.com")
DEFAULT_OID = os.environ.get("X_USER_OID", "test-oid-123")

# =============================================================================
# JWT VALIDATION
# =============================================================================

# Cache the JWKS client (refreshes keys automatically)
@lru_cache(maxsize=1)
def get_jwks_client():
    """Get cached JWKS client for Microsoft's public keys."""
    return PyJWKClient(AZURE_JWKS_URL, cache_keys=True, lifespan=3600)


def validate_token(token: str) -> dict:
    """
    Validate a JWT token from Azure AD.
    
    Returns:
        dict with tenant_id, user_email, user_oid, user_name
    
    Raises:
        Exception if validation fails
    """
    try:
        # Get the signing key from Microsoft's JWKS
        jwks_client = get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        # Decode and validate the token
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=AZURE_CLIENT_ID,
            options={
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": False,  # We'll check issuer manually for multitenant
            }
        )
        
        # Verify issuer is from Microsoft (multitenant)
        issuer = payload.get("iss", "")
        if not issuer.startswith(AZURE_ISSUER_PREFIX):
            raise ValueError(f"Invalid issuer: {issuer}")
        
        # Extract claims
        tenant_id = payload.get("tid")
        user_email = payload.get("preferred_username") or payload.get("email") or payload.get("upn", "unknown")
        user_oid = payload.get("oid", "unknown")
        user_name = payload.get("name", "unknown")
        
        if not tenant_id:
            raise ValueError("Token missing tenant ID (tid claim)")
        
        logger.info(f"Token validated: tenant={tenant_id}, user={user_email}")
        
        return {
            "tenant_id": tenant_id,
            "user_email": user_email,
            "user_oid": user_oid,
            "user_name": user_name
        }
        
    except jwt.ExpiredSignatureError:
        logger.error("Token has expired")
        raise ValueError("Token has expired")
    except jwt.InvalidAudienceError:
        logger.error(f"Invalid audience. Expected: {AZURE_CLIENT_ID}")
        raise ValueError("Token has invalid audience")
    except Exception as e:
        logger.error(f"Token validation failed: {e}")
        raise ValueError(f"Token validation failed: {e}")


# =============================================================================
# TENANT CONTEXT (Global - set per request)
# =============================================================================

# These will be set by the auth middleware before each tool call
_current_tenant_id = DEFAULT_TENANT
_current_user_email = DEFAULT_USER
_current_user_oid = DEFAULT_OID


def get_tenant_context() -> tuple[str, str, str]:
    """Get current tenant context."""
    return _current_tenant_id, _current_user_email, _current_user_oid


def set_tenant_context(tenant_id: str, user_email: str, user_oid: str):
    """Set tenant context from validated token."""
    global _current_tenant_id, _current_user_email, _current_user_oid
    _current_tenant_id = tenant_id
    _current_user_email = user_email
    _current_user_oid = user_oid


# =============================================================================
# TENANT REGISTRY (Maps Azure tenant IDs to data sources)
# =============================================================================

# In production, this would be loaded from a database or config file
TENANT_REGISTRY = {
    # Format: "azure-tenant-id": {"name": "Customer Name", "data_source": "..."}
    # Add your test tenant here after first login
}


def get_tenant_name(azure_tenant_id: str) -> str:
    """Get friendly tenant name from Azure tenant ID."""
    tenant_info = TENANT_REGISTRY.get(azure_tenant_id)
    if tenant_info:
        return tenant_info.get("name", azure_tenant_id)
    return azure_tenant_id  # Return raw ID if not registered


# =============================================================================
# MOCK DATA (Organized by Azure Tenant ID)
# =============================================================================

# Default mock data for any tenant (for testing)
DEFAULT_DEVICES = [
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
]

DEFAULT_ALERTS = [
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
]

# Per-tenant mock data (add more tenants as needed)
MOCK_DEVICES_BY_TENANT = {
    # "azure-tenant-id-here": [...devices...],
}

MOCK_ALERTS_BY_TENANT = {
    # "azure-tenant-id-here": [...alerts...],
}


def get_devices_for_tenant(tenant_id: str) -> list[dict]:
    """Get devices for a specific tenant."""
    # Check if tenant has specific data
    if tenant_id in MOCK_DEVICES_BY_TENANT:
        return MOCK_DEVICES_BY_TENANT[tenant_id]
    # Return default mock data for any tenant (testing)
    return DEFAULT_DEVICES


def get_alerts_for_tenant(tenant_id: str) -> list[dict]:
    """Get alerts for a specific tenant."""
    if tenant_id in MOCK_ALERTS_BY_TENANT:
        return MOCK_ALERTS_BY_TENANT[tenant_id]
    return DEFAULT_ALERTS


# =============================================================================
# FASTMCP SERVER
# =============================================================================

mcp = FastMCP(
    name="ordr-mcp-server",
    instructions="""
    You are the Ordr Security Assistant. You help users query their organization's
    device inventory, security alerts, and network information.
    
    Available capabilities:
    - List and search devices on the network
    - View security alerts and vulnerabilities
    - Get device details by IP or hostname
    
    Always be helpful and provide clear, actionable information.
    """
)


# =============================================================================
# MCP TOOLS
# =============================================================================

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
    
    Returns:
        Dictionary containing list of devices and count
    """
    tenant_id, user_email, _ = get_tenant_context()
    logger.info(f"list_devices called by {user_email} for tenant {tenant_id}")
    
    devices = get_devices_for_tenant(tenant_id)
    
    # Apply filters
    if device_type:
        devices = [d for d in devices if d["device_type"].lower() == device_type.lower()]
    
    if min_risk_score is not None:
        devices = [d for d in devices if d["risk_score"] >= min_risk_score]
    
    if location:
        devices = [d for d in devices if location.lower() in d["location"].lower()]
    
    return {
        "tenant": get_tenant_name(tenant_id),
        "total_count": len(devices),
        "devices": devices
    }


@mcp.tool()
def get_device_by_ip(ip_address: str) -> dict:
    """
    Get detailed information about a device by its IP address.
    
    Args:
        ip_address: The IP address of the device to look up
    
    Returns:
        Device details or error if not found
    """
    tenant_id, user_email, _ = get_tenant_context()
    logger.info(f"get_device_by_ip({ip_address}) called by {user_email}")
    
    devices = get_devices_for_tenant(tenant_id)
    
    for device in devices:
        if device["ip_address"] == ip_address:
            return {"found": True, "device": device}
    
    return {
        "found": False,
        "error": f"No device found with IP address {ip_address}",
        "suggestion": "Use list_devices to see all available devices"
    }


@mcp.tool()
def get_device_by_hostname(hostname: str) -> dict:
    """
    Get detailed information about a device by its hostname.
    
    Args:
        hostname: The hostname of the device to look up (case-insensitive)
    
    Returns:
        Device details or error if not found
    """
    tenant_id, user_email, _ = get_tenant_context()
    logger.info(f"get_device_by_hostname({hostname}) called by {user_email}")
    
    devices = get_devices_for_tenant(tenant_id)
    
    for device in devices:
        if device["hostname"].lower() == hostname.lower():
            return {"found": True, "device": device}
    
    return {
        "found": False,
        "error": f"No device found with hostname {hostname}",
        "suggestion": "Use list_devices to see all available devices"
    }


@mcp.tool()
def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    device_hostname: Optional[str] = None
) -> dict:
    """
    List security alerts.
    
    Args:
        severity: Filter by severity ("critical", "high", "medium", "low")
        status: Filter by status ("open", "investigating", "resolved")
        device_hostname: Filter by device hostname
    
    Returns:
        Dictionary containing list of alerts and counts by severity
    """
    tenant_id, user_email, _ = get_tenant_context()
    logger.info(f"list_alerts called by {user_email} for tenant {tenant_id}")
    
    alerts = get_alerts_for_tenant(tenant_id)
    
    # Apply filters
    if severity:
        alerts = [a for a in alerts if a["severity"].lower() == severity.lower()]
    
    if status:
        alerts = [a for a in alerts if a["status"].lower() == status.lower()]
    
    if device_hostname:
        alerts = [a for a in alerts if device_hostname.lower() in a["device_hostname"].lower()]
    
    # Count by severity
    severity_counts = {}
    for alert in alerts:
        sev = alert["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    return {
        "tenant": get_tenant_name(tenant_id),
        "total_count": len(alerts),
        "by_severity": severity_counts,
        "alerts": alerts
    }


@mcp.tool()
def get_high_risk_devices(threshold: int = 70) -> dict:
    """
    Get devices with high risk scores that need attention.
    
    Args:
        threshold: Risk score threshold (default 70). Returns devices >= this score.
    
    Returns:
        Dictionary containing high-risk devices sorted by risk score
    """
    tenant_id, user_email, _ = get_tenant_context()
    logger.info(f"get_high_risk_devices(threshold={threshold}) called by {user_email}")
    
    devices = get_devices_for_tenant(tenant_id)
    
    high_risk = [d for d in devices if d["risk_score"] >= threshold]
    high_risk.sort(key=lambda x: x["risk_score"], reverse=True)
    
    return {
        "tenant": get_tenant_name(tenant_id),
        "threshold": threshold,
        "count": len(high_risk),
        "devices": high_risk,
        "recommendation": "Review these devices and plan remediation for critical vulnerabilities"
    }


@mcp.tool()
def get_network_summary() -> dict:
    """
    Get a summary of the network inventory and security posture.
    
    Returns:
        Dictionary containing network statistics and security metrics
    """
    tenant_id, user_email, _ = get_tenant_context()
    logger.info(f"get_network_summary called by {user_email} for tenant {tenant_id}")
    
    devices = get_devices_for_tenant(tenant_id)
    alerts = get_alerts_for_tenant(tenant_id)
    
    # Device type counts
    device_types = {}
    for device in devices:
        dt = device["device_type"]
        device_types[dt] = device_types.get(dt, 0) + 1
    
    # Risk distribution
    risk_levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for device in devices:
        score = device["risk_score"]
        if score >= 80:
            risk_levels["critical"] += 1
        elif score >= 60:
            risk_levels["high"] += 1
        elif score >= 40:
            risk_levels["medium"] += 1
        else:
            risk_levels["low"] += 1
    
    # Alert counts
    alert_severity = {}
    open_alerts = 0
    for alert in alerts:
        sev = alert["severity"]
        alert_severity[sev] = alert_severity.get(sev, 0) + 1
        if alert["status"] != "resolved":
            open_alerts += 1
    
    avg_risk = sum(d["risk_score"] for d in devices) / len(devices) if devices else 0
    
    return {
        "tenant": get_tenant_name(tenant_id),
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


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    import sys
    
    # Get port from environment (Render sets PORT)
    port = int(os.environ.get("PORT", os.environ.get("MCP_PORT", 8000)))
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    
    logger.info(f"Starting Ordr MCP Server on port {port}")
    logger.info(f"Test Mode: {TEST_MODE}")
    logger.info(f"Azure Client ID: {AZURE_CLIENT_ID}")
    
    if TEST_MODE:
        logger.warning("⚠️  TEST MODE ENABLED - Authentication is disabled!")
    
    # Run the server with streamable-http transport (for Copilot Studio compatibility)
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port
    )
