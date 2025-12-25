# Ordr MCP Server - Railway Deployment

## Quick Start: Deploy to Railway

### Step 1: Prerequisites

- GitHub account
- Railway account (https://railway.app - sign up with GitHub)

### Step 2: Push Code to GitHub

```bash
# Create a new GitHub repository, then:
cd mcp-multi-tenant
git init
git add .
git commit -m "Initial MCP server"
git remote add origin https://github.com/YOUR_USERNAME/ordr-mcp-server.git
git push -u origin main
```

### Step 3: Deploy to Railway

1. Go to https://railway.app
2. Click "New Project"
3. Select "Deploy from GitHub repo"
4. Choose your `ordr-mcp-server` repository
5. Railway auto-detects Dockerfile and deploys

### Step 4: Get Your URL

After deployment:
1. Click on your service in Railway dashboard
2. Go to "Settings" → "Networking"
3. Click "Generate Domain"
4. You'll get: `https://ordr-mcp-server-xxxx.up.railway.app`

---

## Testing Your Deployment

### Test 1: Health Check

```bash
curl https://YOUR-APP.up.railway.app/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "ordr-mcp-server",
  "test_mode": true,
  "tenant": "tenant-a"
}
```

### Test 2: Server Info

```bash
curl https://YOUR-APP.up.railway.app/info
```

### Test 3: MCP Inspector (Best for Testing Tools)

```bash
# Install MCP Inspector
npx @modelcontextprotocol/inspector sse https://YOUR-APP.up.railway.app/sse
```

This opens a web UI where you can:
- See all available tools
- Call tools interactively
- See responses

### Test 4: Manual SSE Connection

```bash
curl -N https://YOUR-APP.up.railway.app/sse
```

---

## Project Files

| File | Purpose |
|------|---------|
| `mcp_server.py` | Main MCP server with tools |
| `requirements.txt` | Python dependencies |
| `Dockerfile` | Container configuration |
| `railway.json` | Railway deployment config |
| `tenants.yaml` | Tenant configuration (for production) |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 8000 | Port (Railway sets this automatically) |
| `TEST_MODE` | true | Enable test mode (no auth) |
| `X_TENANT_ID` | tenant-a | Default tenant for test mode |
| `X_USER_EMAIL` | testuser@example.com | Default user for test mode |

To change in Railway:
1. Go to your service
2. Click "Variables"
3. Add/modify variables

---

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `list_devices` | List/filter network devices |
| `get_device_by_ip` | Get device by IP address |
| `get_device_by_hostname` | Get device by hostname |
| `list_alerts` | List security alerts |
| `get_high_risk_devices` | Get devices above risk threshold |
| `get_network_summary` | Get network stats summary |

---

## Connecting to Copilot Studio

Once deployed, use this URL in Copilot Studio:

```
MCP Server URL: https://YOUR-APP.up.railway.app/sse
```

### OAuth Configuration (for production)

For production with auth, you'll need:
1. Azure AD App Registration
2. Auth Validator service deployed
3. Nginx reverse proxy

See the full architecture docs for production setup.

---

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
python mcp_server.py

# Test
curl http://localhost:8000/health
```

---

## Troubleshooting

### "Application failed to respond"
- Check Railway logs: Service → Deployments → View Logs
- Ensure PORT environment variable is used (not hardcoded)

### "Connection refused"
- Make sure server binds to 0.0.0.0, not localhost
- Check if domain is generated in Railway settings

### Tools not appearing in MCP Inspector
- Verify SSE endpoint: `/sse`
- Check for Python errors in logs
