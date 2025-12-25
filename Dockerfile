# =============================================================================
# Dockerfile for Ordr MCP Server
# =============================================================================

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY mcp_server.py .

# Environment variables (can be overridden at runtime)
ENV MCP_PORT=8000
ENV TENANT_ID=default
ENV X_TENANT_ID=tenant-a
ENV X_USER_EMAIL=test@example.com
ENV X_USER_OID=test-oid

# Expose port
EXPOSE 8000

# Run the server
CMD ["python", "mcp_server.py"]
