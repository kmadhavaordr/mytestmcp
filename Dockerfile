# =============================================================================
# Dockerfile for Ordr MCP Server with Authentication
# =============================================================================

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY mcp_server.py .

# Environment variables
ENV MCP_PORT=8000
ENV AZURE_CLIENT_ID=d63e5ccd-bd26-4b10-91b7-2dd7052577cb
ENV TEST_MODE=false

# Expose port
EXPOSE 8000

# Run the server
CMD ["python", "mcp_server.py"]
