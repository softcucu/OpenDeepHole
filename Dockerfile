# Stage 1: Build frontend
FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Stage 2: Runtime
FROM python:3.12-slim
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    universal-ctags \
    && rm -rf /var/lib/apt/lists/*

# Install opencode
RUN curl -fsSL https://opencode.ai/install | bash

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ ./backend/
COPY mcp_server/ ./mcp_server/
COPY skills/ ./skills/
COPY config.yaml .
COPY start.sh .

# Copy built frontend
COPY --from=frontend-build /app/backend/static ./backend/static/

RUN chmod +x start.sh

# Create storage directories
RUN mkdir -p /OpenDeepHoleData/projects /OpenDeepHoleData/scans logs

EXPOSE 8000

CMD ["./start.sh"]
